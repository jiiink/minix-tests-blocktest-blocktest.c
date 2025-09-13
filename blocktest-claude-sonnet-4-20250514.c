/* Block Device Driver Test driver, by D.C. van Moolenbroek */
#include <stdlib.h>
#include <stdarg.h>
#include <minix/blockdriver.h>
#include <minix/drvlib.h>
#include <minix/ds.h>
#include <minix/optset.h>
#include <sys/ioc_disk.h>
#include <sys/mman.h>
#include <assert.h>

enum {
	RESULT_OK,			/* exactly as expected */
	RESULT_DEATH,			/* driver died */
	RESULT_COMMFAIL,		/* communication failed */
	RESULT_BADTYPE,			/* bad type in message */
	RESULT_BADID,			/* bad request ID in message */
	RESULT_BADSTATUS,		/* bad/unexpected status in message */
	RESULT_TRUNC,			/* request truncated unexpectedly */
	RESULT_CORRUPT,			/* buffer touched erroneously */
	RESULT_MISSING,			/* buffer left untouched erroneously */
	RESULT_OVERFLOW,		/* area around buffer touched */
	RESULT_BADVALUE			/* bad/unexpected return value */
};

typedef struct {
	int type;
	ssize_t value;
} result_t;

static char driver_label[32] = "";	/* driver DS label */
static devminor_t driver_minor = -1;	/* driver's partition minor to use */
static endpoint_t driver_endpt;	/* driver endpoint */

static int may_write = FALSE;		/* may we write to the device? */
static int sector_size = 512;		/* size of a single disk sector */
static int min_read = 512;		/* minimum total size of read req */
static int min_write = 0;		/* minimum total size of write req */
static int element_size = 512;		/* minimum I/O vector element size */
static int max_size = 131072;		/* maximum total size of any req */
/* Note that we do not test exceeding the max_size limit, so it is safe to set
 * it to a value lower than the driver supports.
 */

/* These settings are used for automated test runs. */
static int contig = TRUE;		/* allocate contiguous DMA memory? */
static int silent = FALSE;		/* do not produce console output? */

static struct part_geom part;		/* base and size of target partition */

#define NR_OPENED 10			/* maximum number of opened devices */
static dev_t opened[NR_OPENED];	/* list of currently opened devices */
static int nr_opened = 0;		/* current number of opened devices */

static int total_tests = 0;		/* total number of tests performed */
static int failed_tests = 0;		/* number of tests that failed */
static int failed_groups = 0;		/* nr of groups that had failures */
static int group_failure;		/* has this group had a failure yet? */
static int driver_deaths = 0;		/* number of restarts that we saw */

/* Options supported by this driver. */
static struct optset optset_table[] = {
	{ "label",	OPT_STRING,	driver_label,	sizeof(driver_label) },
	{ "minor",	OPT_INT,	&driver_minor,	10		     },
	{ "rw",		OPT_BOOL,	&may_write,	TRUE		     },
	{ "ro",		OPT_BOOL,	&may_write,	FALSE		     },
	{ "sector",	OPT_INT,	&sector_size,	10		     },
	{ "element",	OPT_INT,	&element_size,	10		     },
	{ "min_read",	OPT_INT,	&min_read,	10		     },
	{ "min_write",	OPT_INT,	&min_write,	10		     },
	{ "max",	OPT_INT,	&max_size,	10		     },
	{ "nocontig",	OPT_BOOL,	&contig,	FALSE		     },
	{ "silent",	OPT_BOOL,	&silent,	TRUE		     },
	{ NULL,		0,		NULL,		0		     }
};

static void output(const char *fmt, ...)
{
	va_list argp;

	if (silent)
		return;

	va_start(argp, fmt);
	vprintf(fmt, argp);
	va_end(argp);
}

static void *alloc_dma_memory(size_t size)
{
	void *ptr;

	if (size == 0) {
		return NULL;
	}

	if (contig) {
		ptr = alloc_contig(size, 0, NULL);
	} else {
		ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_PREALLOC | MAP_ANON, -1, 0);
	}

	if (ptr == MAP_FAILED || ptr == NULL) {
		panic("unable to allocate %zu bytes of memory", size);
	}

	return ptr;
}

static void free_dma_memory(void *ptr, size_t size)
{
    if (ptr == NULL) {
        return;
    }
    
    if (contig) {
        free_contig(ptr, size);
    } else {
        munmap(ptr, size);
    }
}

static int set_result(result_t *res, int type, ssize_t value)
{
    if (res == NULL) {
        return -1;
    }
    
    res->type = type;
    res->value = value;
    
    return type;
}

static int accept_result(result_t *res, int type, ssize_t value)
{
    if (!res) {
        return FALSE;
    }

    if (res->type == type && res->value == value) {
        set_result(res, RESULT_OK, 0);
        return TRUE;
    }

    return FALSE;
}

static void got_result(result_t *res, char *desc)
{
    static int test_number = 0;

    if (res == NULL || desc == NULL) {
        return;
    }

    total_tests++;
    test_number++;

    if (res->type != RESULT_OK) {
        failed_tests++;

        if (group_failure == FALSE) {
            failed_groups++;
            group_failure = TRUE;
        }
    }

    const char *status = (res->type == RESULT_OK) ? "PASS" : "FAIL";
    output("#%02d: %-38s\t[%s]\n", test_number, desc, status);

    switch (res->type) {
    case RESULT_OK:
        break;
    case RESULT_DEATH:
        output("- driver died\n");
        break;
    case RESULT_COMMFAIL:
        output("- communication failed; ipc_sendrec returned %d\n",
            res->value);
        break;
    case RESULT_BADTYPE:
        output("- bad type %d in reply message\n", res->value);
        break;
    case RESULT_BADID:
        output("- mismatched ID %d in reply message\n", res->value);
        break;
    case RESULT_BADSTATUS:
        output("- bad or unexpected status %d in reply message\n",
            res->value);
        break;
    case RESULT_TRUNC:
        output("- result size not as expected (%u bytes left)\n",
            res->value);
        break;
    case RESULT_CORRUPT:
        output("- buffer has been modified erroneously\n");
        break;
    case RESULT_MISSING:
        output("- buffer has been left untouched erroneously\n");
        break;
    case RESULT_OVERFLOW:
        output("- area around target buffer modified\n");
        break;
    case RESULT_BADVALUE:
        output("- bad or unexpected return value %d from call\n",
            res->value);
        break;
    default:
        output("- unknown error type %d\n", res->type);
        break;
    }
}

static void test_group(const char *name, int exec)
{
    if (name == NULL) {
        return;
    }

    output("Test group: %s%s\n", name, exec ? "" : " (skipping)");

    group_failure = FALSE;
}

static void reopen_device(dev_t minor)
{
    message m;

    memset(&m, 0, sizeof(m));
    m.m_type = BDEV_OPEN;
    m.m_lbdev_lblockdriver_msg.minor = minor;
    m.m_lbdev_lblockdriver_msg.access = may_write ? (BDEV_R_BIT | BDEV_W_BIT) : BDEV_R_BIT;
    m.m_lbdev_lblockdriver_msg.id = 0;

    (void) ipc_sendrec(driver_endpt, &m);
}

static int sendrec_driver(message *m_ptr, ssize_t exp, result_t *res)
{
	message m_orig;
	endpoint_t last_endpt;
	int i, r;

	if (!m_ptr || !res) {
		return set_result(res, RESULT_COMMFAIL, EINVAL);
	}

	m_orig = *m_ptr;

	r = ipc_sendrec(driver_endpt, m_ptr);

	if (r == EDEADSRCDST) {
		output("WARNING: driver has died, attempting to proceed\n");
		driver_deaths++;

		last_endpt = driver_endpt;
		for (;;) {
			r = ds_retrieve_label_endpt(driver_label, &driver_endpt);

			if (r == OK && last_endpt != driver_endpt)
				break;

			micro_delay(100000);
		}

		for (i = 0; i < nr_opened; i++) {
			reopen_device(opened[i]);
		}

		return set_result(res, RESULT_DEATH, 0);
	}

	if (r != OK) {
		return set_result(res, RESULT_COMMFAIL, r);
	}

	if (m_ptr->m_type != BDEV_REPLY) {
		return set_result(res, RESULT_BADTYPE, m_ptr->m_type);
	}

	if (m_ptr->m_lblockdriver_lbdev_reply.id != m_orig.m_lbdev_lblockdriver_msg.id) {
		return set_result(res, RESULT_BADID, m_ptr->m_lblockdriver_lbdev_reply.id);
	}

	if ((exp < 0 && m_ptr->m_lblockdriver_lbdev_reply.status >= 0) ||
		(exp >= 0 && m_ptr->m_lblockdriver_lbdev_reply.status < 0)) {
		return set_result(res, RESULT_BADSTATUS, m_ptr->m_lblockdriver_lbdev_reply.status);
	}

	return set_result(res, RESULT_OK, 0);
}

static void raw_xfer(dev_t minor, u64_t pos, iovec_s_t *iovec, int nr_req,
	int write, ssize_t exp, result_t *res)
{
	cp_grant_id_t grant;
	message m;
	int r;

	if (nr_req > NR_IOREQS) {
		set_result(res, RESULT_BADSTATUS, -EINVAL);
		return;
	}

	if (write && !may_write) {
		set_result(res, RESULT_BADSTATUS, -EACCES);
		return;
	}

	grant = cpf_grant_direct(driver_endpt, (vir_bytes) iovec,
		sizeof(*iovec) * nr_req, CPF_READ);
	if (grant == GRANT_INVALID) {
		set_result(res, RESULT_BADSTATUS, -ENOMEM);
		return;
	}

	memset(&m, 0, sizeof(m));
	m.m_type = write ? BDEV_SCATTER : BDEV_GATHER;
	m.m_lbdev_lblockdriver_msg.minor = minor;
	m.m_lbdev_lblockdriver_msg.pos = pos;
	m.m_lbdev_lblockdriver_msg.count = nr_req;
	m.m_lbdev_lblockdriver_msg.grant = grant;
	m.m_lbdev_lblockdriver_msg.id = lrand48();

	r = sendrec_driver(&m, exp, res);

	if (cpf_revoke(grant) == -1) {
		set_result(res, RESULT_BADSTATUS, -EFAULT);
		return;
	}

	if (r != RESULT_OK)
		return;

	if (m.m_lblockdriver_lbdev_reply.status == exp)
		return;

	if (exp < 0) {
		set_result(res, RESULT_BADSTATUS,
			m.m_lblockdriver_lbdev_reply.status);
	} else {
		set_result(res, RESULT_TRUNC,
			exp - m.m_lblockdriver_lbdev_reply.status);
	}
}

static void vir_xfer(dev_t minor, u64_t pos, iovec_t *iovec, int nr_req,
	int write, ssize_t exp, result_t *res)
{
	iovec_s_t iov_s[NR_IOREQS];
	int i;
	int grant_flags;

	assert(nr_req <= NR_IOREQS);
	assert(iovec != NULL);
	assert(res != NULL);

	grant_flags = write ? CPF_READ : CPF_WRITE;

	for (i = 0; i < nr_req; i++) {
		iov_s[i].iov_size = iovec[i].iov_size;
		iov_s[i].iov_grant = cpf_grant_direct(driver_endpt,
			(vir_bytes) iovec[i].iov_addr, iovec[i].iov_size,
			grant_flags);
		
		if (iov_s[i].iov_grant == GRANT_INVALID) {
			for (int j = 0; j < i; j++) {
				cpf_revoke(iov_s[j].iov_grant);
			}
			panic("unable to allocate grant");
		}
	}

	raw_xfer(minor, pos, iov_s, nr_req, write, exp, res);

	for (i = 0; i < nr_req; i++) {
		iovec[i].iov_size = iov_s[i].iov_size;

		if (cpf_revoke(iov_s[i].iov_grant) == -1) {
			panic("unable to revoke grant");
		}
	}
}

static void simple_xfer(dev_t minor, u64_t pos, u8_t *buf, size_t size,
	int write, ssize_t exp, result_t *res)
{
	iovec_t iov;

	if (!buf || !res) {
		if (res) {
			res->type = RESULT_FAILURE;
		}
		return;
	}

	iov.iov_addr = (vir_bytes) buf;
	iov.iov_size = size;

	vir_xfer(minor, pos, &iov, 1, write, exp, res);
}

static void alloc_buf_and_grant(u8_t **ptr, cp_grant_id_t *grant,
	size_t size, int perms)
{
	if (!ptr || !grant) {
		panic("invalid parameters");
	}

	*ptr = alloc_dma_memory(size);
	if (!*ptr) {
		panic("unable to allocate DMA memory");
	}

	*grant = cpf_grant_direct(driver_endpt, (vir_bytes) *ptr, size, perms);
	if (*grant == GRANT_INVALID) {
		panic("unable to allocate grant");
	}
}

static void free_buf_and_grant(u8_t *ptr, cp_grant_id_t grant, size_t size)
{
	if (ptr != NULL) {
		cpf_revoke(grant);
		free_dma_memory(ptr, size);
	}
}

static void bad_read1(void)
{
	message mt, m;
	iovec_s_t iovt, iov;
	cp_grant_id_t grant, grant2, grant3;
	u8_t *buf_ptr;
	vir_bytes buf_size;
	result_t res;

	test_group("bad read requests, part one", TRUE);

	buf_size = 4096;

	alloc_buf_and_grant(&buf_ptr, &grant2, buf_size, CPF_WRITE);

	grant = cpf_grant_direct(driver_endpt, (vir_bytes) &iov, sizeof(iov), CPF_READ);
	if (grant == GRANT_INVALID) {
		panic("unable to allocate grant");
	}

	memset(&mt, 0, sizeof(mt));
	mt.m_type = BDEV_GATHER;
	mt.m_lbdev_lblockdriver_msg.minor = driver_minor;
	mt.m_lbdev_lblockdriver_msg.pos = 0LL;
	mt.m_lbdev_lblockdriver_msg.count = 1;
	mt.m_lbdev_lblockdriver_msg.grant = grant;
	mt.m_lbdev_lblockdriver_msg.id = lrand48();

	memset(&iovt, 0, sizeof(iovt));
	iovt.iov_grant = grant2;
	iovt.iov_size = buf_size;

	m = mt;
	iov = iovt;

	sendrec_driver(&m, OK, &res);

	if (res.type == RESULT_OK && m.m_lblockdriver_lbdev_reply.status != (ssize_t) iov.iov_size) {
		res.type = RESULT_TRUNC;
		res.value = m.m_lblockdriver_lbdev_reply.status;
	}

	got_result(&res, "normal request");

	m = mt;
	iov = iovt;
	m.m_lbdev_lblockdriver_msg.count = 0;

	sendrec_driver(&m, EINVAL, &res);
	got_result(&res, "zero iovec elements");

	m = mt;
	m.m_lbdev_lblockdriver_msg.grant = GRANT_INVALID;

	sendrec_driver(&m, EINVAL, &res);
	got_result(&res, "bad iovec grant");

	m = mt;
	iov = iovt;

	grant3 = cpf_grant_direct(driver_endpt, (vir_bytes) &iov, sizeof(iov), CPF_READ);
	if (grant3 == GRANT_INVALID) {
		panic("unable to allocate grant");
	}

	cpf_revoke(grant3);
	m.m_lbdev_lblockdriver_msg.grant = grant3;

	sendrec_driver(&m, EINVAL, &res);
	accept_result(&res, RESULT_BADSTATUS, EPERM);
	got_result(&res, "revoked iovec grant");

	m = mt;
	iov = iovt;

	sendrec_driver(&m, OK, &res);

	if (res.type == RESULT_OK && m.m_lblockdriver_lbdev_reply.status != (ssize_t) iov.iov_size) {
		res.type = RESULT_TRUNC;
		res.value = m.m_lblockdriver_lbdev_reply.status;
	}

	got_result(&res, "normal request");

	free_buf_and_grant(buf_ptr, grant2, buf_size);
	cpf_revoke(grant);
}

static u32_t get_sum(const u8_t *ptr, size_t size)
{
	u32_t sum = 0;
	
	if (ptr == NULL) {
		return 0;
	}
	
	while (size > 0) {
		sum = sum ^ (sum << 5) ^ *ptr;
		ptr++;
		size--;
	}
	
	return sum;
}

static u32_t fill_rand(u8_t *ptr, size_t size)
{
    if (ptr == NULL || size == 0) {
        return 0;
    }

    for (size_t i = 0; i < size; i++) {
        ptr[i] = (u8_t)(lrand48() & 0xFF);
    }

    return get_sum(ptr, size);
}

static void test_sum(u8_t *ptr, size_t size, u32_t sum, int should_match,
	result_t *res)
{
	u32_t sum2;

	if (!res || res->type != RESULT_OK)
		return;

	sum2 = get_sum(ptr, size);

	if ((sum == sum2) != should_match) {
		res->type = should_match ? RESULT_CORRUPT : RESULT_MISSING;
		res->value = 0;
	}
}

static void bad_read2(void)
{
    u8_t *buf_ptr, *buf2_ptr, *buf3_ptr, c1, c2;
    size_t buf_size, buf2_size, buf3_size;
    cp_grant_id_t buf_grant, buf2_grant, buf3_grant, grant;
    u32_t buf_sum, buf2_sum, buf3_sum;
    iovec_s_t iov[3], iovt[3];
    result_t res;

    test_group("bad read requests, part two", TRUE);

    buf_size = buf2_size = buf3_size = BUF_SIZE;

    if (alloc_buf_and_grant(&buf_ptr, &buf_grant, buf_size, CPF_WRITE) != 0 ||
        alloc_buf_and_grant(&buf2_ptr, &buf2_grant, buf2_size, CPF_WRITE) != 0 ||
        alloc_buf_and_grant(&buf3_ptr, &buf3_grant, buf3_size, CPF_WRITE) != 0) {
        return;
    }

    iovt[0].iov_grant = buf_grant;
    iovt[0].iov_size = buf_size;
    iovt[1].iov_grant = buf2_grant;
    iovt[1].iov_size = buf2_size;
    iovt[2].iov_grant = buf3_grant;
    iovt[2].iov_size = buf3_size;

    test_normal_vector_request(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                              buf_size, buf2_size, buf3_size);

    test_zero_sized_element(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                           buf_size, buf2_size, buf3_size);

    test_negative_sized_element(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                               buf_size, buf2_size, buf3_size);

    test_negative_total_size(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                            buf_size, buf2_size, buf3_size);

    test_wrapping_total_size(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                            buf_size, buf2_size, buf3_size);

    test_word_unaligned_size(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                            buf_size, buf2_size, buf3_size);

    test_invalid_grant(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                      buf_size, buf2_size, buf3_size);

    test_revoked_grant(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                      buf_size, buf2_size, buf3_size);

    test_readonly_grant(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                       buf_size, buf2_size, buf3_size);

    test_word_unaligned_buffer(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                              buf_size, buf2_size, buf3_size);

    if (min_read > 1) {
        test_word_unaligned_position(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                                    buf_size, buf2_size, buf3_size);
    }

    test_normal_vector_request(iov, iovt, buf_ptr, buf2_ptr, buf3_ptr, 
                              buf_size, buf2_size, buf3_size);

    free_buf_and_grant(buf3_ptr, buf3_grant, buf3_size);
    free_buf_and_grant(buf2_ptr, buf2_grant, buf2_size);
    free_buf_and_grant(buf_ptr, buf_grant, buf_size);
}

static void test_normal_vector_request(iovec_s_t *iov, iovec_s_t *iovt, 
                                      u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                      size_t buf_size, size_t buf2_size, size_t buf3_size)
{
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;

    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);

    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);

    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, buf_size + buf2_size + buf3_size, &res);

    test_sum(buf_ptr, buf_size, buf_sum, FALSE, &res);
    test_sum(buf2_ptr, buf2_size, buf2_sum, FALSE, &res);
    test_sum(buf3_ptr, buf3_size, buf3_sum, FALSE, &res);

    got_result(&res, "normal vector request");
}

static void test_zero_sized_element(iovec_s_t *iov, iovec_s_t *iovt, 
                                   u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                   size_t buf_size, size_t buf2_size, size_t buf3_size)
{
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;

    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[1].iov_size = 0;

    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);

    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);

    test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
    test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

    got_result(&res, "zero size in iovec element");
}

static void test_negative_sized_element(iovec_s_t *iov, iovec_s_t *iovt, 
                                       u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                       size_t buf_size, size_t buf2_size, size_t buf3_size)
{
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;

    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[1].iov_size = (vir_bytes) LONG_MAX + 1;

    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);

    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);

    test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
    test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

    got_result(&res, "negative size in iovec element");
}

static void test_negative_total_size(iovec_s_t *iov, iovec_s_t *iovt, 
                                    u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                    size_t buf_size, size_t buf2_size, size_t buf3_size)
{
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;

    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[0].iov_size = LONG_MAX / 2 - 1;
    iov[1].iov_size = LONG_MAX / 2 - 1;

    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);

    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);

    test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
    test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

    got_result(&res, "negative total size");
}

static void test_wrapping_total_size(iovec_s_t *iov, iovec_s_t *iovt, 
                                    u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                    size_t buf_size, size_t buf2_size, size_t buf3_size)
{
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;

    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[0].iov_size = LONG_MAX - 1;
    iov[1].iov_size = LONG_MAX - 1;

    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);

    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);

    test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
    test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

    got_result(&res, "wrapping total size");
}

static void test_word_unaligned_size(iovec_s_t *iov, iovec_s_t *iovt, 
                                    u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                    size_t buf_size, size_t buf2_size, size_t buf3_size)
{
    u32_t buf_sum, buf2_sum, buf3_sum;
    u8_t c1;
    result_t res;

    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[1].iov_size--;

    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);
    c1 = buf2_ptr[buf2_size - 1];

    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, BUF_SIZE * 3 - 1, &res);

    if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
        test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
        test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);
    } else {
        test_sum(buf_ptr, buf_size, buf_sum, FALSE, &res);
        test_sum(buf2_ptr, buf2_size, buf2_sum, FALSE, &res);
        test_sum(buf3_ptr, buf3_size, buf3_sum, FALSE, &res);
        if (c1 != buf2_ptr[buf2_size - 1])
            set_result(&res, RESULT_CORRUPT, 0);
    }

    got_result(&res, "word-unaligned size in iovec element");
}

static void test_invalid_grant(iovec_s_t *iov, iovec_s_t *iovt, 
                              u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                              size_t buf_size, size_t buf2_size, size_t buf3_size)
{
    u32_t buf2_sum, buf3_sum;
    result_t res;

    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[1].iov_grant = GRANT_INVALID;

    fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);

    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);

    test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

    got_result(&res, "invalid grant in iovec element");
}

static void test_revoked_grant(iovec_s_t *iov, iovec_s_t *iovt, 
                              u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                              size_t buf_size, size_t buf2_size, size_t buf3_size)
{
    u32_t buf_sum, buf2_sum, buf3_sum;
    cp_grant_id_t grant;
    result_t res;

    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    
    grant = cpf_grant_direct(driver_endpt, (vir_bytes) buf2_ptr, buf2_size, CPF_WRITE);
    if (grant == GRANT_INVALID)
        panic("unable to allocate grant");

    cpf_revoke(grant);
    iov[1].iov_grant = grant;

    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);

    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);

    accept_result(&res, RESULT_BADSTATUS, EPERM);

    test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

    got_result(&res, "revoked grant in iovec element");
}

static void test_readonly_grant(iovec_s_t *iov, iovec_s_t *iovt, 
                               u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                               size_t buf_size, size_t buf2_size, size_t buf3_size)
{
    u32_t buf_sum, buf2_sum, buf3_sum;
    cp_grant_id_t grant;
    result_t res;

    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    
    grant = cpf_grant_direct(driver_endpt, (vir_bytes) buf2_ptr, buf2_size, CPF_READ);
    if (grant == GRANT_INVALID)
        panic("unable to allocate grant");

    iov[1].iov_grant = grant;

    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);

    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);

    accept_result(&res, RESULT_BADSTATUS, EPERM);

    test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

    got_result(&res, "read-only grant in iovec element");

    cpf_revoke(grant);
}

static void test_word_unaligned_buffer(iovec_s_t *iov, iovec_s_t *iovt, 
                                      u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                      size_t buf_size, size_t buf2_size, size_t buf3_size)
{
    u32_t buf_sum, buf2_sum, buf3_sum;
    u8_t c1, c2;
    cp_grant_id_t grant;
    result_t res;

    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    
    grant = cpf_grant_direct(driver_endpt, (vir_bytes) (buf2_ptr + 1), 
                            buf2_size - 2, CPF_WRITE);
    if (grant == GRANT_INVALID)
        panic("unable to allocate grant");

    iov[1].iov_grant = grant;
    iov[1].iov_size = buf2_size - 2;

    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);
    c1 = buf2_ptr[0];
    c2 = buf2_ptr[buf2_size - 1];

    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, BUF_SIZE * 3 - 2, &res);

    if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
        test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
        test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);
    } else {
        test_sum(buf_ptr, buf_size, buf_sum, FALSE, &res);
        test_sum(buf2_ptr, buf2_size, buf2_sum, FALSE, &res);
        test_sum(buf3_ptr, buf3_size, buf3_sum, FALSE, &res);
        if (c1 != buf2_ptr[0] || c2 != buf2_ptr[buf2_size - 1])
            set_result(&res, RESULT_CORRUPT, 0);
    }

    got_result(&res, "word-unaligned buffer in iovec element");

    cpf_revoke(grant);
}

static void test_word_unaligned_position(iovec_s_t *iov, iovec_s_t *iovt, 
                                        u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                        size_t buf_size, size_t buf2_size, size_t buf3_size)
{
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;

    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);

    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);

    raw_xfer(driver_minor, 1ULL, iov, 3, FALSE, EINVAL, &res);

    test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
    test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

    got_result(&res, "word-unaligned position");
}

static void bad_write(void)
{
    u8_t *buf_ptr, *buf2_ptr, *buf3_ptr;
    size_t buf_size, buf2_size, buf3_size, sector_unalign;
    cp_grant_id_t buf_grant, buf2_grant, buf3_grant;
    cp_grant_id_t grant;
    u32_t buf_sum, buf2_sum, buf3_sum;
    iovec_s_t iov[3], iovt[3];
    result_t res;

    test_group("bad write requests", may_write);

    if (!may_write)
        return;

    buf_size = buf2_size = buf3_size = BUF_SIZE;

    if (!alloc_buf_and_grant(&buf_ptr, &buf_grant, buf_size, CPF_READ) ||
        !alloc_buf_and_grant(&buf2_ptr, &buf2_grant, buf2_size, CPF_READ) ||
        !alloc_buf_and_grant(&buf3_ptr, &buf3_grant, buf3_size, CPF_READ)) {
        return;
    }

    iovt[0].iov_grant = buf_grant;
    iovt[0].iov_size = buf_size;
    iovt[1].iov_grant = buf2_grant;
    iovt[1].iov_size = buf2_size;
    iovt[2].iov_grant = buf3_grant;
    iovt[2].iov_size = buf3_size;

    if (min_write == 0)
        min_write = sector_size;

    if (min_write > 1) {
        sector_unalign = (min_write > 2) ? 2 : 1;

        memcpy(iov, iovt, sizeof(iovt));

        buf_sum = fill_rand(buf_ptr, buf_size);
        buf2_sum = fill_rand(buf2_ptr, buf2_size);
        buf3_sum = fill_rand(buf3_ptr, buf3_size);

        raw_xfer(driver_minor, (u64_t)sector_unalign, iov, 3, TRUE,
            EINVAL, &res);

        test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
        test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
        test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

        got_result(&res, "sector-unaligned write position");

        memcpy(iov, iovt, sizeof(iovt));
        iov[1].iov_size -= sector_unalign;

        buf_sum = fill_rand(buf_ptr, buf_size);
        buf2_sum = fill_rand(buf2_ptr, buf2_size);
        buf3_sum = fill_rand(buf3_ptr, buf3_size);

        raw_xfer(driver_minor, 0ULL, iov, 3, TRUE, EINVAL, &res);

        test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
        test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
        test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

        got_result(&res, "sector-unaligned write size");
    }

    memcpy(iov, iovt, sizeof(iovt));
    grant = cpf_grant_direct(driver_endpt, (vir_bytes) buf2_ptr,
            buf2_size, CPF_WRITE);
    if (grant == GRANT_INVALID) {
        goto cleanup;
    }

    iov[1].iov_grant = grant;

    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);

    raw_xfer(driver_minor, 0ULL, iov, 3, TRUE, EINVAL, &res);

    accept_result(&res, RESULT_BADSTATUS, EPERM);

    test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
    test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

    got_result(&res, "write-only grant in iovec element");

    cpf_revoke(grant);

cleanup:
    free_buf_and_grant(buf3_ptr, buf3_grant, buf3_size);
    free_buf_and_grant(buf2_ptr, buf2_grant, buf2_size);
    free_buf_and_grant(buf_ptr, buf_grant, buf_size);
}

static void vector_and_large_sub(size_t small_size)
{
	size_t large_size, buf_size, buf2_size;
	u8_t *buf_ptr, *buf2_ptr;
	iovec_t iovec[NR_IOREQS];
	u64_t base_pos;
	result_t res;
	int i;

	if (small_size == 0 || small_size > SIZE_MAX / NR_IOREQS) {
		return;
	}

	base_pos = (u64_t)sector_size;
	large_size = small_size * NR_IOREQS;

	if (large_size > SIZE_MAX - sizeof(u32_t) * 2) {
		return;
	}
	buf_size = large_size + sizeof(u32_t) * 2;

	if (large_size > SIZE_MAX - sizeof(u32_t) * (NR_IOREQS + 1)) {
		return;
	}
	buf2_size = large_size + sizeof(u32_t) * (NR_IOREQS + 1);

	buf_ptr = alloc_dma_memory(buf_size);
	if (!buf_ptr) {
		return;
	}

	buf2_ptr = alloc_dma_memory(buf2_size);
	if (!buf2_ptr) {
		free_dma_memory(buf_ptr, buf_size);
		return;
	}

	if (may_write) {
		fill_rand(buf_ptr, buf_size);

		iovec[0].iov_addr = (vir_bytes) (buf_ptr + sizeof(u32_t));
		iovec[0].iov_size = large_size;

		vir_xfer(driver_minor, base_pos, iovec, 1, TRUE, large_size, &res);
		got_result(&res, "large write");
	}

	for (i = 0; i < NR_IOREQS; i++) {
		u8_t *chunk_ptr = buf2_ptr + sizeof(u32_t) + (i) * (sizeof(u32_t) + small_size);
		u32_t *guard_ptr = (u32_t *)(chunk_ptr - sizeof(u32_t));
		*guard_ptr = 0xDEADBEEFL + i;
		iovec[i].iov_addr = (vir_bytes) chunk_ptr;
		iovec[i].iov_size = small_size;
	}
	u8_t *final_chunk_ptr = buf2_ptr + sizeof(u32_t) + i * (sizeof(u32_t) + small_size);
	u32_t *final_guard_ptr = (u32_t *)(final_chunk_ptr - sizeof(u32_t));
	*final_guard_ptr = 0xFEEDFACEL;

	vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, FALSE, large_size, &res);

	if (res.type == RESULT_OK) {
		for (i = 0; i < NR_IOREQS; i++) {
			u8_t *chunk_ptr = buf2_ptr + sizeof(u32_t) + i * (sizeof(u32_t) + small_size);
			u32_t *guard_ptr = (u32_t *)(chunk_ptr - sizeof(u32_t));
			if (*guard_ptr != 0xDEADBEEFL + i) {
				set_result(&res, RESULT_OVERFLOW, 0);
				break;
			}
		}
		if (res.type == RESULT_OK) {
			u8_t *final_chunk_ptr = buf2_ptr + sizeof(u32_t) + i * (sizeof(u32_t) + small_size);
			u32_t *final_guard_ptr = (u32_t *)(final_chunk_ptr - sizeof(u32_t));
			if (*final_guard_ptr != 0xFEEDFACEL) {
				set_result(&res, RESULT_OVERFLOW, 0);
			}
		}
	}

	if (res.type == RESULT_OK && may_write) {
		for (i = 0; i < NR_IOREQS; i++) {
			u8_t *small_chunk_ptr = buf2_ptr + sizeof(u32_t) + i * (sizeof(u32_t) + small_size);
			u8_t *large_chunk_ptr = buf_ptr + sizeof(u32_t) + small_size * i;
			test_sum(small_chunk_ptr, small_size, get_sum(large_chunk_ptr, small_size), TRUE, &res);
		}
	}

	got_result(&res, "vectored read");

	if (may_write) {
		fill_rand(buf2_ptr, buf2_size);

		for (i = 0; i < NR_IOREQS; i++) {
			u8_t *chunk_ptr = buf2_ptr + sizeof(u32_t) + i * (sizeof(u32_t) + small_size);
			iovec[i].iov_addr = (vir_bytes) chunk_ptr;
			iovec[i].iov_size = small_size;
		}

		vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, TRUE, large_size, &res);
		got_result(&res, "vectored write");
	}

	*(u32_t *) buf_ptr = 0xCAFEBABEL;
	*(u32_t *) (buf_ptr + sizeof(u32_t) + large_size) = 0xDECAFBADL;

	iovec[0].iov_addr = (vir_bytes) (buf_ptr + sizeof(u32_t));
	iovec[0].iov_size = large_size;

	vir_xfer(driver_minor, base_pos, iovec, 1, FALSE, large_size, &res);

	if (res.type == RESULT_OK) {
		if (*(u32_t *) buf_ptr != 0xCAFEBABEL) {
			set_result(&res, RESULT_OVERFLOW, 0);
		}
		if (*(u32_t *) (buf_ptr + sizeof(u32_t) + large_size) != 0xDECAFBADL) {
			set_result(&res, RESULT_OVERFLOW, 0);
		}
	}

	if (res.type == RESULT_OK) {
		for (i = 0; i < NR_IOREQS; i++) {
			u8_t *small_chunk_ptr = buf2_ptr + sizeof(u32_t) + i * (sizeof(u32_t) + small_size);
			u8_t *large_chunk_ptr = buf_ptr + sizeof(u32_t) + small_size * i;
			test_sum(small_chunk_ptr, small_size, get_sum(large_chunk_ptr, small_size), TRUE, &res);
		}
	}

	got_result(&res, "large read");

	free_dma_memory(buf2_ptr, buf2_size);
	free_dma_memory(buf_ptr, buf_size);
}

static void vector_and_large(void)
{
    const size_t COMMON_BLOCK_SIZE = 4096;
    const size_t margin = sector_size * 4;
    size_t adjusted_max_size;
    size_t max_block;

    if (max_size <= margin) {
        return;
    }

    adjusted_max_size = (max_size > part.size - margin) ? 
                       part.size - margin : max_size;

    max_block = adjusted_max_size / NR_IOREQS;
    max_block -= max_block % sector_size;

    test_group("vector and large, common block", TRUE);
    vector_and_large_sub(COMMON_BLOCK_SIZE);

    if (max_block != COMMON_BLOCK_SIZE) {
        test_group("vector and large, large block", TRUE);
        vector_and_large_sub(max_block);
    }
}

static void open_device(dev_t minor)
{
    message m;
    result_t res;
    
    if (nr_opened >= NR_OPENED) {
        return;
    }

    memset(&m, 0, sizeof(m));
    m.m_type = BDEV_OPEN;
    m.m_lbdev_lblockdriver_msg.minor = minor;
    m.m_lbdev_lblockdriver_msg.access = may_write ? (BDEV_R_BIT | BDEV_W_BIT) : BDEV_R_BIT;
    m.m_lbdev_lblockdriver_msg.id = lrand48();

    sendrec_driver(&m, OK, &res);

    opened[nr_opened++] = minor;

    const char* operation = (minor == driver_minor) ? 
        "opening the main partition" : 
        "opening a subpartition";
    got_result(&res, operation);
}

static void close_device(dev_t minor)
{
	message m;
	result_t res;
	int i;
	bool found = false;

	memset(&m, 0, sizeof(m));
	m.m_type = BDEV_CLOSE;
	m.m_lbdev_lblockdriver_msg.minor = minor;
	m.m_lbdev_lblockdriver_msg.id = lrand48();

	sendrec_driver(&m, OK, &res);

	if (nr_opened == 0) {
		return;
	}

	for (i = 0; i < nr_opened; i++) {
		if (opened[i] == minor) {
			opened[i] = opened[nr_opened - 1];
			nr_opened--;
			found = true;
			break;
		}
	}

	if (found) {
		const char *operation = (minor == driver_minor) ? 
			"closing the main partition" : 
			"closing a subpartition";
		got_result(&res, operation);
	}
}

static int vir_ioctl(dev_t minor, unsigned long req, void *ptr, ssize_t exp,
	result_t *res)
{
	cp_grant_id_t grant;
	message m;
	int r, perm;

	if (_MINIX_IOCTL_BIG(req)) {
		return -1;
	}

	perm = 0;
	if (_MINIX_IOCTL_IOR(req)) perm |= CPF_WRITE;
	if (_MINIX_IOCTL_IOW(req)) perm |= CPF_READ;

	grant = cpf_grant_direct(driver_endpt, (vir_bytes) ptr,
			_MINIX_IOCTL_SIZE(req), perm);
	if (grant == GRANT_INVALID) {
		return -1;
	}

	memset(&m, 0, sizeof(m));
	m.m_type = BDEV_IOCTL;
	m.m_lbdev_lblockdriver_msg.minor = minor;
	m.m_lbdev_lblockdriver_msg.request = req;
	m.m_lbdev_lblockdriver_msg.grant = grant;
	m.m_lbdev_lblockdriver_msg.user = NONE;
	m.m_lbdev_lblockdriver_msg.id = lrand48();

	r = sendrec_driver(&m, exp, res);

	if (cpf_revoke(grant) == -1) {
		return -1;
	}

	return r;
}

static void misc_ioctl(void)
{
    result_t res;
    int openct;

    test_group("test miscellaneous ioctls", TRUE);

    vir_ioctl(driver_minor, DIOCGETP, &part, OK, &res);
    got_result(&res, "ioctl to get partition");

    if (res.type == RESULT_OK && part.size < (u64_t)max_size * 2) {
        output("WARNING: small partition, some tests may fail\n");
    }

    openct = 0x0badcafe;
    vir_ioctl(driver_minor, DIOCOPENCT, &openct, OK, &res);

    if (res.type == RESULT_OK && openct != 1) {
        res.type = RESULT_BADVALUE;
        res.value = openct;
    }
    got_result(&res, "ioctl to get open count");

    open_device(driver_minor);
    openct = 0x0badcafe;
    vir_ioctl(driver_minor, DIOCOPENCT, &openct, OK, &res);

    if (res.type == RESULT_OK && openct != 2) {
        res.type = RESULT_BADVALUE;
        res.value = openct;
    }
    got_result(&res, "increased open count after opening");

    close_device(driver_minor);
    openct = 0x0badcafe;
    vir_ioctl(driver_minor, DIOCOPENCT, &openct, OK, &res);

    if (res.type == RESULT_OK && openct != 1) {
        res.type = RESULT_BADVALUE;
        res.value = openct;
    }
    got_result(&res, "decreased open count after closing");
}

static void read_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size)
{
    u8_t *buf_ptr;
    size_t buf_size;
    u32_t sum, sum2, sum3;
    result_t res;

    test_group("read around subpartition limits", TRUE);

    buf_size = sector_size * 3;
    buf_ptr = alloc_dma_memory(buf_size);
    if (!buf_ptr) {
        return;
    }

    fill_rand(buf_ptr, buf_size);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr,
        sector_size, FALSE, sector_size, &res);
    sum = get_sum(buf_ptr, sector_size);
    got_result(&res, "one sector read up to partition end");

    fill_rand(buf_ptr, buf_size);
    simple_xfer(sub0_minor, (u64_t)sub_size - buf_size, buf_ptr, buf_size,
        FALSE, buf_size, &res);
    test_sum(buf_ptr + sector_size * 2, sector_size, sum, TRUE, &res);
    sum2 = get_sum(buf_ptr + sector_size, sector_size * 2);
    got_result(&res, "multisector read up to partition end");

    fill_rand(buf_ptr, buf_size);
    sum3 = get_sum(buf_ptr + sector_size * 2, sector_size);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size * 2, buf_ptr,
        buf_size, FALSE, sector_size * 2, &res);
    test_sum(buf_ptr, sector_size * 2, sum2, TRUE, &res);
    test_sum(buf_ptr + sector_size * 2, sector_size, sum3, TRUE, &res);
    got_result(&res, "read somewhat across partition end");

    fill_rand(buf_ptr, buf_size);
    sum2 = get_sum(buf_ptr + sector_size, sector_size * 2);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr,
        buf_size, FALSE, sector_size, &res);
    test_sum(buf_ptr, sector_size, sum, TRUE, &res);
    test_sum(buf_ptr + sector_size, sector_size * 2, sum2, TRUE, &res);
    got_result(&res, "read mostly across partition end");

    sum = fill_rand(buf_ptr, buf_size);
    sum2 = get_sum(buf_ptr, sector_size);
    simple_xfer(sub0_minor, (u64_t)sub_size, buf_ptr, sector_size, FALSE,
        0, &res);
    test_sum(buf_ptr, sector_size, sum2, TRUE, &res);
    got_result(&res, "one sector read at partition end");

    simple_xfer(sub0_minor, (u64_t)sub_size, buf_ptr, buf_size, FALSE, 0,
        &res);
    test_sum(buf_ptr, buf_size, sum, TRUE, &res);
    got_result(&res, "multisector read at partition end");

    simple_xfer(sub0_minor, (u64_t)sub_size + sector_size, buf_ptr,
        buf_size, FALSE, 0, &res);
    test_sum(buf_ptr, sector_size, sum2, TRUE, &res);
    got_result(&res, "single sector read beyond partition end");

    simple_xfer(sub0_minor, 0x1000000000000000ULL, buf_ptr, buf_size,
        FALSE, 0, &res);
    test_sum(buf_ptr, buf_size, sum, TRUE, &res);

    simple_xfer(sub1_minor, 0xffffffffffffffffULL - sector_size + 1,
        buf_ptr, sector_size, FALSE, 0, &res);
    test_sum(buf_ptr, sector_size, sum2, TRUE, &res);
    got_result(&res, "read with negative offset");

    free_dma_memory(buf_ptr, buf_size);
}

static void write_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size)
{
	u8_t *buf_ptr;
	size_t buf_size;
	u32_t sum, sum2, sum3, sub1_sum;
	result_t res;

	test_group("write around subpartition limits", may_write);

	if (!may_write)
		return;

	buf_size = sector_size * 3;
	buf_ptr = alloc_dma_memory(buf_size);
	if (!buf_ptr)
		return;

	sub1_sum = fill_rand(buf_ptr, buf_size);
	simple_xfer(sub1_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
	got_result(&res, "write to second subpartition");

	sum = fill_rand(buf_ptr, sector_size);
	simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr,
		sector_size, TRUE, sector_size, &res);
	got_result(&res, "write up to partition end");

	fill_rand(buf_ptr, sector_size * 2);
	simple_xfer(sub0_minor, (u64_t)sub_size - sector_size * 2, buf_ptr,
		sector_size * 2, FALSE, sector_size * 2, &res);
	test_sum(buf_ptr + sector_size, sector_size, sum, TRUE, &res);
	got_result(&res, "read up to partition end");

	fill_rand(buf_ptr, buf_size);
	sum = get_sum(buf_ptr + sector_size, sector_size);
	sum3 = get_sum(buf_ptr, sector_size);
	simple_xfer(sub0_minor, (u64_t)sub_size - sector_size * 2, buf_ptr,
		buf_size, TRUE, sector_size * 2, &res);
	got_result(&res, "write somewhat across partition end");

	fill_rand(buf_ptr, buf_size);
	sum2 = get_sum(buf_ptr + sector_size, sector_size * 2);
	simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr,
		buf_size, FALSE, sector_size, &res);
	test_sum(buf_ptr, sector_size, sum, TRUE, &res);
	test_sum(buf_ptr + sector_size, sector_size * 2, sum2, TRUE, &res);
	got_result(&res, "read mostly across partition end");

	fill_rand(buf_ptr, buf_size);
	sum = get_sum(buf_ptr, sector_size);
	simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr,
		buf_size, TRUE, sector_size, &res);
	got_result(&res, "write mostly across partition end");

	fill_rand(buf_ptr, buf_size);
	sum2 = get_sum(buf_ptr + sector_size * 2, sector_size);
	simple_xfer(sub0_minor, (u64_t)sub_size - sector_size * 2, buf_ptr,
		buf_size, FALSE, sector_size * 2, &res);
	test_sum(buf_ptr, sector_size, sum3, TRUE, &res);
	test_sum(buf_ptr + sector_size, sector_size, sum, TRUE, &res);
	test_sum(buf_ptr + sector_size * 2, sector_size, sum2, TRUE, &res);
	got_result(&res, "read somewhat across partition end");

	fill_rand(buf_ptr, sector_size);
	simple_xfer(sub0_minor, (u64_t)sub_size, buf_ptr, sector_size, TRUE, 0,
		&res);
	got_result(&res, "write at partition end");

	simple_xfer(sub0_minor, (u64_t)sub_size + sector_size, buf_ptr,
		sector_size, TRUE, 0, &res);
	got_result(&res, "write beyond partition end");

	fill_rand(buf_ptr, buf_size);
	simple_xfer(sub1_minor, 0ULL, buf_ptr, buf_size, FALSE, buf_size,
		&res);
	test_sum(buf_ptr, buf_size, sub1_sum, TRUE, &res);
	got_result(&res, "read from second subpartition");

	fill_rand(buf_ptr, sector_size);
	simple_xfer(sub1_minor, 0xffffffffffffffffULL - sector_size + 1,
		buf_ptr, sector_size, TRUE, 0, &res);
	got_result(&res, "write with negative offset");

	simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr,
		sector_size, FALSE, sector_size, &res);
	test_sum(buf_ptr, sector_size, sum, TRUE, &res);
	got_result(&res, "read up to partition end");

	free_dma_memory(buf_ptr, buf_size);
}

static void vir_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
	struct part_geom subpart, subpart2;
	size_t sub_size;
	result_t res;

	test_group("virtual subpartition limits", TRUE);

	open_device(sub0_minor);
	open_device(sub1_minor);

	sub_size = sector_size * part_secs;

	if (!setup_first_subpartition(sub0_minor, sub_size)) {
		cleanup_devices(sub0_minor, sub1_minor);
		return;
	}

	if (!setup_second_subpartition(sub1_minor, sub_size)) {
		cleanup_devices(sub0_minor, sub1_minor);
		return;
	}

	read_limits(sub0_minor, sub1_minor, sub_size);
	write_limits(sub0_minor, sub1_minor, sub_size);

	cleanup_devices(sub0_minor, sub1_minor);
}

static bool setup_first_subpartition(dev_t minor, size_t sub_size)
{
	struct part_geom subpart, subpart2;
	result_t res;

	subpart = part;
	subpart.size = (u64_t)sub_size;

	vir_ioctl(minor, DIOCSETP, &subpart, OK, &res);
	got_result(&res, "ioctl to set first subpartition");

	if (res.type != RESULT_OK) {
		return false;
	}

	vir_ioctl(minor, DIOCGETP, &subpart2, OK, &res);

	if (res.type == RESULT_OK && !partition_params_match(&subpart, &subpart2)) {
		res.type = RESULT_BADVALUE;
		res.value = 0;
	}

	got_result(&res, "ioctl to get first subpartition");
	return res.type == RESULT_OK;
}

static bool setup_second_subpartition(dev_t minor, size_t sub_size)
{
	struct part_geom subpart, subpart2;
	result_t res;

	subpart = part;
	subpart.base += sub_size;
	subpart.size = (u64_t)sub_size;

	vir_ioctl(minor, DIOCSETP, &subpart, OK, &res);
	got_result(&res, "ioctl to set second subpartition");

	if (res.type != RESULT_OK) {
		return false;
	}

	vir_ioctl(minor, DIOCGETP, &subpart2, OK, &res);

	if (res.type == RESULT_OK && !partition_params_match(&subpart, &subpart2)) {
		res.type = RESULT_BADVALUE;
		res.value = 0;
	}

	got_result(&res, "ioctl to get second subpartition");
	return res.type == RESULT_OK;
}

static bool partition_params_match(const struct part_geom *p1, const struct part_geom *p2)
{
	return p1->base == p2->base && p1->size == p2->size;
}

static void cleanup_devices(dev_t sub0_minor, dev_t sub1_minor)
{
	close_device(sub1_minor);
	close_device(sub0_minor);
}

static void real_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
    u8_t *buf_ptr;
    size_t buf_size, sub_size;
    struct part_geom subpart;
    struct part_entry *entry;
    result_t res;

    test_group("real subpartition limits", may_write);

    if (!may_write)
        return;

    sub_size = sector_size * part_secs;
    buf_size = sector_size;
    buf_ptr = alloc_dma_memory(buf_size);
    
    if (!buf_ptr) {
        return;
    }

    memset(buf_ptr, 0, buf_size);

    simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
    got_result(&res, "write of invalid partition table");

    close_device(driver_minor);
    open_device(driver_minor);

    open_device(sub0_minor);
    open_device(sub1_minor);

    vir_ioctl(sub0_minor, DIOCGETP, &subpart, 0, &res);
    if (res.type == RESULT_OK && subpart.size != 0) {
        res.type = RESULT_BADVALUE;
        res.value = ex64lo(subpart.size);
    }
    got_result(&res, "ioctl to get first subpartition");

    vir_ioctl(sub1_minor, DIOCGETP, &subpart, 0, &res);
    if (res.type == RESULT_OK && subpart.size != 0) {
        res.type = RESULT_BADVALUE;
        res.value = ex64lo(subpart.size);
    }
    got_result(&res, "ioctl to get second subpartition");

    close_device(sub1_minor);
    close_device(sub0_minor);

    memset(buf_ptr, 0, buf_size);

    entry = (struct part_entry *) &buf_ptr[PART_TABLE_OFF];
    entry[0].sysind = MINIX_PART;
    entry[0].lowsec = part.base / sector_size + 1;
    entry[0].size = part_secs;
    entry[1].sysind = MINIX_PART;
    entry[1].lowsec = entry[0].lowsec + entry[0].size;
    entry[1].size = part_secs;

    buf_ptr[510] = 0x55;
    buf_ptr[511] = 0xAA;

    simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
    got_result(&res, "write of valid partition table");

    close_device(driver_minor);
    open_device(driver_minor);

    open_device(sub0_minor);
    open_device(sub1_minor);

    vir_ioctl(sub0_minor, DIOCGETP, &subpart, 0, &res);
    if (res.type == RESULT_OK &&
        (subpart.base != part.base + sector_size ||
         subpart.size != (u64_t)part_secs * sector_size)) {
        res.type = RESULT_BADVALUE;
        res.value = 0;
    }
    got_result(&res, "ioctl to get first subpartition");

    vir_ioctl(sub1_minor, DIOCGETP, &subpart, 0, &res);
    if (res.type == RESULT_OK &&
        (subpart.base != part.base + (1 + part_secs) * sector_size ||
         subpart.size != (u64_t)part_secs * sector_size)) {
        res.type = RESULT_BADVALUE;
        res.value = 0;
    }
    got_result(&res, "ioctl to get second subpartition");

    read_limits(sub0_minor, sub1_minor, sub_size);
    write_limits(sub0_minor, sub1_minor, sub_size);

    close_device(sub0_minor);
    close_device(sub1_minor);

    free_dma_memory(buf_ptr, buf_size);
}

static void part_limits(void)
{
    dev_t par, sub0_minor, sub1_minor;
    const int PART_SECS = 9;

    if (driver_minor >= MINOR_d0p0s0) {
        output("WARNING: operating on subpartition, "
            "skipping partition tests\n");
        return;
    }

    par = driver_minor % DEV_PER_DRIVE;
    if (par > 0) {
        sub0_minor = MINOR_d0p0s0 + ((driver_minor / DEV_PER_DRIVE) *
            NR_PARTITIONS + par - 1) * NR_PARTITIONS;
    } else {
        sub0_minor = driver_minor + 1;
    }
    sub1_minor = sub0_minor + 1;

    vir_limits(sub0_minor, sub1_minor, PART_SECS);
    real_limits(sub0_minor, sub1_minor, PART_SECS - 1);
}

static void unaligned_size_io(u64_t base_pos, u8_t *buf_ptr, size_t buf_size,
	u8_t *sec_ptr[2], int sectors, int pattern, u32_t ssum[5])
{
	iovec_t iov[3], iovt[3];
	u32_t rsum[3];
	result_t res;
	size_t total_size;
	int i, nr_req;

	if (!buf_ptr || !sec_ptr || !ssum) {
		return;
	}

	base_pos += sector_size;
	total_size = sector_size * sectors;

	if (sector_size / element_size == 2 && sectors == 1 && pattern == 2) {
		return;
	}

	fill_rand(sec_ptr[0], sector_size);
	rsum[0] = get_sum(sec_ptr[0] + element_size, sector_size - element_size);
	fill_rand(buf_ptr, buf_size);

	nr_req = setup_pattern(pattern, iovt, buf_ptr, sec_ptr, total_size, rsum);

	perform_read_test(base_pos, iov, iovt, nr_req, total_size, buf_ptr, 
		sec_ptr, pattern, sectors, ssum, rsum);

	if (!may_write) {
		return;
	}

	perform_write_test(base_pos, iov, iovt, nr_req, total_size, buf_ptr,
		sec_ptr, pattern, sectors, ssum);

	perform_readback_verification(base_pos, buf_ptr, ssum);
}

static int setup_pattern(int pattern, iovec_t *iovt, u8_t *buf_ptr, 
	u8_t *sec_ptr[2], size_t total_size, u32_t *rsum)
{
	switch (pattern) {
	case 0:
		iovt[0].iov_addr = (vir_bytes) sec_ptr[0];
		iovt[0].iov_size = element_size;
		iovt[1].iov_addr = (vir_bytes) buf_ptr;
		iovt[1].iov_size = total_size - element_size;
		rsum[1] = get_sum(buf_ptr + iovt[1].iov_size, element_size);
		return 2;
	case 1:
		iovt[0].iov_addr = (vir_bytes) buf_ptr;
		iovt[0].iov_size = total_size - element_size;
		rsum[1] = get_sum(buf_ptr + iovt[0].iov_size, element_size);
		iovt[1].iov_addr = (vir_bytes) sec_ptr[0];
		iovt[1].iov_size = element_size;
		return 2;
	case 2:
		iovt[0].iov_addr = (vir_bytes) sec_ptr[0];
		iovt[0].iov_size = element_size;
		iovt[1].iov_addr = (vir_bytes) buf_ptr;
		iovt[1].iov_size = total_size - element_size * 2;
		rsum[1] = get_sum(buf_ptr + iovt[1].iov_size, element_size * 2);
		fill_rand(sec_ptr[1], sector_size);
		iovt[2].iov_addr = (vir_bytes) sec_ptr[1];
		iovt[2].iov_size = element_size;
		rsum[2] = get_sum(sec_ptr[1] + element_size, sector_size - element_size);
		return 3;
	default:
		return 0;
	}
}

static void perform_read_test(u64_t base_pos, iovec_t *iov, iovec_t *iovt,
	int nr_req, size_t total_size, u8_t *buf_ptr, u8_t *sec_ptr[2],
	int pattern, int sectors, u32_t *ssum, u32_t *rsum)
{
	result_t res;
	int i;

	memcpy(iov, iovt, sizeof(iovec_t) * nr_req);
	vir_xfer(driver_minor, base_pos, iov, nr_req, FALSE, total_size, &res);

	test_sum(sec_ptr[0] + element_size, sector_size - element_size,
		rsum[0], TRUE, &res);

	perform_pattern_read_operations(pattern, iovt, buf_ptr, sec_ptr, rsum, &res);

	for (i = 0; i < sectors; i++) {
		test_sum(buf_ptr + sector_size * i, sector_size, ssum[1 + i],
			TRUE, &res);
	}

	got_result(&res, "read with small elements");
}

static void perform_pattern_read_operations(int pattern, iovec_t *iovt,
	u8_t *buf_ptr, u8_t *sec_ptr[2], u32_t *rsum, result_t *res)
{
	switch (pattern) {
	case 0:
		test_sum(buf_ptr + iovt[1].iov_size, element_size, rsum[1], TRUE, res);
		memmove(buf_ptr + element_size, buf_ptr, iovt[1].iov_size);
		memcpy(buf_ptr, sec_ptr[0], element_size);
		break;
	case 1:
		test_sum(buf_ptr + iovt[0].iov_size, element_size, rsum[1], TRUE, res);
		memcpy(buf_ptr + iovt[0].iov_size, sec_ptr[0], element_size);
		break;
	case 2:
		test_sum(buf_ptr + iovt[1].iov_size, element_size * 2, rsum[1], TRUE, res);
		test_sum(sec_ptr[1] + element_size, sector_size - element_size,
			rsum[2], TRUE, res);
		memmove(buf_ptr + element_size, buf_ptr, iovt[1].iov_size);
		memcpy(buf_ptr, sec_ptr[0], element_size);
		memcpy(buf_ptr + element_size + iovt[1].iov_size, sec_ptr[1],
			element_size);
		break;
	}
}

static void perform_write_test(u64_t base_pos, iovec_t *iov, iovec_t *iovt,
	int nr_req, size_t total_size, u8_t *buf_ptr, u8_t *sec_ptr[2],
	int pattern, int sectors, u32_t *ssum)
{
	result_t res;
	int i;

	for (i = 0; i < sectors; i++) {
		ssum[1 + i] = fill_rand(buf_ptr + sector_size * i, sector_size);
	}

	perform_pattern_write_operations(pattern, iovt, buf_ptr, sec_ptr);

	memcpy(iov, iovt, sizeof(iovec_t) * nr_req);
	vir_xfer(driver_minor, base_pos, iov, nr_req, TRUE, total_size, &res);

	got_result(&res, "write with small elements");
}

static void perform_pattern_write_operations(int pattern, iovec_t *iovt,
	u8_t *buf_ptr, u8_t *sec_ptr[2])
{
	switch (pattern) {
	case 0:
		memcpy(sec_ptr[0], buf_ptr, element_size);
		memmove(buf_ptr, buf_ptr + element_size, iovt[1].iov_size);
		fill_rand(buf_ptr + iovt[1].iov_size, element_size);
		break;
	case 1:
		memcpy(sec_ptr[0], buf_ptr + iovt[0].iov_size, element_size);
		fill_rand(buf_ptr + iovt[0].iov_size, element_size);
		break;
	case 2:
		memcpy(sec_ptr[0], buf_ptr, element_size);
		memcpy(sec_ptr[1], buf_ptr + element_size + iovt[1].iov_size,
			element_size);
		memmove(buf_ptr, buf_ptr + element_size, iovt[1].iov_size);
		fill_rand(buf_ptr + iovt[1].iov_size, element_size * 2);
		break;
	}
}

static void perform_readback_verification(u64_t base_pos, u8_t *buf_ptr,
	u32_t *ssum)
{
	result_t res;
	int i;

	fill_rand(buf_ptr, sector_size * 3);
	simple_xfer(driver_minor, base_pos, buf_ptr, sector_size * 3, FALSE,
		sector_size * 3, &res);

	for (i = 0; i < 3; i++) {
		test_sum(buf_ptr + sector_size * i, sector_size, ssum[1 + i],
			TRUE, &res);
	}

	got_result(&res, "readback verification");
}

static void unaligned_size(void)
{
	u8_t *buf_ptr = NULL, *sec_ptr[2] = {NULL, NULL};
	size_t buf_size;
	u32_t sum = 0L, ssum[5];
	u64_t base_pos;
	result_t res;
	int i;

	test_group("sector-unaligned elements", sector_size != element_size);

	if (sector_size == element_size)
		return;

	if (sector_size % element_size != 0)
		return;

	buf_size = sector_size * 5;
	base_pos = (u64_t)sector_size * 2;

	buf_ptr = alloc_dma_memory(buf_size);
	if (!buf_ptr)
		return;
	
	sec_ptr[0] = alloc_dma_memory(sector_size);
	if (!sec_ptr[0])
		goto cleanup_buf;
	
	sec_ptr[1] = alloc_dma_memory(sector_size);
	if (!sec_ptr[1])
		goto cleanup_sec0;

	if (may_write) {
		sum = fill_rand(buf_ptr, buf_size);

		for (i = 0; i < 5; i++)
			ssum[i] = get_sum(buf_ptr + sector_size * i, sector_size);

		simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE, buf_size, &res);
		got_result(&res, "write several sectors");
	}

	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);

	if (may_write) {
		test_sum(buf_ptr, buf_size, sum, TRUE, &res);
	} else {
		for (i = 0; i < 5; i++)
			ssum[i] = get_sum(buf_ptr + sector_size * i, sector_size);
	}

	got_result(&res, "read several sectors");

	for (i = 0; i < 9; i++) {
		unaligned_size_io(base_pos, buf_ptr, buf_size, sec_ptr,
			i / 3 + 1, i % 3, ssum);
	}

	if (may_write) {
		fill_rand(buf_ptr, buf_size);
		simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);
		test_sum(buf_ptr, sector_size, ssum[0], TRUE, &res);
		test_sum(buf_ptr + sector_size * 4, sector_size, ssum[4], TRUE, &res);
		got_result(&res, "check first and last sectors");
	}

	free_dma_memory(sec_ptr[1], sector_size);
cleanup_sec0:
	free_dma_memory(sec_ptr[0], sector_size);
cleanup_buf:
	free_dma_memory(buf_ptr, buf_size);
}

static void unaligned_pos1(void)
{
    u8_t *buf_ptr, *buf2_ptr;
    size_t buf_size, buf2_size, size;
    u32_t sum, sum2;
    u64_t base_pos;
    result_t res;

    test_group("sector-unaligned positions, part one", min_read != sector_size);

    if (min_read == sector_size)
        return;

    assert(sector_size % min_read == 0);
    assert(min_read % element_size == 0);

    buf_size = buf2_size = sector_size * 3;
    base_pos = (u64_t)sector_size * 3;

    buf_ptr = alloc_dma_memory(buf_size);
    if (!buf_ptr) return;
    
    buf2_ptr = alloc_dma_memory(buf2_size);
    if (!buf2_ptr) {
        free_dma_memory(buf_ptr, buf_size);
        return;
    }

    if (may_write) {
        sum = fill_rand(buf_ptr, buf_size);
        simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE, buf_size, &res);
        got_result(&res, "write several sectors");
    }

    fill_rand(buf_ptr, buf_size);
    simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);

    if (may_write)
        test_sum(buf_ptr, buf_size, sum, TRUE, &res);

    got_result(&res, "read several sectors");

    fill_rand(buf2_ptr, sector_size);
    sum = get_sum(buf2_ptr + min_read, sector_size - min_read);

    simple_xfer(driver_minor, base_pos + sector_size - min_read,
        buf2_ptr, min_read, FALSE, min_read, &res);

    test_sum(buf2_ptr, min_read, get_sum(buf_ptr + sector_size - min_read, min_read), TRUE, &res);
    test_sum(buf2_ptr + min_read, sector_size - min_read, sum, TRUE, &res);

    got_result(&res, "single sector read with lead");

    fill_rand(buf2_ptr, sector_size);
    sum = get_sum(buf2_ptr, sector_size - min_read);

    simple_xfer(driver_minor, base_pos, buf2_ptr + sector_size - min_read,
        min_read, FALSE, min_read, &res);

    test_sum(buf2_ptr + sector_size - min_read, min_read, get_sum(buf_ptr, min_read), TRUE, &res);
    test_sum(buf2_ptr, sector_size - min_read, sum, TRUE, &res);

    got_result(&res, "single sector read with trail");

    fill_rand(buf2_ptr, sector_size);
    sum = get_sum(buf2_ptr, min_read);
    sum2 = get_sum(buf2_ptr + min_read * 2, sector_size - min_read * 2);

    simple_xfer(driver_minor, base_pos + min_read, buf2_ptr + min_read,
        min_read, FALSE, min_read, &res);

    test_sum(buf2_ptr + min_read, min_read, get_sum(buf_ptr + min_read, min_read), TRUE, &res);
    test_sum(buf2_ptr, min_read, sum, TRUE, &res);
    test_sum(buf2_ptr + min_read * 2, sector_size - min_read * 2, sum2, TRUE, &res);

    got_result(&res, "single sector read with lead and trail");

    size = min_read + sector_size * 2;

    fill_rand(buf2_ptr, buf2_size);
    sum = get_sum(buf2_ptr + size, buf2_size - size);

    simple_xfer(driver_minor, base_pos + sector_size - min_read, buf2_ptr,
        size, FALSE, size, &res);

    test_sum(buf2_ptr, size, get_sum(buf_ptr + sector_size - min_read, size), TRUE, &res);
    test_sum(buf2_ptr + size, buf2_size - size, sum, TRUE, &res);

    got_result(&res, "multisector read with lead");

    fill_rand(buf2_ptr, buf2_size);
    sum = get_sum(buf2_ptr + size, buf2_size - size);

    simple_xfer(driver_minor, base_pos, buf2_ptr, size, FALSE, size, &res);

    test_sum(buf2_ptr, size, get_sum(buf_ptr, size), TRUE, &res);
    test_sum(buf2_ptr + size, buf2_size - size, sum, TRUE, &res);

    got_result(&res, "multisector read with trail");

    fill_rand(buf2_ptr, buf2_size);
    sum = get_sum(buf2_ptr + sector_size, buf2_size - sector_size);

    simple_xfer(driver_minor, base_pos + min_read, buf2_ptr, sector_size,
        FALSE, sector_size, &res);

    test_sum(buf2_ptr, sector_size, get_sum(buf_ptr + min_read, sector_size), TRUE, &res);
    test_sum(buf2_ptr + sector_size, buf2_size - sector_size, sum, TRUE, &res);

    got_result(&res, "multisector read with lead and trail");

    free_dma_memory(buf2_ptr, buf2_size);
    free_dma_memory(buf_ptr, buf_size);
}

static void unaligned_pos2(void)
{
	u8_t *buf_ptr = NULL, *buf2_ptr = NULL;
	size_t buf_size, buf2_size, max_block;
	u32_t sum = 0L, sum2 = 0L, rsum[NR_IOREQS];
	u64_t base_pos;
	iovec_t iov[NR_IOREQS];
	result_t res;
	int i;

	test_group("sector-unaligned positions, part two", min_read != sector_size);

	if (min_read == sector_size)
		return;

	buf_size = buf2_size = max_size + sector_size;
	base_pos = (u64_t)sector_size * 3;

	buf_ptr = alloc_dma_memory(buf_size);
	if (!buf_ptr) {
		got_result(&res, "failed to allocate first buffer");
		return;
	}

	buf2_ptr = alloc_dma_memory(buf2_size);
	if (!buf2_ptr) {
		free_dma_memory(buf_ptr, buf_size);
		got_result(&res, "failed to allocate second buffer");
		return;
	}

	if (may_write) {
		sum = fill_rand(buf_ptr, max_size);
		simple_xfer(driver_minor, base_pos, buf_ptr, max_size, TRUE, max_size, &res);
		got_result(&res, "large baseline write");

		sum2 = fill_rand(buf_ptr + max_size, sector_size);
		simple_xfer(driver_minor, base_pos + max_size, buf_ptr + max_size, sector_size, TRUE, sector_size, &res);
		got_result(&res, "small baseline write");
	}

	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, base_pos, buf_ptr, max_size, FALSE, max_size, &res);

	if (may_write)
		test_sum(buf_ptr, max_size, sum, TRUE, &res);

	got_result(&res, "large baseline read");

	simple_xfer(driver_minor, base_pos + max_size, buf_ptr + max_size, sector_size, FALSE, sector_size, &res);

	if (may_write)
		test_sum(buf_ptr + max_size, sector_size, sum2, TRUE, &res);

	got_result(&res, "small baseline read");

	fill_rand(buf2_ptr, buf2_size);

	for (i = 0; i < NR_IOREQS; i++) {
		iov[i].iov_addr = (vir_bytes) buf2_ptr + i * sector_size;
		iov[i].iov_size = min_read;
		rsum[i] = get_sum(buf2_ptr + i * sector_size + min_read, sector_size - min_read);
	}

	vir_xfer(driver_minor, base_pos + min_read, iov, NR_IOREQS, FALSE, min_read * NR_IOREQS, &res);

	for (i = 0; i < NR_IOREQS; i++) {
		test_sum(buf2_ptr + i * sector_size + min_read, sector_size - min_read, rsum[i], TRUE, &res);
		memmove(buf2_ptr + i * min_read, buf2_ptr + i * sector_size, min_read);
	}

	test_sum(buf2_ptr, min_read * NR_IOREQS, get_sum(buf_ptr + min_read, min_read * NR_IOREQS), TRUE, &res);
	got_result(&res, "small fully unaligned filled vector");

	fill_rand(buf2_ptr, buf2_size);
	simple_xfer(driver_minor, base_pos + min_read, buf2_ptr, max_size, FALSE, max_size, &res);
	test_sum(buf2_ptr, max_size, get_sum(buf_ptr + min_read, max_size), TRUE, &res);
	got_result(&res, "large fully unaligned single element");

	max_block = max_size / NR_IOREQS;
	max_block -= max_block % sector_size;

	fill_rand(buf2_ptr, buf2_size);

	for (i = 0; i < NR_IOREQS; i++) {
		iov[i].iov_addr = (vir_bytes) buf2_ptr + i * max_block;
		iov[i].iov_size = max_block;
	}

	vir_xfer(driver_minor, base_pos + min_read, iov, NR_IOREQS, FALSE, max_block * NR_IOREQS, &res);
	test_sum(buf2_ptr, max_block * NR_IOREQS, get_sum(buf_ptr + min_read, max_block * NR_IOREQS), TRUE, &res);
	got_result(&res, "large fully unaligned filled vector");

	free_dma_memory(buf2_ptr, buf2_size);
	free_dma_memory(buf_ptr, buf_size);
}

static void sweep_area(u64_t base_pos)
{
    u8_t *buf_ptr;
    size_t buf_size;
    u32_t sum = 0L, ssum[8];
    result_t res;
    int i, j;
    
    buf_size = sector_size * 8;
    buf_ptr = alloc_dma_memory(buf_size);
    if (!buf_ptr) {
        return;
    }
    
    if (may_write) {
        sum = fill_rand(buf_ptr, buf_size);
        simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE, buf_size, &res);
        got_result(&res, "write to full area");
    }
    
    fill_rand(buf_ptr, buf_size);
    simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);
    
    if (may_write) {
        test_sum(buf_ptr, buf_size, sum, TRUE, &res);
    }
    
    for (i = 0; i < 8; i++) {
        ssum[i] = get_sum(buf_ptr + sector_size * i, sector_size);
    }
    
    got_result(&res, "read from full area");
    
    for (i = 0; i < 6; i++) {
        fill_rand(buf_ptr, sector_size * 3);
        simple_xfer(driver_minor, base_pos + sector_size * i, buf_ptr, sector_size * 3, FALSE, sector_size * 3, &res);
        
        for (j = 0; j < 3; j++) {
            test_sum(buf_ptr + sector_size * j, sector_size, ssum[i + j], TRUE, &res);
        }
        
        got_result(&res, "read from subarea");
        
        if (!may_write) {
            continue;
        }
        
        fill_rand(buf_ptr, sector_size * 3);
        simple_xfer(driver_minor, base_pos + sector_size * i, buf_ptr, sector_size * 3, TRUE, sector_size * 3, &res);
        
        for (j = 0; j < 3; j++) {
            ssum[i + j] = get_sum(buf_ptr + sector_size * j, sector_size);
        }
        
        got_result(&res, "write to subarea");
    }
    
    if (may_write) {
        fill_rand(buf_ptr, buf_size);
        simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);
        
        for (i = 0; i < 8; i++) {
            test_sum(buf_ptr + sector_size * i, sector_size, ssum[i], TRUE, &res);
        }
        
        got_result(&res, "readback from full area");
    }
    
    free_dma_memory(buf_ptr, buf_size);
}

static void sweep_and_check(u64_t pos, int check_integ)
{
	u8_t *buf_ptr = NULL;
	size_t buf_size;
	u32_t sum = 0L;
	result_t res;

	if (!check_integ) {
		sweep_area(pos);
		return;
	}

	buf_size = sector_size * 3;
	buf_ptr = alloc_dma_memory(buf_size);
	if (!buf_ptr) {
		return;
	}

	if (may_write) {
		sum = fill_rand(buf_ptr, buf_size);
		simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
		got_result(&res, "write integrity zone");
	}

	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, FALSE, buf_size, &res);

	if (may_write) {
		test_sum(buf_ptr, buf_size, sum, TRUE, &res);
	} else {
		sum = get_sum(buf_ptr, buf_size);
	}

	got_result(&res, "read integrity zone");

	sweep_area(pos);

	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, FALSE, buf_size, &res);
	test_sum(buf_ptr, buf_size, sum, TRUE, &res);
	got_result(&res, "check integrity zone");

	free_dma_memory(buf_ptr, buf_size);
}

static void basic_sweep(void)
{
    test_group("basic area sweep", TRUE);
    sweep_area((u64_t)sector_size);
}

static void high_disk_pos(void)
{
	u64_t base_pos;
	u64_t threshold;
	u64_t partition_end;

	threshold = 0x100000000ULL;
	base_pos = threshold + (sector_size * 4);
	base_pos -= base_pos % sector_size;

	partition_end = part.base + part.size;
	if (partition_end < base_pos) {
		test_group("high disk positions", FALSE);
		return;
	}

	base_pos -= sector_size * 8;

	if (base_pos < part.base) {
		test_group("high disk positions", FALSE);
		return;
	}

	test_group("high disk positions", TRUE);

	base_pos -= part.base;

	sweep_and_check(base_pos, part.base == 0ULL);
}

static void high_part_pos(void)
{
	u64_t base_pos;

	if (part.base == 0ULL) {
		return;
	}

	base_pos = 0x100000000ULL + (sector_size * 4);
	base_pos -= base_pos % sector_size;

	if (part.size < base_pos) {
		test_group("high partition positions", FALSE);
		return;
	}

	test_group("high partition positions", TRUE);

	base_pos -= sector_size * 8;

	sweep_and_check(base_pos, TRUE);
}

static void high_lba_pos1(void)
{
    u64_t base_pos = (1ULL << 24) * sector_size;
    
    if (part.base + part.size < base_pos) {
        test_group("high LBA positions, part one", FALSE);
        return;
    }

    base_pos -= sector_size * 8;

    if (base_pos < part.base) {
        test_group("high LBA positions, part one", FALSE);
        return;
    }

    test_group("high LBA positions, part one", TRUE);

    base_pos -= part.base;

    sweep_and_check(base_pos, part.base == 0ULL);
}

static void high_lba_pos2(void)
{
	u64_t base_pos;
	u64_t min_partition_end;
	u64_t adjusted_base_pos;
	int run_tests;

	base_pos = (1ULL << 28) * sector_size;
	min_partition_end = base_pos;
	
	if (part.base + part.size < min_partition_end) {
		run_tests = 0;
	} else {
		adjusted_base_pos = base_pos - (sector_size * 8);
		run_tests = (adjusted_base_pos >= part.base) ? 1 : 0;
	}

	test_group("high LBA positions, part two", run_tests);

	if (run_tests) {
		adjusted_base_pos -= part.base;
		sweep_and_check(adjusted_base_pos, part.base == 0ULL);
	}
}

static void high_pos(void)
{
    basic_sweep();
    high_disk_pos();
    high_part_pos();
    high_lba_pos1();
    high_lba_pos2();
}

static void open_primary(void)
{
    test_group("device open", TRUE);
    open_device(driver_minor);
}

static void close_primary(void)
{
    test_group("device close", TRUE);
    close_device(driver_minor);
    assert(nr_opened == 0);
}

static void do_tests(void)
{
    open_primary();
    misc_ioctl();
    bad_read1();
    bad_read2();
    bad_write();
    vector_and_large();
    part_limits();
    unaligned_size();
    unaligned_pos1();
    unaligned_pos2();
    high_pos();
    close_primary();
}

static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
    if (env_argc > 1) {
        optset_parse(optset_table, env_argv[1]);
    }

    if (driver_label[0] == '\0') {
        panic("no driver label given");
    }

    if (ds_retrieve_label_endpt(driver_label, &driver_endpt) != OK) {
        panic("unable to resolve driver label");
    }

    if (driver_minor > 255) {
        panic("invalid or no driver minor given");
    }

    srand48(getticks());

    output("BLOCKTEST: driver label '%s' (endpt %d), minor %d\n",
           driver_label, driver_endpt, driver_minor);

    do_tests();

    output("BLOCKTEST: summary: %d out of %d tests failed "
           "across %d group%s; %d driver deaths\n",
           failed_tests, total_tests, failed_groups,
           failed_groups == 1 ? "" : "s", driver_deaths);

    return failed_tests ? EINVAL : OK;
}

static void sef_local_startup(void)
{
    if (sef_setcb_init_fresh(sef_cb_init_fresh) != OK) {
        return;
    }
    
    sef_startup();
}

int main(int argc, char **argv)
{
    if (argc < 0 || argv == NULL) {
        return -1;
    }

    if (env_setargs(argc, argv) != 0) {
        return -1;
    }

    if (sef_local_startup() != 0) {
        return -1;
    }

    return 0;
}
