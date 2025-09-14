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
	if (silent || fmt == NULL)
		return;

	va_list argp;
	va_start(argp, fmt);
	(void)vprintf(fmt, argp);
	va_end(argp);
}

static void *alloc_dma_memory(size_t size)
{
	void *ptr = NULL;

	if (contig) {
		ptr = alloc_contig(size, 0, NULL);
	} else {
		ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_PREALLOC | MAP_ANON, -1, 0);
	}

	if (ptr == NULL || ptr == MAP_FAILED) {
		panic("unable to allocate %zu bytes of memory", size);
	}

	return ptr;
}

static void free_dma_memory(void *ptr, size_t size)
{
	if (ptr == NULL || size == 0)
		return;

	if (contig) {
		free_contig(ptr, size);
		return;
	}

	(void)munmap(ptr, size);
}

static int set_result(result_t *res, int type, ssize_t value)
{
	if (res == NULL) {
		return type;
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
	if (res->type != type || res->value != value) {
		return FALSE;
	}
	set_result(res, RESULT_OK, 0);
	return TRUE;
}

static void got_result(result_t *res, char *desc)
{
	static int i = 0;
	const char *safe_desc = desc ? desc : "<no description>";
	const char *status;

	total_tests++;

	if (res == NULL) {
		failed_tests++;
		if (group_failure == FALSE) {
			failed_groups++;
			group_failure = TRUE;
		}
		status = "FAIL";
		output("#%02d: %-38s\t[%s]\n", ++i, safe_desc, status);
		output("- internal error: null result pointer\n");
		return;
	}

	if (res->type != RESULT_OK) {
		failed_tests++;
		if (group_failure == FALSE) {
			failed_groups++;
			group_failure = TRUE;
		}
	}

	status = (res->type == RESULT_OK) ? "PASS" : "FAIL";
	output("#%02d: %-38s\t[%s]\n", ++i, safe_desc, status);

	switch (res->type) {
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
	case RESULT_OK:
		break;
	default:
		output("- unknown result type %d\n", res->type);
		break;
	}
}

static void test_group(const char *name, int exec)
{
	const char *safe_name = (name != NULL) ? name : "(null)";
	const char *suffix = exec ? "" : " (skipping)";
	output("Test group: %s%s\n", safe_name, suffix);
	group_failure = FALSE;
}

static void reopen_device(dev_t minor)
{
    message msg = (message){0};
    int access = BDEV_R_BIT | (may_write ? BDEV_W_BIT : 0);

    msg.m_type = BDEV_OPEN;
    msg.m_lbdev_lblockdriver_msg.minor = minor;
    msg.m_lbdev_lblockdriver_msg.access = access;
    msg.m_lbdev_lblockdriver_msg.id = 0;

    (void)ipc_sendrec(driver_endpt, &msg);
}

static int sendrec_driver(message *m_ptr, ssize_t exp, result_t *res)
{
	message m_orig;
	endpoint_t last_endpt;
	int r;
	result_t dummy_res;

	if (res == NULL) {
		res = &dummy_res;
	}
	if (m_ptr == NULL) {
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
			if (r == OK && last_endpt != driver_endpt) {
				break;
			}
			micro_delay(100000);
		}

		for (int i = 0; i < nr_opened; i++) {
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

	{
		int reply_id = m_ptr->m_lblockdriver_lbdev_reply.id;
		int orig_id = m_orig.m_lbdev_lblockdriver_msg.id;

		if (reply_id != orig_id) {
			return set_result(res, RESULT_BADID, reply_id);
		}
	}

	{
		ssize_t status = m_ptr->m_lblockdriver_lbdev_reply.status;
		if ((exp < 0) != (status < 0)) {
			return set_result(res, RESULT_BADSTATUS, (int)status);
		}
	}

	return set_result(res, RESULT_OK, 0);
}

static void raw_xfer(dev_t minor, u64_t pos, iovec_s_t *iovec, int nr_req,
	int is_write, ssize_t exp, result_t *res)
{
	cp_grant_id_t grant;
	message m;
	int r;

	assert(nr_req <= NR_IOREQS);
	assert(!is_write || may_write);

	if (nr_req < 0 || (size_t)nr_req > ((size_t)-1) / sizeof(*iovec))
		panic("invalid iovec length");

	{
		size_t bytes = sizeof(*iovec) * (size_t)nr_req;

		grant = cpf_grant_direct(driver_endpt, (vir_bytes)iovec, bytes, CPF_READ);
		if (grant == GRANT_INVALID)
			panic("unable to allocate grant");
	}

	memset(&m, 0, sizeof(m));
	m.m_type = is_write ? BDEV_SCATTER : BDEV_GATHER;
	m.m_lbdev_lblockdriver_msg.minor = minor;
	m.m_lbdev_lblockdriver_msg.pos = pos;
	m.m_lbdev_lblockdriver_msg.count = nr_req;
	m.m_lbdev_lblockdriver_msg.grant = grant;
	m.m_lbdev_lblockdriver_msg.id = lrand48();

	r = sendrec_driver(&m, exp, res);

	if (cpf_revoke(grant) == -1)
		panic("unable to revoke grant");

	if (r == RESULT_OK) {
		ssize_t status = m.m_lblockdriver_lbdev_reply.status;

		if (status != exp) {
			if (exp < 0)
				set_result(res, RESULT_BADSTATUS, status);
			else
				set_result(res, RESULT_TRUNC, exp - status);
		}
	}
}

static void vir_xfer(dev_t minor, u64_t pos, iovec_t *iovec, int nr_req,
	int write, ssize_t exp, result_t *res)
{
	iovec_s_t iov_s[NR_IOREQS];
	int i;
	int access;

	assert(nr_req <= NR_IOREQS);

	access = write ? CPF_READ : CPF_WRITE;

	for (i = 0; i < nr_req; i++) {
		iov_s[i].iov_size = iovec[i].iov_size;
		iov_s[i].iov_grant = cpf_grant_direct(driver_endpt,
			(vir_bytes)iovec[i].iov_addr, iovec[i].iov_size, access);
		if (iov_s[i].iov_grant == GRANT_INVALID) {
			while (--i >= 0) {
				(void)cpf_revoke(iov_s[i].iov_grant);
			}
			panic("unable to allocate grant");
		}
	}

	raw_xfer(minor, pos, iov_s, nr_req, write, exp, res);

	for (i = 0; i < nr_req; i++) {
		iovec[i].iov_size = iov_s[i].iov_size;
		if (cpf_revoke(iov_s[i].iov_grant) == -1) {
			int j;
			for (j = i + 1; j < nr_req; j++) {
				(void)cpf_revoke(iov_s[j].iov_grant);
			}
			panic("unable to revoke grant");
		}
	}
}

static void simple_xfer(dev_t minor, u64_t pos, u8_t *buf, size_t size,
	int is_write, ssize_t exp, result_t *res)
{
	const int iov_cnt = 1;
	iovec_t iov = {
		.iov_addr = (vir_bytes)buf,
		.iov_size = size
	};

	vir_xfer(minor, pos, &iov, iov_cnt, is_write, exp, res);
}

static void alloc_buf_and_grant(u8_t **ptr, cp_grant_id_t *grant, size_t size, int perms)
{
	u8_t *buf;
	cp_grant_id_t gid;

	if (ptr == NULL || grant == NULL) {
		panic("alloc_buf_and_grant: invalid arguments");
		return;
	}

	buf = alloc_dma_memory(size);
	if (buf == NULL) {
		panic("alloc_buf_and_grant: unable to allocate DMA buffer");
		return;
	}

	gid = cpf_grant_direct(driver_endpt, (vir_bytes)buf, size, perms);
	if (gid == GRANT_INVALID) {
		panic("alloc_buf_and_grant: unable to allocate grant");
		return;
	}

	*ptr = buf;
	*grant = gid;
}

static void free_buf_and_grant(u8_t *ptr, cp_grant_id_t grant, size_t size)
{
	(void)cpf_revoke(grant);

	if (ptr != NULL && size > 0) {
		free_dma_memory(ptr, size);
	}
}

static void adjust_result_for_truncation(result_t *res, const message *m, ssize_t expected_status)
{
	if (res->type == RESULT_OK &&
	    m->m_lblockdriver_lbdev_reply.status != expected_status) {
		res->type = RESULT_TRUNC;
		res->value = m->m_lblockdriver_lbdev_reply.status;
	}
}

static void bad_read1(void)
{
	message mt, m;
	iovec_s_t iovt, iov;
	cp_grant_id_t grant, grant2, grant3;
	u8_t *buf_ptr;
	const vir_bytes buf_size = (vir_bytes)4096;
	result_t res;

	test_group("bad read requests, part one", TRUE);

	alloc_buf_and_grant(&buf_ptr, &grant2, buf_size, CPF_WRITE);

	if ((grant = cpf_grant_direct(driver_endpt, (vir_bytes)&iov, sizeof(iov), CPF_READ)) == GRANT_INVALID)
		panic("unable to allocate grant");

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
	adjust_result_for_truncation(&res, &m, (ssize_t)iov.iov_size);
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
	if ((grant3 = cpf_grant_direct(driver_endpt, (vir_bytes)&iov, sizeof(iov), CPF_READ)) == GRANT_INVALID)
		panic("unable to allocate grant");
	cpf_revoke(grant3);
	m.m_lbdev_lblockdriver_msg.grant = grant3;
	sendrec_driver(&m, EINVAL, &res);
	accept_result(&res, RESULT_BADSTATUS, EPERM);
	got_result(&res, "revoked iovec grant");

	m = mt;
	iov = iovt;
	sendrec_driver(&m, OK, &res);
	adjust_result_for_truncation(&res, &m, (ssize_t)iov.iov_size);
	got_result(&res, "normal request");

	free_buf_and_grant(buf_ptr, grant2, buf_size);
	cpf_revoke(grant);
}

static u32_t get_sum(const u8_t *ptr, size_t size)
{
    if (ptr == NULL || size == 0) {
        return 0;
    }

    u32_t sum = 0;
    const u8_t *end = ptr + size;

    while (ptr < end) {
        sum ^= (sum << 5) ^ (u32_t)(*ptr);
        ptr++;
    }

    return sum;
}

static u32_t fill_rand(u8_t *ptr, size_t size)
{
	size_t i;

	if (ptr == NULL || size == 0) {
		return 0;
	}

	for (i = 0; i < size; i++) {
		ptr[i] = (u8_t)lrand48();
	}

	return get_sum(ptr, size);
}

static void test_sum(u8_t *ptr, size_t size, u32_t sum, int should_match, result_t *res)
{
	if (res == NULL || res->type != RESULT_OK)
		return;

	if (ptr == NULL && size != 0U) {
		res->type = should_match ? RESULT_CORRUPT : RESULT_MISSING;
		res->value = 0;
		return;
	}

	u32_t computed_sum = get_sum(ptr, size);
	int matches = (sum == computed_sum);
	int expected_match = (should_match != 0);

	if (matches != expected_match) {
		res->type = expected_match ? RESULT_CORRUPT : RESULT_MISSING;
		res->value = 0;
	}
}

static void copy_iov3(iovec_s_t dst[3], const iovec_s_t src[3])
{
	memcpy(dst, src, sizeof(iovec_s_t) * 3);
}

static void fill3(u8_t *b1, size_t s1, u8_t *b2, size_t s2, u8_t *b3, size_t s3,
	u32_t *sum1, u32_t *sum2, u32_t *sum3)
{
	*sum1 = fill_rand(b1, s1);
	*sum2 = fill_rand(b2, s2);
	*sum3 = fill_rand(b3, s3);
}

static void test3(u8_t *b1, size_t s1, u32_t sum1, u8_t *b2, size_t s2, u32_t sum2,
	u8_t *b3, size_t s3, u32_t sum3, int nochange, result_t *res)
{
	test_sum(b1, s1, sum1, nochange, res);
	test_sum(b2, s2, sum2, nochange, res);
	test_sum(b3, s3, sum3, nochange, res);
}

static void bad_read2(void)
{
	u8_t *buf_ptr, *buf2_ptr, *buf3_ptr, c1, c2;
	size_t buf_size, buf2_size, buf3_size;
	cp_grant_id_t buf_grant, buf2_grant, buf3_grant, grant;
	u32_t buf_sum = 0, buf2_sum = 0, buf3_sum = 0;
	iovec_s_t iov[3], iovt[3];
	result_t res;
	const size_t IOVCNT = 3;

	memset(&res, 0, sizeof(res));

	test_group("bad read requests, part two", TRUE);

	buf_size = buf2_size = buf3_size = BUF_SIZE;

	alloc_buf_and_grant(&buf_ptr, &buf_grant, buf_size, CPF_WRITE);
	alloc_buf_and_grant(&buf2_ptr, &buf2_grant, buf2_size, CPF_WRITE);
	alloc_buf_and_grant(&buf3_ptr, &buf3_grant, buf3_size, CPF_WRITE);

	if (!buf_ptr || !buf2_ptr || !buf3_ptr ||
	    buf_grant == GRANT_INVALID || buf2_grant == GRANT_INVALID ||
	    buf3_grant == GRANT_INVALID)
		panic("unable to allocate buffers or grants");

	iovt[0].iov_grant = buf_grant;
	iovt[0].iov_size = buf_size;
	iovt[1].iov_grant = buf2_grant;
	iovt[1].iov_size = buf2_size;
	iovt[2].iov_grant = buf3_grant;
	iovt[2].iov_size = buf3_size;

	copy_iov3(iov, iovt);

	fill3(buf_ptr, buf_size, buf2_ptr, buf2_size, buf3_ptr, buf3_size,
	    &buf_sum, &buf2_sum, &buf3_sum);

	raw_xfer(driver_minor, 0ULL, iov, (int)IOVCNT, FALSE,
	    buf_size + buf2_size + buf3_size, &res);

	test3(buf_ptr, buf_size, buf_sum, buf2_ptr, buf2_size, buf2_sum,
	    buf3_ptr, buf3_size, buf3_sum, FALSE, &res);

	got_result(&res, "normal vector request");

	copy_iov3(iov, iovt);
	iov[1].iov_size = 0;

	fill3(buf_ptr, buf_size, buf2_ptr, buf2_size, buf3_ptr, buf3_size,
	    &buf_sum, &buf2_sum, &buf3_sum);

	raw_xfer(driver_minor, 0ULL, iov, (int)IOVCNT, FALSE, EINVAL, &res);

	test3(buf_ptr, buf_size, buf_sum, buf2_ptr, buf2_size, buf2_sum,
	    buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

	got_result(&res, "zero size in iovec element");

	copy_iov3(iov, iovt);
	iov[1].iov_size = (vir_bytes) LONG_MAX + 1;

	raw_xfer(driver_minor, 0ULL, iov, (int)IOVCNT, FALSE, EINVAL, &res);

	test3(buf_ptr, buf_size, buf_sum, buf2_ptr, buf2_size, buf2_sum,
	    buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

	got_result(&res, "negative size in iovec element");

	copy_iov3(iov, iovt);
	iov[0].iov_size = LONG_MAX / 2 - 1;
	iov[1].iov_size = LONG_MAX / 2 - 1;

	raw_xfer(driver_minor, 0ULL, iov, (int)IOVCNT, FALSE, EINVAL, &res);

	test3(buf_ptr, buf_size, buf_sum, buf2_ptr, buf2_size, buf2_sum,
	    buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

	got_result(&res, "negative total size");

	copy_iov3(iov, iovt);
	iov[0].iov_size = LONG_MAX - 1;
	iov[1].iov_size = LONG_MAX - 1;

	raw_xfer(driver_minor, 0ULL, iov, (int)IOVCNT, FALSE, EINVAL, &res);

	test3(buf_ptr, buf_size, buf_sum, buf2_ptr, buf2_size, buf2_sum,
	    buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

	got_result(&res, "wrapping total size");

	copy_iov3(iov, iovt);
	iov[1].iov_size--;

	fill3(buf_ptr, buf_size, buf2_ptr, buf2_size, buf3_ptr, buf3_size,
	    &buf_sum, &buf2_sum, &buf3_sum);
	c1 = buf2_ptr[buf2_size - 1];

	raw_xfer(driver_minor, 0ULL, iov, (int)IOVCNT, FALSE,
	    (buf_size + buf2_size + buf3_size) - 1, &res);

	if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
		test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
		test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);
	} else {
		test3(buf_ptr, buf_size, buf_sum, buf2_ptr, buf2_size, buf2_sum,
		    buf3_ptr, buf3_size, buf3_sum, FALSE, &res);
		if (c1 != buf2_ptr[buf2_size - 1])
			set_result(&res, RESULT_CORRUPT, 0);
	}

	got_result(&res, "word-unaligned size in iovec element");

	copy_iov3(iov, iovt);
	iov[1].iov_grant = GRANT_INVALID;

	fill_rand(buf_ptr, buf_size);
	buf2_sum = fill_rand(buf2_ptr, buf2_size);
	buf3_sum = fill_rand(buf3_ptr, buf3_size);

	raw_xfer(driver_minor, 0ULL, iov, (int)IOVCNT, FALSE, EINVAL, &res);

	test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
	test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

	got_result(&res, "invalid grant in iovec element");

	copy_iov3(iov, iovt);
	grant = cpf_grant_direct(driver_endpt, (vir_bytes) buf2_ptr,
	    buf2_size, CPF_WRITE);
	if (grant == GRANT_INVALID)
		panic("unable to allocate grant");

	cpf_revoke(grant);

	iov[1].iov_grant = grant;

	fill3(buf_ptr, buf_size, buf2_ptr, buf2_size, buf3_ptr, buf3_size,
	    &buf_sum, &buf2_sum, &buf3_sum);

	raw_xfer(driver_minor, 0ULL, iov, (int)IOVCNT, FALSE, EINVAL, &res);

	accept_result(&res, RESULT_BADSTATUS, EPERM);

	test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
	test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

	got_result(&res, "revoked grant in iovec element");

	copy_iov3(iov, iovt);
	grant = cpf_grant_direct(driver_endpt, (vir_bytes) buf2_ptr,
	    buf2_size, CPF_READ);
	if (grant == GRANT_INVALID)
		panic("unable to allocate grant");

	iov[1].iov_grant = grant;

	fill3(buf_ptr, buf_size, buf2_ptr, buf2_size, buf3_ptr, buf3_size,
	    &buf_sum, &buf2_sum, &buf3_sum);

	raw_xfer(driver_minor, 0ULL, iov, (int)IOVCNT, FALSE, EINVAL, &res);

	accept_result(&res, RESULT_BADSTATUS, EPERM);

	test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
	test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

	got_result(&res, "read-only grant in iovec element");

	cpf_revoke(grant);

	copy_iov3(iov, iovt);
	grant = cpf_grant_direct(driver_endpt, (vir_bytes) (buf2_ptr + 1),
	    buf2_size - 2, CPF_WRITE);
	if (grant == GRANT_INVALID)
		panic("unable to allocate grant");

	iov[1].iov_grant = grant;
	iov[1].iov_size = buf2_size - 2;

	fill3(buf_ptr, buf_size, buf2_ptr, buf2_size, buf3_ptr, buf3_size,
	    &buf_sum, &buf2_sum, &buf3_sum);
	c1 = buf2_ptr[0];
	c2 = buf2_ptr[buf2_size - 1];

	raw_xfer(driver_minor, 0ULL, iov, (int)IOVCNT, FALSE,
	    (buf_size + buf2_size + buf3_size) - 2, &res);

	if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
		test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, &res);
		test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, &res);
	} else {
		test3(buf_ptr, buf_size, buf_sum, buf2_ptr, buf2_size, buf2_sum,
		    buf3_ptr, buf3_size, buf3_sum, FALSE, &res);
		if (c1 != buf2_ptr[0] || c2 != buf2_ptr[buf2_size - 1])
			set_result(&res, RESULT_CORRUPT, 0);
	}

	got_result(&res, "word-unaligned buffer in iovec element");

	cpf_revoke(grant);

	if (min_read > 1) {
		copy_iov3(iov, iovt);

		fill3(buf_ptr, buf_size, buf2_ptr, buf2_size, buf3_ptr, buf3_size,
		    &buf_sum, &buf2_sum, &buf3_sum);

		raw_xfer(driver_minor, 1ULL, iov, (int)IOVCNT, FALSE, EINVAL, &res);

		test3(buf_ptr, buf_size, buf_sum, buf2_ptr, buf2_size, buf2_sum,
		    buf3_ptr, buf3_size, buf3_sum, TRUE, &res);

		got_result(&res, "word-unaligned position");
	}

	copy_iov3(iov, iovt);

	fill3(buf_ptr, buf_size, buf2_ptr, buf2_size, buf3_ptr, buf3_size,
	    &buf_sum, &buf2_sum, &buf3_sum);

	raw_xfer(driver_minor, 0ULL, iov, (int)IOVCNT, FALSE,
	    buf_size + buf2_size + buf3_size, &res);

	test3(buf_ptr, buf_size, buf_sum, buf2_ptr, buf2_size, buf2_sum,
	    buf3_ptr, buf3_size, buf3_sum, FALSE, &res);

	got_result(&res, "normal vector request");

	free_buf_and_grant(buf3_ptr, buf3_grant, buf3_size);
	free_buf_and_grant(buf2_ptr, buf2_grant, buf2_size);
	free_buf_and_grant(buf_ptr, buf_grant, buf_size);
}

static void fill_buffers(u8_t *const bufs[], const size_t sizes[], u32_t sums[], size_t count)
{
	size_t i;
	for (i = 0; i < count; i++) {
		sums[i] = fill_rand(bufs[i], sizes[i]);
	}
}

static void verify_buffers(const u8_t *const bufs[], const size_t sizes[], const u32_t sums[], size_t count, result_t *res)
{
	size_t i;
	for (i = 0; i < count; i++) {
		test_sum(bufs[i], sizes[i], sums[i], TRUE, res);
	}
}

static void bad_write(void)
{
	u8_t *buf_ptr, *buf2_ptr, *buf3_ptr;
	size_t buf_size, buf2_size, buf3_size, sector_unalign;
	cp_grant_id_t buf_grant, buf2_grant, buf3_grant;
	cp_grant_id_t grant;
	u32_t sums[3];
	iovec_s_t iov[3], iovt[3];
	result_t res;

	const int iov_cnt = 3;

	test_group("bad write requests", may_write);

	if (!may_write)
		return;

	buf_size = buf2_size = buf3_size = BUF_SIZE;

	alloc_buf_and_grant(&buf_ptr, &buf_grant, buf_size, CPF_READ);
	alloc_buf_and_grant(&buf2_ptr, &buf2_grant, buf2_size, CPF_READ);
	alloc_buf_and_grant(&buf3_ptr, &buf3_grant, buf3_size, CPF_READ);

	if (buf_ptr == NULL || buf_grant == GRANT_INVALID) panic("unable to allocate buffer/grant");
	if (buf2_ptr == NULL || buf2_grant == GRANT_INVALID) panic("unable to allocate buffer/grant");
	if (buf3_ptr == NULL || buf3_grant == GRANT_INVALID) panic("unable to allocate buffer/grant");

	u8_t *bufs[3] = { buf_ptr, buf2_ptr, buf3_ptr };
	size_t sizes[3] = { buf_size, buf2_size, buf3_size };
	cp_grant_id_t grants[3] = { buf_grant, buf2_grant, buf3_grant };

	memset(iov, 0, sizeof(iov));
	memset(iovt, 0, sizeof(iovt));
	{
		size_t i;
		for (i = 0; i < (size_t)iov_cnt; i++) {
			iovt[i].iov_grant = grants[i];
			iovt[i].iov_size = sizes[i];
		}
	}

	if (min_write == 0)
		min_write = sector_size;

	if (min_write > 1) {
		sector_unalign = (min_write > 2) ? 2 : 1;

		memcpy(iov, iovt, sizeof(iov));
		fill_buffers(bufs, sizes, sums, (size_t)iov_cnt);

		raw_xfer(driver_minor, (u64_t)sector_unalign, iov, iov_cnt, TRUE, EINVAL, &res);

		verify_buffers((const u8_t *const *)bufs, sizes, sums, (size_t)iov_cnt, &res);
		got_result(&res, "sector-unaligned write position");

		memcpy(iov, iovt, sizeof(iov));
		if (iov[1].iov_size < sector_unalign) panic("sector_unalign exceeds iovec element size");
		iov[1].iov_size -= sector_unalign;

		fill_buffers(bufs, sizes, sums, (size_t)iov_cnt);

		raw_xfer(driver_minor, 0ULL, iov, iov_cnt, TRUE, EINVAL, &res);

		verify_buffers((const u8_t *const *)bufs, sizes, sums, (size_t)iov_cnt, &res);
		got_result(&res, "sector-unaligned write size");
	}

	memcpy(iov, iovt, sizeof(iov));
	grant = cpf_grant_direct(driver_endpt, (vir_bytes) buf2_ptr, buf2_size, CPF_WRITE);
	if (grant == GRANT_INVALID)
		panic("unable to allocate grant");

	iov[1].iov_grant = grant;

	fill_buffers(bufs, sizes, sums, (size_t)iov_cnt);

	raw_xfer(driver_minor, 0ULL, iov, iov_cnt, TRUE, EINVAL, &res);

	accept_result(&res, RESULT_BADSTATUS, EPERM);

	verify_buffers((const u8_t *const *)bufs, sizes, sums, (size_t)iov_cnt, &res);
	got_result(&res, "write-only grant in iovec element");

	cpf_revoke(grant);

	free_buf_and_grant(buf3_ptr, buf3_grant, buf3_size);
	free_buf_and_grant(buf2_ptr, buf2_grant, buf2_size);
	free_buf_and_grant(buf_ptr, buf_grant, buf_size);
}

static void vector_and_large_sub(size_t small_size)
{
	size_t large_size, buf_size, buf2_size;
	u8_t *buf_ptr = NULL, *buf2_ptr = NULL;
	iovec_t iovec[NR_IOREQS];
	u64_t base_pos = (u64_t)sector_size;
	result_t res;
	int i;

	const size_t guard = sizeof(u32_t);
	const size_t iovcnt = (size_t)NR_IOREQS;
	const size_t SIZE_MAX_LOCAL = (size_t)~(size_t)0;

	if (small_size != 0 && iovcnt > SIZE_MAX_LOCAL / small_size) return;
	large_size = small_size * iovcnt;

	if (guard > SIZE_MAX_LOCAL / 2) return;
	if (large_size > SIZE_MAX_LOCAL - 2 * guard) return;
	buf_size = large_size + 2 * guard;

	if (iovcnt > SIZE_MAX_LOCAL - 1) return;
	{
		size_t guard_count = iovcnt + 1;
		if (guard_count > SIZE_MAX_LOCAL / guard) return;
		{
			size_t guards_total = guard * guard_count;
			if (large_size > SIZE_MAX_LOCAL - guards_total) return;
			buf2_size = large_size + guards_total;
		}
	}

	buf_ptr = alloc_dma_memory(buf_size);
	if (!buf_ptr) goto cleanup;
	buf2_ptr = alloc_dma_memory(buf2_size);
	if (!buf2_ptr) goto cleanup;

#define SPTR(n) (buf2_ptr + guard + (n) * (guard + small_size))
#define LPTR(n) (buf_ptr  + guard + (n) * small_size)
#define GUARD_BEFORE(p) (*(((u32_t *)(p)) - 1))

	if (may_write) {
		fill_rand(buf_ptr, buf_size);

		iovec[0].iov_addr = (vir_bytes)(buf_ptr + guard);
		iovec[0].iov_size = large_size;

		vir_xfer(driver_minor, base_pos, iovec, 1, TRUE, large_size, &res);
		got_result(&res, "large write");
	}

	for (i = 0; i < (int)iovcnt; i++) {
		GUARD_BEFORE(SPTR(i)) = 0xDEADBEEFL + (u32_t)i;
		iovec[i].iov_addr = (vir_bytes)SPTR(i);
		iovec[i].iov_size = small_size;
	}
	GUARD_BEFORE(SPTR(i)) = 0xFEEDFACEL;

	vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, FALSE, large_size, &res);

	if (res.type == RESULT_OK) {
		for (i = 0; i < (int)iovcnt; i++) {
			if (GUARD_BEFORE(SPTR(i)) != 0xDEADBEEFL + (u32_t)i)
				set_result(&res, RESULT_OVERFLOW, 0);
		}
		if (GUARD_BEFORE(SPTR(i)) != 0xFEEDFACEL)
			set_result(&res, RESULT_OVERFLOW, 0);
	}

	if (res.type == RESULT_OK && may_write) {
		for (i = 0; i < (int)iovcnt; i++) {
			test_sum(SPTR(i), small_size, get_sum(LPTR(i), small_size), TRUE, &res);
		}
	}

	got_result(&res, "vectored read");

	if (may_write) {
		fill_rand(buf2_ptr, buf2_size);

		for (i = 0; i < (int)iovcnt; i++) {
			iovec[i].iov_addr = (vir_bytes)SPTR(i);
			iovec[i].iov_size = small_size;
		}

		vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, TRUE, large_size, &res);
		got_result(&res, "vectored write");
	}

	*(u32_t *)buf_ptr = 0xCAFEBABEL;
	*(u32_t *)(buf_ptr + guard + large_size) = 0xDECAFBADL;

	iovec[0].iov_addr = (vir_bytes)(buf_ptr + guard);
	iovec[0].iov_size = large_size;

	vir_xfer(driver_minor, base_pos, iovec, 1, FALSE, large_size, &res);

	if (res.type == RESULT_OK) {
		if (*(u32_t *)buf_ptr != 0xCAFEBABEL)
			set_result(&res, RESULT_OVERFLOW, 0);
		if (*(u32_t *)(buf_ptr + guard + large_size) != 0xDECAFBADL)
			set_result(&res, RESULT_OVERFLOW, 0);
	}

	if (res.type == RESULT_OK) {
		for (i = 0; i < (int)iovcnt; i++) {
			test_sum(SPTR(i), small_size, get_sum(LPTR(i), small_size), TRUE, &res);
		}
	}

	got_result(&res, "large read");

#undef GUARD_BEFORE
#undef LPTR
#undef SPTR

cleanup:
	if (buf2_ptr) free_dma_memory(buf2_ptr, buf2_size);
	if (buf_ptr) free_dma_memory(buf_ptr, buf_size);
}

static void vector_and_large(void)
{
	size_t max_block = 0;
	const size_t common_block_size = 4096;

	if (sector_size > 0) {
		size_t margin;
		if (sector_size <= part.size / 4)
			margin = sector_size * 4;
		else
			margin = part.size;

		{
			size_t max_allowed = part.size - margin;
			if (max_size > max_allowed)
				max_size = max_allowed;
		}
	} else {
		if (max_size > part.size)
			max_size = part.size;
	}

	if (NR_IOREQS != 0 && sector_size != 0) {
		max_block = max_size / NR_IOREQS;
		max_block -= max_block % sector_size;
	}

	test_group("vector and large, common block", TRUE);
	vector_and_large_sub(common_block_size);

	if (max_block != 0 && max_block != common_block_size) {
		test_group("vector and large, large block", TRUE);
		vector_and_large_sub(max_block);
	}
}

static void open_device(dev_t minor)
{
	message msg = (message){0};
	result_t res;
	const char *desc = (minor == driver_minor) ? "opening the main partition" : "opening a subpartition";

	msg.m_type = BDEV_OPEN;
	msg.m_lbdev_lblockdriver_msg.minor = minor;
	msg.m_lbdev_lblockdriver_msg.access = may_write ? (BDEV_R_BIT | BDEV_W_BIT) : BDEV_R_BIT;
	msg.m_lbdev_lblockdriver_msg.id = lrand48();

	sendrec_driver(&msg, OK, &res);

	assert(nr_opened < NR_OPENED);
	if (nr_opened < NR_OPENED) {
		opened[nr_opened++] = minor;
	}

	got_result(&res, desc);
}

static void close_device(dev_t minor)
{
	message m = {0};
	result_t res;
	const char *desc;
	int i;

	m.m_type = BDEV_CLOSE;
	m.m_lbdev_lblockdriver_msg.minor = minor;
	m.m_lbdev_lblockdriver_msg.id = lrand48();

	sendrec_driver(&m, OK, &res);

	assert(nr_opened > 0);
	for (i = 0; i < nr_opened; i++) {
		if (opened[i] == minor) {
			opened[i] = opened[--nr_opened];
			break;
		}
	}

	desc = (minor == driver_minor) ? "closing the main partition" :
		"closing a subpartition";
	got_result(&res, desc);
}

static int vir_ioctl(dev_t minor, unsigned long req, void *ptr, ssize_t exp, result_t *res)
{
	cp_grant_id_t grant;
	message m = {0};
	int r;
	int perm = 0;

	assert(!_MINIX_IOCTL_BIG(req));

	if (_MINIX_IOCTL_IOR(req)) perm |= CPF_WRITE;
	if (_MINIX_IOCTL_IOW(req)) perm |= CPF_READ;

	grant = cpf_grant_direct(driver_endpt, (vir_bytes)ptr, _MINIX_IOCTL_SIZE(req), perm);
	if (grant == GRANT_INVALID)
		panic("unable to allocate grant");

	m.m_type = BDEV_IOCTL;
	m.m_lbdev_lblockdriver_msg.minor = minor;
	m.m_lbdev_lblockdriver_msg.request = req;
	m.m_lbdev_lblockdriver_msg.grant = grant;
	m.m_lbdev_lblockdriver_msg.user = NONE;
	m.m_lbdev_lblockdriver_msg.id = lrand48();

	r = sendrec_driver(&m, exp, res);

	if (cpf_revoke(grant) == -1)
		panic("unable to revoke grant");

	return r;
}

static const int OPENCT_SENTINEL = 0x0badcafe;

static void check_open_count(int expected_count, const char *message, result_t *res_ptr)
{
	int openct = OPENCT_SENTINEL;

	vir_ioctl(driver_minor, DIOCOPENCT, &openct, OK, res_ptr);

	if (res_ptr->type == RESULT_OK && openct != expected_count) {
		res_ptr->type = RESULT_BADVALUE;
		res_ptr->value = openct;
	}

	got_result(res_ptr, message);
}

static void misc_ioctl(void)
{
	result_t res;

	test_group("test miscellaneous ioctls", TRUE);

	vir_ioctl(driver_minor, DIOCGETP, &part, OK, &res);
	got_result(&res, "ioctl to get partition");

	if (res.type == RESULT_OK && part.size < 2ULL * (u64_t)max_size)
		output("WARNING: small partition, some tests may fail\n");

	check_open_count(1, "ioctl to get open count", &res);

	open_device(driver_minor);
	check_open_count(2, "increased open count after opening", &res);

	close_device(driver_minor);
	check_open_count(1, "decreased open count after closing", &res);
}

static void read_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size)
{
	u8_t *buf_ptr = NULL;
	size_t buf_size;
	u32_t sum = 0, sum2 = 0, sum3 = 0;
	result_t res;
	const u64_t huge_beyond = 0x1000000000000000ULL;
	u64_t offset;

	test_group("read around subpartition limits", TRUE);

	if (sector_size == 0 || sector_size > SIZE_MAX / 3)
		return;

	buf_size = sector_size * 3;
	buf_ptr = alloc_dma_memory(buf_size);
	if (buf_ptr == NULL)
		return;

	fill_rand(buf_ptr, buf_size);

	offset = (u64_t)sub_size - sector_size;
	simple_xfer(sub0_minor, offset, buf_ptr, sector_size, FALSE, sector_size, &res);

	sum = get_sum(buf_ptr, sector_size);

	got_result(&res, "one sector read up to partition end");

	fill_rand(buf_ptr, buf_size);

	offset = (u64_t)sub_size - buf_size;
	simple_xfer(sub0_minor, offset, buf_ptr, buf_size, FALSE, buf_size, &res);

	test_sum(buf_ptr + sector_size * 2, sector_size, sum, TRUE, &res);

	sum2 = get_sum(buf_ptr + sector_size, sector_size * 2);

	got_result(&res, "multisector read up to partition end");

	fill_rand(buf_ptr, buf_size);
	sum3 = get_sum(buf_ptr + sector_size * 2, sector_size);

	offset = (u64_t)sub_size - sector_size * 2;
	simple_xfer(sub0_minor, offset, buf_ptr, buf_size, FALSE, sector_size * 2, &res);

	test_sum(buf_ptr, sector_size * 2, sum2, TRUE, &res);
	test_sum(buf_ptr + sector_size * 2, sector_size, sum3, TRUE, &res);

	got_result(&res, "read somewhat across partition end");

	fill_rand(buf_ptr, buf_size);
	sum2 = get_sum(buf_ptr + sector_size, sector_size * 2);

	offset = (u64_t)sub_size - sector_size;
	simple_xfer(sub0_minor, offset, buf_ptr, buf_size, FALSE, sector_size, &res);

	test_sum(buf_ptr, sector_size, sum, TRUE, &res);
	test_sum(buf_ptr + sector_size, sector_size * 2, sum2, TRUE, &res);

	got_result(&res, "read mostly across partition end");

	sum = fill_rand(buf_ptr, buf_size);
	sum2 = get_sum(buf_ptr, sector_size);

	offset = (u64_t)sub_size;
	simple_xfer(sub0_minor, offset, buf_ptr, sector_size, FALSE, 0, &res);

	test_sum(buf_ptr, sector_size, sum2, TRUE, &res);

	got_result(&res, "one sector read at partition end");

	simple_xfer(sub0_minor, offset, buf_ptr, buf_size, FALSE, 0, &res);

	test_sum(buf_ptr, buf_size, sum, TRUE, &res);

	got_result(&res, "multisector read at partition end");

	offset = (u64_t)sub_size + sector_size;
	simple_xfer(sub0_minor, offset, buf_ptr, buf_size, FALSE, 0, &res);

	test_sum(buf_ptr, sector_size, sum2, TRUE, &res);

	got_result(&res, "single sector read beyond partition end");

	simple_xfer(sub0_minor, huge_beyond, buf_ptr, buf_size, FALSE, 0, &res);

	test_sum(buf_ptr, buf_size, sum, TRUE, &res);

	offset = UINT64_MAX - (u64_t)sector_size + 1;
	simple_xfer(sub1_minor, offset, buf_ptr, sector_size, FALSE, 0, &res);

	test_sum(buf_ptr, sector_size, sum2, TRUE, &res);

	got_result(&res, "read with negative offset");

	free_dma_memory(buf_ptr, buf_size);
}

static void write_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size)
{
	u8_t *buf_ptr;
	const size_t sl = sector_size;
	const size_t buf_size = sl * 3;
	u32_t sum, sum2, sum3, sub1_sum;
	result_t res;

	test_group("write around subpartition limits", may_write);
	if (!may_write) return;

	buf_ptr = alloc_dma_memory(buf_size);
	if (buf_ptr == NULL) return;

	sub1_sum = fill_rand(buf_ptr, buf_size);
	simple_xfer(sub1_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
	got_result(&res, "write to second subpartition");

	sum = fill_rand(buf_ptr, sl);
	simple_xfer(sub0_minor, (u64_t)sub_size - (u64_t)sl, buf_ptr, sl, TRUE, sl, &res);
	got_result(&res, "write up to partition end");

	fill_rand(buf_ptr, sl * 2);
	simple_xfer(sub0_minor, (u64_t)sub_size - (u64_t)sl * 2, buf_ptr, sl * 2, FALSE, sl * 2, &res);
	test_sum(buf_ptr + sl, sl, sum, TRUE, &res);
	got_result(&res, "read up to partition end");

	fill_rand(buf_ptr, buf_size);
	sum = get_sum(buf_ptr + sl, sl);
	sum3 = get_sum(buf_ptr, sl);
	simple_xfer(sub0_minor, (u64_t)sub_size - (u64_t)sl * 2, buf_ptr, buf_size, TRUE, sl * 2, &res);
	got_result(&res, "write somewhat across partition end");

	fill_rand(buf_ptr, buf_size);
	sum2 = get_sum(buf_ptr + sl, sl * 2);
	simple_xfer(sub0_minor, (u64_t)sub_size - (u64_t)sl, buf_ptr, buf_size, FALSE, sl, &res);
	test_sum(buf_ptr, sl, sum, TRUE, &res);
	test_sum(buf_ptr + sl, sl * 2, sum2, TRUE, &res);
	got_result(&res, "read mostly across partition end");

	fill_rand(buf_ptr, buf_size);
	sum = get_sum(buf_ptr, sl);
	simple_xfer(sub0_minor, (u64_t)sub_size - (u64_t)sl, buf_ptr, buf_size, TRUE, sl, &res);
	got_result(&res, "write mostly across partition end");

	fill_rand(buf_ptr, buf_size);
	sum2 = get_sum(buf_ptr + sl * 2, sl);
	simple_xfer(sub0_minor, (u64_t)sub_size - (u64_t)sl * 2, buf_ptr, buf_size, FALSE, sl * 2, &res);
	test_sum(buf_ptr, sl, sum3, TRUE, &res);
	test_sum(buf_ptr + sl, sl, sum, TRUE, &res);
	test_sum(buf_ptr + sl * 2, sl, sum2, TRUE, &res);
	got_result(&res, "read somewhat across partition end");

	fill_rand(buf_ptr, sl);
	simple_xfer(sub0_minor, (u64_t)sub_size, buf_ptr, sl, TRUE, 0, &res);
	got_result(&res, "write at partition end");

	simple_xfer(sub0_minor, (u64_t)sub_size + (u64_t)sl, buf_ptr, sl, TRUE, 0, &res);
	got_result(&res, "write beyond partition end");

	fill_rand(buf_ptr, buf_size);
	simple_xfer(sub1_minor, 0ULL, buf_ptr, buf_size, FALSE, buf_size, &res);
	test_sum(buf_ptr, buf_size, sub1_sum, TRUE, &res);
	got_result(&res, "read from second subpartition");

	fill_rand(buf_ptr, sl);
	simple_xfer(sub1_minor, 0xffffffffffffffffULL - (u64_t)sl + 1ULL, buf_ptr, sl, TRUE, 0, &res);
	got_result(&res, "write with negative offset");

	simple_xfer(sub0_minor, (u64_t)sub_size - (u64_t)sl, buf_ptr, sl, FALSE, sl, &res);
	test_sum(buf_ptr, sl, sum, TRUE, &res);
	got_result(&res, "read up to partition end");

	free_dma_memory(buf_ptr, buf_size);
}

static void set_and_verify_subpartition(dev_t minor,
                                        const struct part_geom *base_part,
                                        u64_t base_offset,
                                        size_t size,
                                        const char *set_msg,
                                        const char *get_msg)
{
	struct part_geom subpart = *base_part;
	struct part_geom subpart2;
	result_t res;

	subpart.base += base_offset;
	subpart.size = (u64_t)size;

	vir_ioctl(minor, DIOCSETP, &subpart, OK, &res);
	got_result(&res, set_msg);

	vir_ioctl(minor, DIOCGETP, &subpart2, OK, &res);

	if (res.type == RESULT_OK &&
	    (subpart.base != subpart2.base || subpart.size != subpart2.size)) {
		res.type = RESULT_BADVALUE;
		res.value = 0;
	}

	got_result(&res, get_msg);
}

static void vir_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
	size_t sub_size;

	test_group("virtual subpartition limits", TRUE);

	open_device(sub0_minor);
	open_device(sub1_minor);

	sub_size = sector_size * part_secs;

	set_and_verify_subpartition(sub0_minor, &part, 0, sub_size,
	    "ioctl to set first subpartition",
	    "ioctl to get first subpartition");

	set_and_verify_subpartition(sub1_minor, &part, sub_size, sub_size,
	    "ioctl to set second subpartition",
	    "ioctl to get second subpartition");

	read_limits(sub0_minor, sub1_minor, sub_size);
	write_limits(sub0_minor, sub1_minor, sub_size);

	close_device(sub1_minor);
	close_device(sub0_minor);
}

static void reopen_device(dev_t minor)
{
	close_device(minor);
	open_device(minor);
}

static void check_subpartition_zero(dev_t minor, const char *msg)
{
	struct part_geom sp;
	result_t res;

	vir_ioctl(minor, DIOCGETP, &sp, 0, &res);

	if (res.type == RESULT_OK && sp.size != 0) {
		res.type = RESULT_BADVALUE;
		res.value = ex64lo(sp.size);
	}

	got_result(&res, msg);
}

static void check_subpartition_match(dev_t minor, u64_t exp_base, u64_t exp_size, const char *msg)
{
	struct part_geom sp;
	result_t res;

	vir_ioctl(minor, DIOCGETP, &sp, 0, &res);

	if (res.type == RESULT_OK && (sp.base != exp_base || sp.size != exp_size)) {
		res.type = RESULT_BADVALUE;
		res.value = 0;
	}

	got_result(&res, msg);
}

static void real_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
	u8_t *buf_ptr;
	size_t buf_size, sub_size;

	test_group("real subpartition limits", may_write);

	if (!may_write)
		return;

	sub_size = sector_size * (size_t)part_secs;

	buf_size = sector_size;
	buf_ptr = alloc_dma_memory(buf_size);
	if (buf_ptr == NULL)
		return;

	memset(buf_ptr, 0, buf_size);

	simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
	got_result(&res, "write of invalid partition table");

	reopen_device(driver_minor);

	open_device(sub0_minor);
	open_device(sub1_minor);

	check_subpartition_zero(sub0_minor, "ioctl to get first subpartition");
	check_subpartition_zero(sub1_minor, "ioctl to get second subpartition");

	close_device(sub1_minor);
	close_device(sub0_minor);

	if (buf_size < 512) {
		free_dma_memory(buf_ptr, buf_size);
		return;
	}

	memset(buf_ptr, 0, buf_size);

	entry = (struct part_entry *)&buf_ptr[PART_TABLE_OFF];

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

	reopen_device(driver_minor);

	open_device(sub0_minor);
	open_device(sub1_minor);

	{
		u64_t exp_size = (u64_t)part_secs * sector_size;
		u64_t exp_base0 = part.base + sector_size;
		u64_t exp_base1 = part.base + ((u64_t)1 + (u64_t)part_secs) * sector_size;

		check_subpartition_match(sub0_minor, exp_base0, exp_size, "ioctl to get first subpartition");
		check_subpartition_match(sub1_minor, exp_base1, exp_size, "ioctl to get second subpartition");
	}

	read_limits(sub0_minor, sub1_minor, sub_size);
	write_limits(sub0_minor, sub1_minor, sub_size);

	close_device(sub0_minor);
	close_device(sub1_minor);

	free_dma_memory(buf_ptr, buf_size);
}

static void part_limits(void)
{
	dev_t sub0_minor, sub1_minor;
	int part_secs = 9;
	int par;
	unsigned long drive_idx, group;
	unsigned long calc;

	if (driver_minor >= MINOR_d0p0s0) {
		output("WARNING: operating on subpartition, skipping partition tests\n");
		return;
	}

	if (DEV_PER_DRIVE <= 0 || NR_PARTITIONS <= 0 || part_secs < 4) {
		return;
	}

	par = driver_minor % DEV_PER_DRIVE;
	drive_idx = (unsigned long)(driver_minor / DEV_PER_DRIVE);

	if (par > 0) {
		group = drive_idx * (unsigned long)NR_PARTITIONS;
		calc = (group + (unsigned long)(par - 1)) * (unsigned long)NR_PARTITIONS;
		sub0_minor = (dev_t)((unsigned long)MINOR_d0p0s0 + calc);
	} else {
		sub0_minor = driver_minor + 1;
	}

	sub1_minor = sub0_minor + 1;

	vir_limits(sub0_minor, sub1_minor, part_secs);
	real_limits(sub0_minor, sub1_minor, part_secs - 1);
}

static int setup_small_element_iov(u8_t *buf_ptr, size_t total_size, u8_t *sec_ptr[2], int pattern, iovec_t iovt[3], u32_t rsum[3])
{
	int nr_req = 0;

	memset(iovt, 0, sizeof(iovt[0]) * 3);
	memset(rsum, 0, sizeof(rsum[0]) * 3);

	switch (pattern) {
	case 0:
		iovt[0].iov_addr = (vir_bytes)sec_ptr[0];
		iovt[0].iov_size = element_size;

		iovt[1].iov_addr = (vir_bytes)buf_ptr;
		if (total_size < element_size) return 0;
		iovt[1].iov_size = total_size - element_size;

		rsum[1] = get_sum(buf_ptr + iovt[1].iov_size, element_size);

		nr_req = 2;
		break;

	case 1:
		iovt[0].iov_addr = (vir_bytes)buf_ptr;
		if (total_size < element_size) return 0;
		iovt[0].iov_size = total_size - element_size;

		rsum[1] = get_sum(buf_ptr + iovt[0].iov_size, element_size);

		iovt[1].iov_addr = (vir_bytes)sec_ptr[0];
		iovt[1].iov_size = element_size;

		nr_req = 2;
		break;

	case 2:
		if (!sec_ptr[1]) return 0;

		iovt[0].iov_addr = (vir_bytes)sec_ptr[0];
		iovt[0].iov_size = element_size;

		if (total_size < element_size * 2) return 0;
		iovt[1].iov_addr = (vir_bytes)buf_ptr;
		iovt[1].iov_size = total_size - element_size * 2;

		rsum[1] = get_sum(buf_ptr + iovt[1].iov_size, element_size * 2);

		fill_rand(sec_ptr[1], sector_size);
		iovt[2].iov_addr = (vir_bytes)sec_ptr[1];
		iovt[2].iov_size = element_size;

		rsum[2] = get_sum(sec_ptr[1] + element_size, sector_size - element_size);

		nr_req = 3;
		break;

	default:
		return 0;
	}

	return nr_req;
}

static void verify_and_rebuild_buffer_after_read(u8_t *buf_ptr, u8_t *sec_ptr[2], const iovec_t iovt[3], int pattern, const u32_t rsum[3], result_t *res)
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
		test_sum(sec_ptr[1] + element_size, sector_size - element_size, rsum[2], TRUE, res);
		memmove(buf_ptr + element_size, buf_ptr, iovt[1].iov_size);
		memcpy(buf_ptr, sec_ptr[0], element_size);
		memcpy(buf_ptr + element_size + iovt[1].iov_size, sec_ptr[1], element_size);
		break;

	default:
		break;
	}
}

static void prepare_buffers_for_write(u8_t *buf_ptr, u8_t *sec_ptr[2], const iovec_t iovt[3], int pattern)
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
		memcpy(sec_ptr[1], buf_ptr + element_size + iovt[1].iov_size, element_size);
		memmove(buf_ptr, buf_ptr + element_size, iovt[1].iov_size);
		fill_rand(buf_ptr + iovt[1].iov_size, element_size * 2);
		break;

	default:
		break;
	}
}

static void unaligned_size_io(u64_t base_pos, u8_t *buf_ptr, size_t buf_size, u8_t *sec_ptr[2], int sectors, int pattern, u32_t ssum[5])
{
	iovec_t iov[3];
	iovec_t iovt[3];
	u32_t rsum[3];
	result_t res;
	size_t total_size;
	int i;
	int nr_req;

	if (!buf_ptr || !sec_ptr || !sec_ptr[0]) return;
	if (sector_size == 0 || element_size == 0) return;
	if (sectors < 1 || sectors > 3) return;
	if (buf_size < sector_size * 3) return;

	base_pos += sector_size;
	total_size = (size_t)sector_size * (size_t)sectors;
	if (total_size > buf_size) return;

	if ((sector_size / element_size) == 2 && sectors == 1 && pattern == 2) return;

	memset(iov, 0, sizeof(iov));
	memset(iovt, 0, sizeof(iovt));
	memset(rsum, 0, sizeof(rsum));

	fill_rand(sec_ptr[0], sector_size);
	rsum[0] = get_sum(sec_ptr[0] + element_size, sector_size - element_size);

	fill_rand(buf_ptr, buf_size);

	nr_req = setup_small_element_iov(buf_ptr, total_size, sec_ptr, pattern, iovt, rsum);
	if (nr_req <= 0) return;

	memcpy(iov, iovt, sizeof(iov));

	vir_xfer(driver_minor, base_pos, iov, nr_req, FALSE, total_size, &res);

	test_sum(sec_ptr[0] + element_size, sector_size - element_size, rsum[0], TRUE, &res);

	verify_and_rebuild_buffer_after_read(buf_ptr, sec_ptr, iovt, pattern, rsum, &res);

	for (i = 0; i < sectors; i++) {
		test_sum(buf_ptr + sector_size * i, sector_size, ssum[1 + i], TRUE, &res);
	}

	got_result(&res, "read with small elements");

	if (!may_write) return;

	for (i = 0; i < sectors; i++) {
		ssum[1 + i] = fill_rand(buf_ptr + sector_size * i, sector_size);
	}

	prepare_buffers_for_write(buf_ptr, sec_ptr, iovt, pattern);

	memcpy(iov, iovt, sizeof(iov));
	vir_xfer(driver_minor, base_pos, iov, nr_req, TRUE, total_size, &res);

	got_result(&res, "write with small elements");

	fill_rand(buf_ptr, sector_size * 3);

	simple_xfer(driver_minor, base_pos, buf_ptr, sector_size * 3, FALSE, sector_size * 3, &res);

	for (i = 0; i < 3; i++) {
		test_sum(buf_ptr + sector_size * i, sector_size, ssum[1 + i], TRUE, &res);
	}

	got_result(&res, "readback verification");
}

static void unaligned_size(void)
{
	u8_t *buf_ptr = NULL, *sec_ptr[2] = { NULL, NULL };
	size_t buf_size;
	u32_t sum = 0L, ssum[5] = { 0 };
	u64_t base_pos;
	result_t res;
	int i;

	test_group("sector-unaligned elements", sector_size != element_size);

	if (sector_size == element_size)
		return;

	if (element_size == 0 || sector_size == 0 || (sector_size % element_size) != 0)
		return;

	buf_size = sector_size * 5;
	base_pos = (u64_t)sector_size * 2;

	buf_ptr = alloc_dma_memory(buf_size);
	if (buf_ptr == NULL)
		goto cleanup;

	sec_ptr[0] = alloc_dma_memory(sector_size);
	if (sec_ptr[0] == NULL)
		goto cleanup;

	sec_ptr[1] = alloc_dma_memory(sector_size);
	if (sec_ptr[1] == NULL)
		goto cleanup;

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

	for (i = 0; i < 9; i++)
		unaligned_size_io(base_pos, buf_ptr, buf_size, sec_ptr, i / 3 + 1, i % 3, ssum);

	if (may_write) {
		fill_rand(buf_ptr, buf_size);
		simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);

		test_sum(buf_ptr, sector_size, ssum[0], TRUE, &res);
		test_sum(buf_ptr + sector_size * 4, sector_size, ssum[4], TRUE, &res);

		got_result(&res, "check first and last sectors");
	}

cleanup:
	if (sec_ptr[1] != NULL)
		free_dma_memory(sec_ptr[1], sector_size);
	if (sec_ptr[0] != NULL)
		free_dma_memory(sec_ptr[0], sector_size);
	if (buf_ptr != NULL)
		free_dma_memory(buf_ptr, buf_size);
}

static void unaligned_pos1(void)
{
	u8_t *buf_ptr = NULL, *buf2_ptr = NULL;
	size_t buf_size, buf2_size, size;
	u32_t sum = 0, sum2 = 0;
	u64_t base_pos;
	result_t res;

	test_group("sector-unaligned positions, part one", min_read != sector_size);

	if (min_read == sector_size)
		return;

	if (min_read == 0 || element_size == 0 || sector_size == 0)
		return;

	if (min_read > sector_size)
		return;

	assert(sector_size % min_read == 0);
	assert(min_read % element_size == 0);

	if (sector_size > (SIZE_MAX / 3))
		return;

	buf_size = buf2_size = sector_size * 3;
	base_pos = (u64_t)sector_size * 3;

	buf_ptr = alloc_dma_memory(buf_size);
	if (buf_ptr == NULL)
		return;

	buf2_ptr = alloc_dma_memory(buf2_size);
	if (buf2_ptr == NULL) {
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
	simple_xfer(driver_minor, base_pos + sector_size - min_read, buf2_ptr, min_read, FALSE, min_read, &res);
	test_sum(buf2_ptr, min_read, get_sum(buf_ptr + sector_size - min_read, min_read), TRUE, &res);
	test_sum(buf2_ptr + min_read, sector_size - min_read, sum, TRUE, &res);
	got_result(&res, "single sector read with lead");

	fill_rand(buf2_ptr, sector_size);
	sum = get_sum(buf2_ptr, sector_size - min_read);
	simple_xfer(driver_minor, base_pos, buf2_ptr + sector_size - min_read, min_read, FALSE, min_read, &res);
	test_sum(buf2_ptr + sector_size - min_read, min_read, get_sum(buf_ptr, min_read), TRUE, &res);
	test_sum(buf2_ptr, sector_size - min_read, sum, TRUE, &res);
	got_result(&res, "single sector read with trail");

	fill_rand(buf2_ptr, sector_size);
	sum = get_sum(buf2_ptr, min_read);
	sum2 = get_sum(buf2_ptr + min_read * 2, sector_size - min_read * 2);
	simple_xfer(driver_minor, base_pos + min_read, buf2_ptr + min_read, min_read, FALSE, min_read, &res);
	test_sum(buf2_ptr + min_read, min_read, get_sum(buf_ptr + min_read, min_read), TRUE, &res);
	test_sum(buf2_ptr, min_read, sum, TRUE, &res);
	test_sum(buf2_ptr + min_read * 2, sector_size - min_read * 2, sum2, TRUE, &res);
	got_result(&res, "single sector read with lead and trail");

	size = min_read + sector_size * 2;

	fill_rand(buf2_ptr, buf2_size);
	sum = get_sum(buf2_ptr + size, buf2_size - size);
	simple_xfer(driver_minor, base_pos + sector_size - min_read, buf2_ptr, size, FALSE, size, &res);
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
	simple_xfer(driver_minor, base_pos + min_read, buf2_ptr, sector_size, FALSE, sector_size, &res);
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
	buf2_ptr = alloc_dma_memory(buf2_size);
	if (buf_ptr == NULL || buf2_ptr == NULL) {
		if (buf2_ptr != NULL) free_dma_memory(buf2_ptr, buf2_size);
		if (buf_ptr != NULL) free_dma_memory(buf_ptr, buf_size);
		return;
	}

	if (may_write) {
		sum = fill_rand(buf_ptr, max_size);

		simple_xfer(driver_minor, base_pos, buf_ptr, max_size, TRUE,
			max_size, &res);
		got_result(&res, "large baseline write");

		sum2 = fill_rand(buf_ptr + max_size, sector_size);

		simple_xfer(driver_minor, base_pos + (u64_t)max_size,
			buf_ptr + max_size, sector_size, TRUE, sector_size,
			&res);
		got_result(&res, "small baseline write");
	}

	fill_rand(buf_ptr, buf_size);

	simple_xfer(driver_minor, base_pos, buf_ptr, max_size, FALSE, max_size,
		&res);
	if (may_write)
		test_sum(buf_ptr, max_size, sum, TRUE, &res);
	got_result(&res, "large baseline read");

	simple_xfer(driver_minor, base_pos + (u64_t)max_size, buf_ptr + max_size,
		sector_size, FALSE, sector_size, &res);
	if (may_write)
		test_sum(buf_ptr + max_size, sector_size, sum2, TRUE, &res);
	got_result(&res, "small baseline read");

	fill_rand(buf2_ptr, buf2_size);

	{
		const size_t nr = (size_t)NR_IOREQS;
		int do_small_vec = 1;
		size_t total_min_read = 0, sum_range_end = 0;

		if (min_read > sector_size) do_small_vec = 0;
		if (nr == 0) do_small_vec = 0;
		if (do_small_vec && min_read != 0 && nr > SIZE_MAX / min_read) do_small_vec = 0;
		if (do_small_vec) total_min_read = min_read * nr;
		if (do_small_vec && total_min_read > SIZE_MAX - min_read) do_small_vec = 0;
		if (do_small_vec) sum_range_end = min_read + total_min_read;
		if (do_small_vec && nr > SIZE_MAX / sector_size) do_small_vec = 0;
		if (do_small_vec && nr > buf2_size / sector_size) do_small_vec = 0;
		if (do_small_vec && nr > buf2_size / min_read) do_small_vec = 0;
		if (do_small_vec && sum_range_end > buf_size) do_small_vec = 0;
		if (do_small_vec && (nr - 1) > (buf2_size - min_read) / sector_size) do_small_vec = 0;

		if (do_small_vec) {
			for (i = 0; i < (int)nr; i++) {
				iov[i].iov_addr = (vir_bytes) (buf2_ptr + (size_t)i * sector_size);
				iov[i].iov_size = min_read;

				rsum[i] = get_sum(buf2_ptr + (size_t)i * sector_size + min_read,
					sector_size - min_read);
			}

			vir_xfer(driver_minor, base_pos + (u64_t)min_read, iov, NR_IOREQS, FALSE,
				total_min_read, &res);

			for (i = 0; i < (int)nr; i++) {
				test_sum(buf2_ptr + (size_t)i * sector_size + min_read,
					sector_size - min_read, rsum[i], TRUE, &res);
				memmove(buf2_ptr + (size_t)i * min_read,
					buf2_ptr + (size_t)i * sector_size, min_read);
			}

			test_sum(buf2_ptr, total_min_read,
				get_sum(buf_ptr + min_read, total_min_read), TRUE, &res);

			got_result(&res, "small fully unaligned filled vector");
		}
	}

	fill_rand(buf2_ptr, buf2_size);

	if (min_read <= sector_size && min_read <= buf_size - max_size) {
		simple_xfer(driver_minor, base_pos + (u64_t)min_read, buf2_ptr, max_size,
			FALSE, max_size, &res);

		test_sum(buf2_ptr, max_size, get_sum(buf_ptr + min_read, max_size),
			TRUE, &res);

		got_result(&res, "large fully unaligned single element");
	}

	max_block = max_size / NR_IOREQS;
	max_block -= (sector_size ? (max_block % sector_size) : 0);

	if (max_block > 0) {
		const size_t nr = (size_t)NR_IOREQS;
		int do_large_vec = 1;

		if (nr == 0) do_large_vec = 0;
		if (do_large_vec && nr > SIZE_MAX / max_block) do_large_vec = 0;
		if (do_large_vec && nr * max_block > buf2_size) do_large_vec = 0;
		if (do_large_vec && min_read > sector_size) do_large_vec = 0;
		if (do_large_vec && (max_block * nr > buf_size - min_read))
			do_large_vec = 0;

		if (do_large_vec) {
			fill_rand(buf2_ptr, buf2_size);

			for (i = 0; i < (int)nr; i++) {
				iov[i].iov_addr = (vir_bytes) (buf2_ptr + (size_t)i * max_block);
				iov[i].iov_size = max_block;
			}

			vir_xfer(driver_minor, base_pos + (u64_t)min_read, iov, NR_IOREQS, FALSE,
				max_block * NR_IOREQS, &res);

			test_sum(buf2_ptr, max_block * NR_IOREQS,
				get_sum(buf_ptr + min_read, max_block * NR_IOREQS), TRUE, &res);

			got_result(&res, "large fully unaligned filled vector");
		}
	}

	free_dma_memory(buf2_ptr, buf2_size);
	free_dma_memory(buf_ptr, buf_size);
}

static void sweep_area(u64_t base_pos)
{
	const size_t area_sectors = 8;
	const size_t sub_sectors = 3;
	const size_t area_size = sector_size * area_sectors;
	const size_t sub_size = sector_size * sub_sectors;
	u8_t *buf_ptr;
	u32_t sum = 0L, ssum[8];
	result_t res;
	size_t i, j;

	buf_ptr = alloc_dma_memory(area_size);
	if (buf_ptr == NULL)
		return;

	if (may_write) {
		sum = fill_rand(buf_ptr, area_size);
		simple_xfer(driver_minor, base_pos, buf_ptr, area_size, TRUE,
			area_size, &res);
		got_result(&res, "write to full area");
	}

	fill_rand(buf_ptr, area_size);

	simple_xfer(driver_minor, base_pos, buf_ptr, area_size, FALSE, area_size,
		&res);

	if (may_write)
		test_sum(buf_ptr, area_size, sum, TRUE, &res);

	for (i = 0; i < area_sectors; i++)
		ssum[i] = get_sum(buf_ptr + sector_size * i, sector_size);

	got_result(&res, "read from full area");

	for (i = 0; i <= area_sectors - sub_sectors; i++) {
		fill_rand(buf_ptr, sub_size);

		simple_xfer(driver_minor, base_pos + (u64_t)(sector_size * i),
			buf_ptr, sub_size, FALSE, sub_size, &res);

		for (j = 0; j < sub_sectors; j++)
			test_sum(buf_ptr + sector_size * j, sector_size,
				ssum[i + j], TRUE, &res);

		got_result(&res, "read from subarea");

		if (!may_write)
			continue;

		fill_rand(buf_ptr, sub_size);

		simple_xfer(driver_minor, base_pos + (u64_t)(sector_size * i),
			buf_ptr, sub_size, TRUE, sub_size, &res);

		for (j = 0; j < sub_sectors; j++)
			ssum[i + j] = get_sum(buf_ptr + sector_size * j,
				sector_size);

		got_result(&res, "write to subarea");
	}

	if (may_write) {
		fill_rand(buf_ptr, area_size);

		simple_xfer(driver_minor, base_pos, buf_ptr, area_size, FALSE,
			area_size, &res);

		for (i = 0; i < area_sectors; i++)
			test_sum(buf_ptr + sector_size * i, sector_size,
				ssum[i], TRUE, &res);

		got_result(&res, "readback from full area");
	}

	free_dma_memory(buf_ptr, area_size);
}

static void sweep_and_check(u64_t pos, int check_integ)
{
	if (!check_integ) {
		sweep_area(pos);
		return;
	}

	{
		size_t buf_size = sector_size * 3;
		u8_t *buf_ptr = alloc_dma_memory(buf_size);
		u32_t sum = 0U;
		result_t res;

		if (buf_ptr == NULL) {
			sweep_area(pos);
			return;
		}

		if (may_write) {
			sum = fill_rand(buf_ptr, buf_size);
			simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
			got_result(&res, "write integrity zone");
		}

		fill_rand(buf_ptr, buf_size);
		simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, FALSE, buf_size, &res);

		if (may_write)
			test_sum(buf_ptr, buf_size, sum, TRUE, &res);
		else
			sum = get_sum(buf_ptr, buf_size);

		got_result(&res, "read integrity zone");

		sweep_area(pos);

		fill_rand(buf_ptr, buf_size);
		simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, FALSE, buf_size, &res);
		test_sum(buf_ptr, buf_size, sum, TRUE, &res);
		got_result(&res, "check integrity zone");

		free_dma_memory(buf_ptr, buf_size);
	}
}

static void basic_sweep(void)
{
	const u64_t size = (u64_t)sector_size;

	test_group("basic area sweep", TRUE);

	sweep_area(size);
}

static void high_disk_pos(void)
{
	const char *tg_name = "high disk positions";
	u64_t base_pos;
	u64_t part_end;
	const u64_t U64_MAX_VAL = (u64_t)~(u64_t)0;

	if (sector_size == 0) {
		test_group(tg_name, FALSE);
		return;
	}

	base_pos = 0x100000000ULL | (sector_size * 4);
	base_pos -= base_pos % sector_size;

	if (U64_MAX_VAL - part.base < part.size) {
		part_end = U64_MAX_VAL;
	} else {
		part_end = part.base + part.size;
	}

	if (part_end < base_pos) {
		test_group(tg_name, FALSE);
		return;
	}

	if (sector_size > U64_MAX_VAL / 8) {
		test_group(tg_name, FALSE);
		return;
	}

	{
		u64_t adjust = sector_size * 8;

		if (base_pos < adjust) {
			test_group(tg_name, FALSE);
			return;
		}

		base_pos -= adjust;
	}

	if (base_pos < part.base) {
		test_group(tg_name, FALSE);
		return;
	}

	test_group(tg_name, TRUE);

	base_pos -= part.base;

	sweep_and_check(base_pos, part.base == 0ULL);
}

static void high_part_pos(void)
{
	const char *label = "high partition positions";
	u64_t base_pos;

	if (part.base == 0ULL) {
		return;
	}

	base_pos = 0x100000000ULL | ((u64_t)sector_size * 4U);
	base_pos -= base_pos % (u64_t)sector_size;

	if (part.size < base_pos) {
		test_group(label, FALSE);
		return;
	}

	test_group(label, TRUE);

	base_pos -= (u64_t)sector_size * 8U;

	sweep_and_check(base_pos, TRUE);
}

static void high_lba_pos1(void)
{
	const char *name = "high LBA positions, part one";
	const u64_t boundary = ((u64_t)1U << 24) * (u64_t)sector_size;
	const u64_t eight_sectors = (u64_t)sector_size * 8U;

	if (!(part.base >= boundary || part.size >= (boundary - part.base))) {
		test_group(name, FALSE);
		return;
	}

	if (boundary < eight_sectors) {
		test_group(name, FALSE);
		return;
	}

	{
		const u64_t pos = boundary - eight_sectors;

		if (part.base > pos) {
			test_group(name, FALSE);
			return;
		}

		test_group(name, TRUE);
		sweep_and_check(pos - part.base, part.base == 0ULL);
	}
}

static void high_lba_pos2(void)
{
	const char *const group = "high LBA positions, part two";
	u64_t base_pos;
	u64_t part_end;
	u64_t offset;

	base_pos = (u64_t)(1ULL << 28);
	if (sector_size != 0 && base_pos > ((u64_t)-1) / sector_size) {
		test_group(group, FALSE);
		return;
	}
	base_pos *= sector_size;

	if (part.size > ((u64_t)-1) - part.base) {
		part_end = (u64_t)-1;
	} else {
		part_end = part.base + part.size;
	}

	if (part_end < base_pos) {
		test_group(group, FALSE);
		return;
	}

	if (sector_size > ((u64_t)-1) >> 3) {
		test_group(group, FALSE);
		return;
	}
	offset = sector_size << 3;

	if (base_pos < offset) {
		test_group(group, FALSE);
		return;
	}
	base_pos -= offset;

	if (base_pos < part.base) {
		test_group(group, FALSE);
		return;
	}

	test_group(group, TRUE);

	base_pos -= part.base;

	sweep_and_check(base_pos, part.base == 0ULL);
}

static void high_pos(void)
{
    void (*const steps[])(void) = {
        basic_sweep,
        high_disk_pos,
        high_part_pos,
        high_lba_pos1,
        high_lba_pos2
    };
    const unsigned int step_count = (unsigned int)(sizeof(steps) / sizeof(steps[0]));
    unsigned int i;
    for (i = 0; i < step_count; ++i) {
        steps[i]();
    }
}

static void open_primary(void)
{
    (void)test_group("device open", TRUE);
    (void)open_device(driver_minor);
}

static void close_primary(void)
{
	const char *const group_name = "device close";
	test_group(group_name, TRUE);
	(void)close_device(driver_minor);
	assert(nr_opened == 0);
}

static void do_tests(void)
{
	typedef void (*test_fn_t)(void);
	static const test_fn_t tests[] = {
		misc_ioctl,
		bad_read1,
		bad_read2,
		bad_write,
		vector_and_large,
		part_limits,
		unaligned_size,
		unaligned_pos1,
		unaligned_pos2,
		high_pos
	};

	open_primary();
	for (unsigned int i = 0; i < (sizeof(tests) / sizeof(tests[0])); ++i) {
		tests[i]();
	}
	close_primary();
}

static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
	enum { MAX_DRIVER_MINOR = 255 };

	if (env_argc > 1 && env_argv != NULL && env_argv[1] != NULL) {
		optset_parse(optset_table, env_argv[1]);
	}

	if (driver_label == NULL || driver_label[0] == '\0') {
		panic("no driver label given");
	}

	{
		int r = ds_retrieve_label_endpt(driver_label, &driver_endpt);
		if (r != 0) {
			panic("unable to resolve driver label");
		}
	}

	if (driver_minor > MAX_DRIVER_MINOR) {
		panic("invalid or no driver minor given");
	}

	srand48(getticks());

	output("BLOCKTEST: driver label '%s' (endpt %d), minor %d\n",
	    driver_label, driver_endpt, driver_minor);

	do_tests();

	{
		const char *suffix = (failed_groups == 1) ? "" : "s";
		output("BLOCKTEST: summary: %d out of %d tests failed across %d group%s; %d driver deaths\n",
		    failed_tests, total_tests, failed_groups, suffix, driver_deaths);
	}

	return failed_tests ? EINVAL : OK;
}

static void sef_local_startup(void)
{
	sef_setcb_init_fresh(sef_cb_init_fresh);
	sef_startup();
}

#include <stdlib.h>

void env_setargs(int argc, char **argv);
void sef_local_startup(void);

static int run_driver_task(int argc, char **argv)
{
	if (argv == NULL) {
		static char *empty_argv[] = { NULL };
		argv = empty_argv;
		argc = 0;
	}

	env_setargs(argc, argv);
	sef_local_startup();

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	return run_driver_task(argc, argv);
}
