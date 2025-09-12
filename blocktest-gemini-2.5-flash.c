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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <errno.h>

static bool contig = false;

static void panic(const char *fmt, ...)
{
    va_list args;
    fprintf(stderr, "PANIC: ");
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    if (errno != 0) {
        perror("System error");
    }
    exit(EXIT_FAILURE);
}

static void *alloc_contig(size_t size, int flags, void *data)
{
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PREALLOC | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (ptr == MAP_FAILED) {
        return NULL;
    }
    return ptr;
}

static void *alloc_dma_memory(size_t size)
{
    void *ptr;

    if (contig) {
        ptr = alloc_contig(size, 0, NULL);
        if (ptr == NULL) {
            panic("unable to allocate %zu bytes of memory", size);
        }
    } else {
        ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PREALLOC | MAP_ANON, -1, 0);
        if (ptr == MAP_FAILED) {
            panic("unable to allocate %zu bytes of memory", size);
        }
    }

    return ptr;
}

#include <sys/mman.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

static void free_dma_memory(void *ptr, size_t size)
{
    if (ptr == NULL) {
        return;
    }

    if (contig) {
        free_contig(ptr, size);
    } else {
        if (munmap(ptr, size) == -1) {
            fprintf(stderr, "ERROR: Failed to unmap DMA memory at %p with size %zu: %s\n",
                    ptr, size, strerror(errno));
        }
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
	if (res == NULL) {
		return FALSE;
	}

	if (res->type == type && res->value == value) {
		set_result(res, RESULT_OK, 0);
		return TRUE;
	}

	return FALSE;
}

static void got_result(const result_t *res, const char *desc)
{
	static int i = 0;

	total_tests++;
	if (res->type != RESULT_OK) {
		failed_tests++;

		if (!group_failure) {
			failed_groups++;
			group_failure = TRUE;
		}
	}

	output("#%02d: %-38s\t[%s]\n", ++i, desc,
		(res->type == RESULT_OK) ? "PASS" : "FAIL");

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
	}
}

static void test_group(const char *name, int exec)
{
    const char *display_name = (name != NULL) ? name : "<unknown>";
    const char *status_suffix = exec ? "" : " (skipping)";

    output("Test group: %s%s\n", display_name, status_suffix);

    group_failure = FALSE;
}

static void reopen_device(dev_t minor)
{
    message m;
    unsigned int access_flags = BDEV_R_BIT;

    memset(&m, 0, sizeof(m));
    m.m_type = BDEV_OPEN;
    m.m_lbdev_lblockdriver_msg.minor = minor;

    if (may_write) {
        access_flags |= BDEV_W_BIT;
    }
    m.m_lbdev_lblockdriver_msg.access = access_flags;
    m.m_lbdev_lblockdriver_msg.id = 0;

    (void) ipc_sendrec(driver_endpt, &m);
}

static const long DRIVER_RETRY_DELAY_US = 100000;

static int handle_driver_death_recovery(result_t *res)
{
	output("WARNING: driver has died, attempting to proceed\n");

	driver_deaths++;

	endpoint_t last_endpt = driver_endpt;
	for (;;) {
		int r = ds_retrieve_label_endpt(driver_label, &driver_endpt);

		if (r == OK && last_endpt != driver_endpt)
			break;

		micro_delay(DRIVER_RETRY_DELAY_US);
	}

	for (int i = 0; i < nr_opened; i++)
		reopen_device(opened[i]);

	return set_result(res, RESULT_DEATH, 0);
}

static int sendrec_driver(message *m_ptr, ssize_t exp, result_t *res)
{
	message m_orig = *m_ptr;
	int r = ipc_sendrec(driver_endpt, m_ptr);

	if (r == EDEADSRCDST) {
		return handle_driver_death_recovery(res);
	}

	if (r != OK)
		return set_result(res, RESULT_COMMFAIL, r);

	if (m_ptr->m_type != BDEV_REPLY)
		return set_result(res, RESULT_BADTYPE, m_ptr->m_type);

	if (m_ptr->m_lblockdriver_lbdev_reply.id != m_orig.m_lbdev_lblockdriver_msg.id)
		return set_result(res, RESULT_BADID,
				m_ptr->m_lblockdriver_lbdev_reply.id);

	int status = m_ptr->m_lblockdriver_lbdev_reply.status;
	if ((exp < 0) != (status < 0))
		return set_result(res, RESULT_BADSTATUS, status);

	return set_result(res, RESULT_OK, 0);
}

static void raw_xfer(dev_t minor, u64_t pos, iovec_s_t *iovec, int nr_req,
	int write, ssize_t exp, result_t *res)
{
	cp_grant_id_t grant;
	message m;
	int r;

	if (nr_req <= 0 || nr_req > NR_IOREQS) {
		set_result(res, RESULT_BADPARAM, 0);
		return;
	}
	if (write && !may_write) {
		set_result(res, RESULT_BADPARAM, 0);
		return;
	}

	grant = cpf_grant_direct(driver_endpt, (vir_bytes) iovec,
			sizeof(*iovec) * nr_req, CPF_READ);
	if (grant == GRANT_INVALID) {
		panic("unable to allocate grant");
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
		panic("unable to revoke grant");
	}

	if (r != RESULT_OK) {
		return;
	}

	if (m.m_lblockdriver_lbdev_reply.status == exp) {
		return;
	}

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
	int grants_allocated_count = 0; /* Tracks how many grants were successfully allocated. */

	assert(nr_req <= NR_IOREQS);

	for (i = 0; i < nr_req; i++) {
		iov_s[i].iov_size = iovec[i].iov_size;

		if ((iov_s[i].iov_grant = cpf_grant_direct(driver_endpt,
			(vir_bytes) iovec[i].iov_addr, iovec[i].iov_size,
			write ? CPF_READ : CPF_WRITE)) == GRANT_INVALID)
		{
			/* Grant allocation failed. Clean up any grants already allocated. */
			goto err_cleanup_grants;
		}
		grants_allocated_count++; /* Increment only on successful allocation. */
	}

	/* All grants allocated successfully. Perform the transfer. */
	raw_xfer(minor, pos, iov_s, nr_req, write, exp, res);

	/* After transfer, revoke all grants. */
	for (i = 0; i < nr_req; i++) {
		/* Update the iovec size, as raw_xfer might have modified it. */
		iovec[i].iov_size = iov_s[i].iov_size;

		if (cpf_revoke(iov_s[i].iov_grant) == -1) {
			/* Failed to revoke a grant after successful transfer. */
			panic("vir_xfer: unable to revoke grant after transfer");
		}
	}
	return;

err_cleanup_grants:
	/* This label is reached if cpf_grant_direct fails. */
	/* grants_allocated_count holds the number of grants successfully allocated before the failure. */
	for (i = 0; i < grants_allocated_count; i++) {
		if (cpf_revoke(iov_s[i].iov_grant) == -1) {
			/* Critical failure: unable to revoke a grant during error cleanup. */
			panic("vir_xfer: unable to revoke grant during error cleanup");
		}
	}
	/* Panic with the original allocation failure reason. */
	panic("vir_xfer: failed to allocate grant");
}

static void simple_xfer(dev_t minor, u64_t pos, u8_t *buf, size_t size,
	int write, ssize_t exp, result_t *res)
{
	iovec_t iov = {
		.iov_addr = (vir_bytes)buf,
		.iov_size = size
	};

	vir_xfer(minor, pos, &iov, 1, write, exp, res);
}

static void alloc_buf_and_grant(u8_t **ptr, cp_grant_id_t *grant,
	size_t size, int perms)
{
	*ptr = alloc_dma_memory(size);

	if (*ptr == NULL) {
		panic("alloc_buf_and_grant: unable to allocate DMA memory");
	}

	*grant = cpf_grant_direct(driver_endpt, (vir_bytes) *ptr, size, perms);

	if (*grant == GRANT_INVALID) {
		panic("alloc_buf_and_grant: unable to create grant");
	}
}

static void free_buf_and_grant(u8_t *ptr, cp_grant_id_t grant, size_t size)
{
	cpf_revoke(grant);

	if (ptr != NULL) {
		free_dma_memory(ptr, size);
	}
}

static void run_read_test(message *m_ptr, iovec_s_t *iov_ptr, result_t *res_ptr, int expected_errno, const char *description)
{
    sendrec_driver(m_ptr, expected_errno, res_ptr);

    if (expected_errno == OK && res_ptr->type == RESULT_OK) {
        if (m_ptr->m_lblockdriver_lbdev_reply.status != (ssize_t) iov_ptr->iov_size) {
            res_ptr->type = RESULT_TRUNC;
            res_ptr->value = m_ptr->m_lblockdriver_lbdev_reply.status;
        }
    }

    got_result(res_ptr, description);
}

static void bad_read1(void)
{
    const size_t BUF_SIZE = 4096;

    message base_msg_template, current_msg;
    iovec_s_t base_iov_template, current_iov;
    cp_grant_id_t iov_struct_grant_id;
    cp_grant_id_t data_buffer_grant_id;
    u8_t *data_buffer_ptr;
    result_t test_result;

    test_group("bad read requests, part one", TRUE);

    alloc_buf_and_grant(&data_buffer_ptr, &data_buffer_grant_id, BUF_SIZE, CPF_WRITE);

    if ((iov_struct_grant_id = cpf_grant_direct(driver_endpt, (vir_bytes) &current_iov,
            sizeof(current_iov), CPF_READ)) == GRANT_INVALID) {
        panic("bad_read1: unable to allocate grant for iovec structure");
    }

    memset(&base_msg_template, 0, sizeof(base_msg_template));
    base_msg_template.m_type = BDEV_GATHER;
    base_msg_template.m_lbdev_lblockdriver_msg.minor = driver_minor;
    base_msg_template.m_lbdev_lblockdriver_msg.pos = 0LL;
    base_msg_template.m_lbdev_lblockdriver_msg.count = 1;
    base_msg_template.m_lbdev_lblockdriver_msg.grant = iov_struct_grant_id;
    base_msg_template.m_lbdev_lblockdriver_msg.id = lrand48();

    memset(&base_iov_template, 0, sizeof(base_iov_template));
    base_iov_template.iov_grant = data_buffer_grant_id;
    base_iov_template.iov_size = BUF_SIZE;

    /* Test 1: Normal request. */
    current_msg = base_msg_template;
    current_iov = base_iov_template;

    run_read_test(&current_msg, &current_iov, &test_result, OK, "normal request");

    /* Test 2: Zero iovec elements. */
    current_msg = base_msg_template;
    current_iov = base_iov_template;

    current_msg.m_lbdev_lblockdriver_msg.count = 0;

    run_read_test(&current_msg, &current_iov, &test_result, EINVAL, "zero iovec elements");

    /* Test 3: Bad iovec grant. */
    current_msg = base_msg_template;

    current_msg.m_lbdev_lblockdriver_msg.grant = GRANT_INVALID;

    run_read_test(&current_msg, &current_iov, &test_result, EINVAL, "bad iovec grant");

    /* Test 4: Revoked iovec grant. */
    current_msg = base_msg_template;
    current_iov = base_iov_template;

    cp_grant_id_t revoked_iov_grant_id;
    if ((revoked_iov_grant_id = cpf_grant_direct(driver_endpt, (vir_bytes) &current_iov,
            sizeof(current_iov), CPF_READ)) == GRANT_INVALID) {
        panic("bad_read1: unable to allocate temporary grant for revocation test");
    }
    cpf_revoke(revoked_iov_grant_id);

    current_msg.m_lbdev_lblockdriver_msg.grant = revoked_iov_grant_id;

    sendrec_driver(&current_msg, EINVAL, &test_result);
    accept_result(&test_result, RESULT_BADSTATUS, EPERM);
    got_result(&test_result, "revoked iovec grant");

    /* Test 5: Normal request (final check). */
    current_msg = base_msg_template;
    current_iov = base_iov_template;

    run_read_test(&current_msg, &current_iov, &test_result, OK, "normal request (final check)");

    /* Clean up. */
    free_buf_and_grant(data_buffer_ptr, data_buffer_grant_id, BUF_SIZE);
    cpf_revoke(iov_struct_grant_id);
}

static u32_t get_sum(u8_t *ptr, size_t size)
{
	u32_t sum = 0;

	if (ptr != NULL) {
		for (; size > 0; size--, ptr++) {
			sum = sum ^ (sum << 5) ^ *ptr;
		}
	}
	return sum;
}

#include <stdlib.h>

static u32_t fill_rand(u8_t *ptr, size_t size)
{
    if (ptr == NULL && size > 0) {
        return 0;
    }

    for (size_t i = 0; i < size; i++) {
        ptr[i] = (u8_t)(rand() % 256);
    }

    return get_sum(ptr, size);
}

static void test_sum(u8_t *ptr, size_t size, u32_t sum, int should_match,
	result_t *res)
{
	if (res->type != RESULT_OK) {
		return;
	}

	u32_t calculated_sum = get_sum(ptr, size);
	int sums_match = (sum == calculated_sum);

	if (should_match) {
		/* We expect the given sum to match the calculated sum. */
		if (!sums_match) {
			/* Mismatch found: the buffer is corrupt. */
			res->type = RESULT_CORRUPT;
			res->value = 0;
		}
	} else {
		/* We expect the given sum NOT to match the calculated sum. */
		if (sums_match) {
			/* Unexpected match found: the buffer is missing. */
			res->type = RESULT_MISSING;
			res->value = 0;
		}
	}
}

typedef struct {
    u8_t *ptr;
    size_t size;
    cp_grant_id_t grant;
    u32_t sum;
} buffer_context_t;

static void initialize_all_buffers(buffer_context_t bufs[3], iovec_s_t iov_template[3]) {
    for (int i = 0; i < 3; i++) {
        bufs[i].size = BUF_SIZE;
        alloc_buf_and_grant(&bufs[i].ptr, &bufs[i].grant, bufs[i].size, CPF_WRITE);
        iov_template[i].iov_grant = bufs[i].grant;
        iov_template[i].iov_size = bufs[i].size;
    }
}

static void cleanup_all_buffers(buffer_context_t bufs[3]) {
    for (int i = 2; i >= 0; i--) {
        free_buf_and_grant(bufs[i].ptr, bufs[i].grant, bufs[i].size);
    }
}

static void fill_and_sum_buffers(buffer_context_t bufs[3]) {
    for (int i = 0; i < 3; i++) {
        bufs[i].sum = fill_rand(bufs[i].ptr, bufs[i].size);
    }
}

static void test_all_buffer_sums(buffer_context_t bufs[3], bool expect_match, result_t *res) {
    for (int i = 0; i < 3; i++) {
        test_sum(bufs[i].ptr, bufs[i].size, bufs[i].sum, expect_match, res);
    }
}

static cp_grant_id_t safe_cpf_grant_direct(endpoint_t endpoint, vir_bytes addr, size_t size, int access) {
    cp_grant_id_t grant = cpf_grant_direct(endpoint, addr, size, access);
    if (grant == GRANT_INVALID) {
        panic("unable to allocate grant");
    }
    return grant;
}

static void bad_read2(void)
{
    buffer_context_t bufs[3];
    iovec_s_t iovt[3]; /* Template iovec */
    iovec_s_t iov[3];  /* iovec for current test */
    result_t res;
    cp_grant_id_t temp_grant = GRANT_INVALID;
    u8_t c1, c2;

    test_group("bad read requests, part two", TRUE);

    /* Initialize all buffers and setup iovt */
    initialize_all_buffers(bufs, iovt);

    /* Test normal vector request. */
    memcpy(iov, iovt, sizeof(iovt));
    fill_and_sum_buffers(bufs);
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, bufs[0].size + bufs[1].size + bufs[2].size, &res);
    test_all_buffer_sums(bufs, FALSE, &res);
    got_result(&res, "normal vector request");

    /* Test zero sized iovec element. */
    memcpy(iov, iovt, sizeof(iovt));
    iov[1].iov_size = 0;
    fill_and_sum_buffers(bufs);
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    test_all_buffer_sums(bufs, TRUE, &res);
    got_result(&res, "zero size in iovec element");

    /* Test negative sized iovec element. */
    memcpy(iov, iovt, sizeof(iovt));
    iov[1].iov_size = (vir_bytes) LONG_MAX + 1;
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    test_all_buffer_sums(bufs, TRUE, &res);
    got_result(&res, "negative size in iovec element");

    /* Test iovec with negative total size. */
    memcpy(iov, iovt, sizeof(iovt));
    iov[0].iov_size = (size_t)LONG_MAX / 2 - 1;
    iov[1].iov_size = (size_t)LONG_MAX / 2 - 1;
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    test_all_buffer_sums(bufs, TRUE, &res);
    got_result(&res, "negative total size");

    /* Test iovec with wrapping total size. */
    memcpy(iov, iovt, sizeof(iovt));
    iov[0].iov_size = (size_t)LONG_MAX - 1;
    iov[1].iov_size = (size_t)LONG_MAX - 1;
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    test_all_buffer_sums(bufs, TRUE, &res);
    got_result(&res, "wrapping total size");

    /* Test word-unaligned iovec element size. */
    memcpy(iov, iovt, sizeof(iovt));
    iov[1].iov_size--;
    fill_and_sum_buffers(bufs);
    c1 = bufs[1].ptr[bufs[1].size - 1];
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, bufs[0].size + bufs[1].size + bufs[2].size - 1, &res);
    if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
        /* Do not test the first buffer, as it may contain a partial result. */
        test_sum(bufs[1].ptr, bufs[1].size, bufs[1].sum, TRUE, &res);
        test_sum(bufs[2].ptr, bufs[2].size, bufs[2].sum, TRUE, &res);
    } else {
        test_all_buffer_sums(bufs, FALSE, &res);
        if (c1 != bufs[1].ptr[bufs[1].size - 1])
            set_result(&res, RESULT_CORRUPT, 0);
    }
    got_result(&res, "word-unaligned size in iovec element");

    /* Test invalid grant in iovec element. */
    memcpy(iov, iovt, sizeof(iovt));
    iov[1].iov_grant = GRANT_INVALID;
    fill_and_sum_buffers(bufs);
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    /* Do not test the first buffer, as it may contain a partial result. */
    test_sum(bufs[1].ptr, bufs[1].size, bufs[1].sum, TRUE, &res);
    test_sum(bufs[2].ptr, bufs[2].size, bufs[2].sum, TRUE, &res);
    got_result(&res, "invalid grant in iovec element");

    /* Test revoked grant in iovec element. */
    memcpy(iov, iovt, sizeof(iovt));
    temp_grant = safe_cpf_grant_direct(driver_endpt, (vir_bytes) bufs[1].ptr, bufs[1].size, CPF_WRITE);
    cpf_revoke(temp_grant);
    iov[1].iov_grant = temp_grant;
    fill_and_sum_buffers(bufs);
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    accept_result(&res, RESULT_BADSTATUS, EPERM);
    /* Do not test the first buffer, as it may contain a partial result. */
    test_sum(bufs[1].ptr, bufs[1].size, bufs[1].sum, TRUE, &res);
    test_sum(bufs[2].ptr, bufs[2].size, bufs[2].sum, TRUE, &res);
    got_result(&res, "revoked grant in iovec element");

    /* Test read-only grant in iovec element. */
    memcpy(iov, iovt, sizeof(iovt));
    temp_grant = safe_cpf_grant_direct(driver_endpt, (vir_bytes) bufs[1].ptr, bufs[1].size, CPF_READ);
    iov[1].iov_grant = temp_grant;
    fill_and_sum_buffers(bufs);
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    accept_result(&res, RESULT_BADSTATUS, EPERM);
    /* Do not test the first buffer, as it may contain a partial result. */
    test_sum(bufs[1].ptr, bufs[1].size, bufs[1].sum, TRUE, &res);
    test_sum(bufs[2].ptr, bufs[2].size, bufs[2].sum, TRUE, &res);
    got_result(&res, "read-only grant in iovec element");
    cpf_revoke(temp_grant);

    /* Test word-unaligned buffer in iovec element. */
    memcpy(iov, iovt, sizeof(iovt));
    temp_grant = safe_cpf_grant_direct(driver_endpt, (vir_bytes) (bufs[1].ptr + 1),
            bufs[1].size - 2, CPF_WRITE);
    iov[1].iov_grant = temp_grant;
    iov[1].iov_size = bufs[1].size - 2;
    fill_and_sum_buffers(bufs);
    c1 = bufs[1].ptr[0];
    c2 = bufs[1].ptr[bufs[1].size - 1];
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, bufs[0].size + bufs[1].size - 2 + bufs[2].size, &res);
    if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
        /* Do not test the first buffer, as it may contain a partial result. */
        test_sum(bufs[1].ptr, bufs[1].size, bufs[1].sum, TRUE, &res);
        test_sum(bufs[2].ptr, bufs[2].size, bufs[2].sum, TRUE, &res);
    } else {
        test_all_buffer_sums(bufs, FALSE, &res);
        if (c1 != bufs[1].ptr[0] || c2 != bufs[1].ptr[bufs[1].size - 1])
            set_result(&res, RESULT_CORRUPT, 0);
    }
    got_result(&res, "word-unaligned buffer in iovec element");
    cpf_revoke(temp_grant);

    /* Test word-unaligned position. */
    if (min_read > 1) {
        memcpy(iov, iovt, sizeof(iovt));
        fill_and_sum_buffers(bufs);
        raw_xfer(driver_minor, 1ULL, iov, 3, FALSE, EINVAL, &res);
        test_all_buffer_sums(bufs, TRUE, &res);
        got_result(&res, "word-unaligned position");
    }

    /* Test normal vector request (final check). */
    memcpy(iov, iovt, sizeof(iovt));
    fill_and_sum_buffers(bufs);
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, bufs[0].size + bufs[1].size + bufs[2].size, &res);
    test_all_buffer_sums(bufs, FALSE, &res);
    got_result(&res, "normal vector request");

    /* Clean up. */
    cleanup_all_buffers(bufs);
}

static u8_t *buf_ptr, *buf2_ptr, *buf3_ptr;
static size_t buf_size, buf2_size, buf3_size;
static cp_grant_id_t buf_grant, buf2_grant, buf3_grant;
static cp_grant_id_t grant;
static u32_t buf_sum, buf2_sum, buf3_sum;
static iovec_s_t iov[3], iovt[3];
static result_t res;

typedef struct {
    u8_t *ptr;
    cp_grant_id_t grant;
    size_t size;
    u32_t initial_sum;
} BufferContext;

static void execute_bad_write_test(
    u64_t offset,
    const iovec_s_t *iov_to_use,
    int iov_count,
    int expected_errno,
    int alternative_errno,
    const char *description,
    BufferContext *buffers_ctx
) {
    result_t test_res;
    int i;

    for (i = 0; i < 3; i++) {
        buffers_ctx[i].initial_sum = fill_rand(buffers_ctx[i].ptr, buffers_ctx[i].size);
    }

    raw_xfer(driver_minor, offset, iov_to_use, iov_count, TRUE, expected_errno, &test_res);

    if (alternative_errno != 0) {
        accept_result(&test_res, RESULT_BADSTATUS, alternative_errno);
    }

    for (i = 0; i < 3; i++) {
        test_sum(buffers_ctx[i].ptr, buffers_ctx[i].size, buffers_ctx[i].initial_sum, TRUE, &test_res);
    }

    got_result(&test_res, description);
}

static void bad_write(void)
{
	BufferContext buffers[3];
	iovec_s_t iov_base_template[3];
	iovec_s_t iov_current[3];
	cp_grant_id_t write_only_grant = GRANT_INVALID;

	test_group("bad write requests", may_write);

	if (!may_write) {
		return;
	}

	buffers[0].size = BUF_SIZE;
	buffers[1].size = BUF_SIZE;
	buffers[2].size = BUF_SIZE;

	alloc_buf_and_grant(&buffers[0].ptr, &buffers[0].grant, buffers[0].size, CPF_READ);
	alloc_buf_and_grant(&buffers[1].ptr, &buffers[1].grant, buffers[1].size, CPF_READ);
	alloc_buf_and_grant(&buffers[2].ptr, &buffers[2].grant, buffers[2].size, CPF_READ);

	iov_base_template[0].iov_grant = buffers[0].grant;
	iov_base_template[0].iov_size = buffers[0].size;
	iov_base_template[1].iov_grant = buffers[1].grant;
	iov_base_template[1].iov_size = buffers[1].size;
	iov_base_template[2].iov_grant = buffers[2].grant;
	iov_base_template[2].iov_size = buffers[2].size;

	if (min_write == 0) {
		min_write = sector_size;
	}

	if (min_write > 1) {
		size_t sector_unalign = (min_write > 2) ? 2 : 1;

		memcpy(iov_current, iov_base_template, sizeof(iov_base_template));
		execute_bad_write_test(
			(u64_t)sector_unalign,
			iov_current, 3, EINVAL, 0,
			"sector-unaligned write position",
			buffers
		);

		memcpy(iov_current, iov_base_template, sizeof(iov_base_template));
		iov_current[1].iov_size -= sector_unalign;
		execute_bad_write_test(
			0ULL,
			iov_current, 3, EINVAL, 0,
			"sector-unaligned write size",
			buffers
		);
	}

	memcpy(iov_current, iov_base_template, sizeof(iov_base_template));

	write_only_grant = cpf_grant_direct(driver_endpt, (vir_bytes)buffers[1].ptr,
										buffers[1].size, CPF_WRITE);
	if (write_only_grant == GRANT_INVALID) {
		panic("unable to allocate write-only grant for test");
	}

	iov_current[1].iov_grant = write_only_grant;

	execute_bad_write_test(
		0ULL,
		iov_current, 3, EINVAL, EPERM,
		"write-only grant in iovec element",
		buffers
	);

	cpf_revoke(write_only_grant);

	free_buf_and_grant(buffers[2].ptr, buffers[2].grant, buffers[2].size);
	free_buf_and_grant(buffers[1].ptr, buffers[1].grant, buffers[1].size);
	free_buf_and_grant(buffers[0].ptr, buffers[0].grant, buffers[0].size);
}

static void vector_and_large_sub(size_t small_size)
{
    result_t res;
    set_result(&res, RESULT_OK, 0);

    size_t large_size = small_size * NR_IOREQS;

    size_t buf_size = large_size + sizeof(u32_t) * 2;
    size_t buf2_size = (sizeof(u32_t) + small_size) * NR_IOREQS + sizeof(u32_t);

    u8_t *buf_ptr = NULL;
    u8_t *buf2_ptr = NULL;
    iovec_t iovec[NR_IOREQS];
    u64_t base_pos = (u64_t)sector_size;

    u32_t *large_buf_guard_start = NULL;
    u8_t *large_buf_data_start = NULL;
    u32_t *large_buf_guard_end = NULL;

    buf_ptr = alloc_dma_memory(buf_size);
    if (!buf_ptr) {
        set_result(&res, RESULT_MEMORY_ERROR, 0);
        goto cleanup;
    }

    buf2_ptr = alloc_dma_memory(buf2_size);
    if (!buf2_ptr) {
        set_result(&res, RESULT_MEMORY_ERROR, 0);
        goto cleanup;
    }

    large_buf_guard_start = (u32_t *)buf_ptr;
    large_buf_data_start = buf_ptr + sizeof(u32_t);
    large_buf_guard_end = (u32_t *)(buf_ptr + sizeof(u32_t) + large_size);

    if (may_write) {
        fill_rand(buf_ptr, buf_size);

        iovec[0].iov_addr = (vir_bytes)large_buf_data_start;
        iovec[0].iov_size = large_size;

        vir_xfer(driver_minor, base_pos, iovec, 1, TRUE, large_size, &res);
        got_result(&res, "large write");
        if (res.type != RESULT_OK) goto cleanup;
    }

    for (int i = 0; i < NR_IOREQS; i++) {
        u32_t *small_buf_guard_ptr = (u32_t *)(buf2_ptr + (size_t)i * (sizeof(u32_t) + small_size));
        *small_buf_guard_ptr = 0xDEADBEEFUL + i;
        iovec[i].iov_addr = (vir_bytes)(buf2_ptr + (size_t)i * (sizeof(u32_t) + small_size) + sizeof(u32_t));
        iovec[i].iov_size = small_size;
    }
    u32_t *final_small_buf_guard_ptr = (u32_t *)(buf2_ptr + (size_t)NR_IOREQS * (sizeof(u32_t) + small_size));
    *final_small_buf_guard_ptr = 0xFEEDFACEUL;

    vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, FALSE, large_size, &res);
    got_result(&res, "vectored read");
    if (res.type != RESULT_OK) goto cleanup;

    for (int i = 0; i < NR_IOREQS; i++) {
        u32_t *small_buf_guard_ptr = (u32_t *)(buf2_ptr + (size_t)i * (sizeof(u32_t) + small_size));
        if (*small_buf_guard_ptr != 0xDEADBEEFUL + i) {
            set_result(&res, RESULT_OVERFLOW, 0);
            goto cleanup;
        }
    }
    if (*final_small_buf_guard_ptr != 0xFEEDFACEUL) {
        set_result(&res, RESULT_OVERFLOW, 0);
        goto cleanup;
    }

    if (may_write) {
        for (int i = 0; i < NR_IOREQS; i++) {
            u8_t *small_buf_data_ptr = buf2_ptr + (size_t)i * (sizeof(u32_t) + small_size) + sizeof(u32_t);
            u8_t *large_buf_chunk_ptr = buf_ptr + sizeof(u32_t) + (size_t)i * small_size;
            test_sum(small_buf_data_ptr, small_size,
                get_sum(large_buf_chunk_ptr, small_size), TRUE, &res);
            if (res.type != RESULT_OK) goto cleanup;
        }
    }

    if (may_write) {
        fill_rand(buf2_ptr, buf2_size);

        for (int i = 0; i < NR_IOREQS; i++) {
            iovec[i].iov_addr = (vir_bytes)(buf2_ptr + (size_t)i * (sizeof(u32_t) + small_size) + sizeof(u32_t));
            iovec[i].iov_size = small_size;
        }

        vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, TRUE, large_size, &res);
        got_result(&res, "vectored write");
        if (res.type != RESULT_OK) goto cleanup;
    }

    *large_buf_guard_start = 0xCAFEBABELUL;
    *large_buf_guard_end = 0xDECAFBADUL;

    iovec[0].iov_addr = (vir_bytes)large_buf_data_start;
    iovec[0].iov_size = large_size;

    vir_xfer(driver_minor, base_pos, iovec, 1, FALSE, large_size, &res);
    got_result(&res, "large read");
    if (res.type != RESULT_OK) goto cleanup;

    if (*large_buf_guard_start != 0xCAFEBABELUL) {
        set_result(&res, RESULT_OVERFLOW, 0);
        goto cleanup;
    }
    if (*large_buf_guard_end != 0xDECAFBADUL) {
        set_result(&res, RESULT_OVERFLOW, 0);
        goto cleanup;
    }

    for (int i = 0; i < NR_IOREQS; i++) {
        u8_t *small_buf_data_ptr = buf2_ptr + (size_t)i * (sizeof(u32_t) + small_size) + sizeof(u32_t);
        u8_t *large_buf_chunk_ptr = buf_ptr + sizeof(u32_t) + (size_t)i * small_size;
        test_sum(large_buf_chunk_ptr, small_size,
            get_sum(small_buf_data_ptr, small_size), TRUE, &res);
        if (res.type != RESULT_OK) goto cleanup;
    }

cleanup:
    if (buf2_ptr) {
        free_dma_memory(buf2_ptr, buf2_size);
    }
    if (buf_ptr) {
        free_dma_memory(buf_ptr, buf_size);
    }
}

static void vector_and_large(void)
{
    static const size_t MARGIN_SECTORS = 4;
    static const size_t COMMON_BLOCK_SIZE = 4096;

    size_t max_block;

    if (sector_size == 0) {
        return;
    }

    if (NR_IOREQS == 0) {
        return;
    }

    const size_t margin_bytes = sector_size * MARGIN_SECTORS;
    size_t effective_device_size;

    if (part.size <= margin_bytes) {
        effective_device_size = 0;
    } else {
        effective_device_size = part.size - margin_bytes;
    }

    if (max_size > effective_device_size) {
        max_size = effective_device_size;
    }

    max_block = max_size / NR_IOREQS;
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
	int access_flags;

	/* Maintainability: Check local tracking array capacity before proceeding.
	 * This prevents buffer overflows (security, reliability) and
	 * avoids attempting to open a device that cannot be tracked locally,
	 * thus ensuring consistency between driver and application state.
	 * The original `assert` would crash in debug; this handles the condition
	 * gracefully without altering the void return type.
	 */
	if (nr_opened >= NR_OPENED) {
		/* Local tracking array is full. The device cannot be opened
		 * effectively from the application's perspective, as it cannot be tracked.
		 * Since the function is void, we cannot return an error code.
		 * Returning here implies a silent failure, which prevents a crash/overflow
		 * and avoids inconsistent state where a device is opened but untracked.
		 */
		return;
	}

	/* Determine access flags for the device. */
	access_flags = may_write ? (BDEV_R_BIT | BDEV_W_BIT) : BDEV_R_BIT;

	/* Prepare the message structure for the BDEV_OPEN request. */
	memset(&m, 0, sizeof(m)); /* Ensure the message structure is zero-initialized. */
	m.m_type = BDEV_OPEN;
	m.m_lbdev_lblockdriver_msg.minor = minor;
	m.m_lbdev_lblockdriver_msg.access = access_flags;
	/* Assign a random ID for the operation. Assumed to be sufficient for its purpose. */
	m.m_lbdev_lblockdriver_msg.id = lrand48();

	/* Send the request to the block device driver and receive the result. */
	sendrec_driver(&m, OK, &res);

	/* Reliability: Check the result of the driver operation BEFORE updating local state.
	 * The device should only be considered 'opened' and added to tracking if
	 * the driver operation successfully completed.
	 * `got_result` is assumed to return true (non-zero) on success, false (zero) on failure.
	 */
	if (got_result(&res, minor == driver_minor ? "opening the main partition" :
							"opening a subpartition")) {
		/* Driver operation succeeded. Track the device locally.
		 * The `nr_opened < NR_OPENED` check was already performed at the start,
		 * guaranteeing space in the `opened` array.
		 */
		opened[nr_opened++] = minor;
	}
	/* If `got_result` returns false, the driver operation failed, and
	 * the device is not added to the `opened` list, maintaining state consistency.
	 */
}

static void close_device(dev_t minor)
{
	message m;
	result_t res;

	// Initialize message structure and populate fields
	memset(&m, 0, sizeof(m));
	m.m_type = BDEV_CLOSE;
	m.m_lbdev_lblockdriver_msg.minor = minor;
	m.m_lbdev_lblockdriver_msg.id = lrand48(); // Use lrand48 for ID generation, maintaining original behavior

	// Send the close message to the block driver.
	// Assuming sendrec_driver correctly populates 'res' with the outcome,
	// even in cases of underlying communication failures, and 'got_result'
	// is designed to process all possible statuses within 'res'.
	// No explicit return status check for sendrec_driver itself, aligning with original behavior.
	sendrec_driver(&m, OK, &res);

	// Remove assert(nr_opened > 0);. Asserts are for debugging and can cause program termination.
	// Robust code handles conditions gracefully. The loop below naturally handles
	// the case where nr_opened is 0 by not iterating, making the assert redundant and potentially harmful.

	// Remove the 'minor' from the list of opened devices.
	// This loop correctly handles cases where the device is not found in the list,
	// or if 'nr_opened' is 0 (the loop will not execute).
	for (int i = 0; i < nr_opened; i++) { // Declare 'i' within the loop scope for improved maintainability
		if (opened[i] == minor) {
			// Device found. Replace it with the last element and decrement the count.
			// This is an efficient and common idiom for removing an element from an unordered list.
			opened[i] = opened[--nr_opened];
			break; // Exit loop once the device is found and removed
		}
	}

	// Process the result obtained from the block driver, providing context for logging/reporting.
	got_result(&res, minor == driver_minor ? "closing the main partition" :
		"closing a subpartition");
}

static int vir_ioctl(dev_t minor, unsigned long req, void *ptr, ssize_t exp,
	result_t *res)
{
	cp_grant_id_t grant;
	message m;
	int r;
	int perm = 0;

	if (_MINIX_IOCTL_BIG(req)) {
		return EINVAL;
	}

	if (_MINIX_IOCTL_IOR(req)) perm |= CPF_WRITE;
	if (_MINIX_IOCTL_IOW(req)) perm |= CPF_READ;

	grant = cpf_grant_direct(driver_endpt, (vir_bytes) ptr,
			_MINIX_IOCTL_SIZE(req), perm);
	if (grant == GRANT_INVALID)
		panic("unable to allocate grant");

	memset(&m, 0, sizeof(m));
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

static void check_driver_open_count(int expected_count, const char *description)
{
	result_t res;
	int current_open_count = 0;

	vir_ioctl(driver_minor, DIOCOPENCT, &current_open_count, OK, &res);

	if (res.type == RESULT_OK && current_open_count != expected_count) {
		res.type = RESULT_BADVALUE;
		res.value = current_open_count;
	}
	got_result(&res, description);
}

static void misc_ioctl(void)
{
	result_t res;
	part_t part;
	u64_t required_partition_size_threshold = (u64_t)max_size * 2;

	test_group("test miscellaneous ioctls", TRUE);

	vir_ioctl(driver_minor, DIOCGETP, &part, OK, &res);
	got_result(&res, "ioctl to get partition");

	if (res.type == RESULT_OK && part.size < required_partition_size_threshold) {
		output("WARNING: small partition, some tests may fail\n");
	}

	check_driver_open_count(1, "ioctl to get initial open count");

	open_device(driver_minor);
	check_driver_open_count(2, "increased open count after opening device");

	close_device(driver_minor);
	check_driver_open_count(1, "decreased open count after closing device");
}

static void read_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size)
{
    u8_t *buf_ptr = NULL;
    size_t buf_size = 0;
    u32_t sum, sum2, sum3;
    result_t res;

    const size_t ONE_SECTOR_SIZE = sector_size;
    const size_t TWO_SECTORS_SIZE = sector_size * 2;
    const size_t THREE_SECTORS_SIZE = sector_size * 3;

    const u64_t OFFSET_WAY_BEYOND = 0x1000000000000000ULL;
    const u64_t OFFSET_NEGATIVE = 0xffffffffffffffffULL - ONE_SECTOR_SIZE + 1;

    test_group("read around subpartition limits", TRUE);

    buf_size = THREE_SECTORS_SIZE;
    buf_ptr = alloc_dma_memory(buf_size);

    if (buf_ptr == NULL) {
        return;
    }

    /* Test case 1: Read one sector up to the partition limit. */
    fill_rand(buf_ptr, buf_size);
    sum = get_sum(buf_ptr, ONE_SECTOR_SIZE);

    simple_xfer(sub0_minor, (u64_t)sub_size - ONE_SECTOR_SIZE, buf_ptr,
        ONE_SECTOR_SIZE, FALSE, ONE_SECTOR_SIZE, &res);

    test_sum(buf_ptr, ONE_SECTOR_SIZE, sum, TRUE, &res);
    got_result(&res, "one sector read up to partition end");

    /* Test case 2: Read three sectors up to the partition limit. */
    fill_rand(buf_ptr, buf_size);

    simple_xfer(sub0_minor, (u64_t)sub_size - THREE_SECTORS_SIZE, buf_ptr, buf_size,
        FALSE, THREE_SECTORS_SIZE, &res);

    /* Note: 'sum' here refers to the value assigned in Test case 1. */
    test_sum(buf_ptr + TWO_SECTORS_SIZE, ONE_SECTOR_SIZE, sum, TRUE, &res);

    sum2 = get_sum(buf_ptr + ONE_SECTOR_SIZE, TWO_SECTORS_SIZE);
    got_result(&res, "multisector read up to partition end");

    /* Test case 3: Read three sectors, two up to and one beyond the partition end. */
    fill_rand(buf_ptr, buf_size);
    sum3 = get_sum(buf_ptr + TWO_SECTORS_SIZE, ONE_SECTOR_SIZE);

    simple_xfer(sub0_minor, (u64_t)sub_size - TWO_SECTORS_SIZE, buf_ptr,
        buf_size, FALSE, TWO_SECTORS_SIZE, &res);

    /* Note: 'sum2' here refers to the value assigned in Test case 2. */
    test_sum(buf_ptr, TWO_SECTORS_SIZE, sum2, TRUE, &res);
    test_sum(buf_ptr + TWO_SECTORS_SIZE, ONE_SECTOR_SIZE, sum3, TRUE, &res);
    got_result(&res, "read somewhat across partition end");

    /* Test case 4: Read three sectors, one up to and two beyond the partition end. */
    fill_rand(buf_ptr, buf_size);
    sum2 = get_sum(buf_ptr + ONE_SECTOR_SIZE, TWO_SECTORS_SIZE);

    simple_xfer(sub0_minor, (u64_t)sub_size - ONE_SECTOR_SIZE, buf_ptr,
        buf_size, FALSE, ONE_SECTOR_SIZE, &res);

    /* Note: 'sum' here refers to the value assigned in Test case 1. */
    test_sum(buf_ptr, ONE_SECTOR_SIZE, sum, TRUE, &res);
    test_sum(buf_ptr + ONE_SECTOR_SIZE, TWO_SECTORS_SIZE, sum2, TRUE, &res);
    got_result(&res, "read mostly across partition end");

    /* Test case 5: Read one sector starting at the partition end. */
    sum = fill_rand(buf_ptr, buf_size);
    sum2 = get_sum(buf_ptr, ONE_SECTOR_SIZE);

    simple_xfer(sub0_minor, (u64_t)sub_size, buf_ptr, ONE_SECTOR_SIZE, FALSE,
        0, &res);

    test_sum(buf_ptr, ONE_SECTOR_SIZE, sum2, TRUE, &res);
    got_result(&res, "one sector read at partition end");

    /* Test case 6: Read three sectors starting at the partition end. */
    simple_xfer(sub0_minor, (u64_t)sub_size, buf_ptr, buf_size, FALSE, 0,
        &res);

    /* Note: 'sum' here refers to the value assigned in Test case 5. */
    test_sum(buf_ptr, buf_size, sum, TRUE, &res);
    got_result(&res, "multisector read at partition end");

    /* Test case 7: Read one sector beyond the partition end. */
    simple_xfer(sub0_minor, (u64_t)sub_size + ONE_SECTOR_SIZE, buf_ptr,
        buf_size, FALSE, 0, &res);

    /* Note: 'sum2' here refers to the value assigned in Test case 5. */
    test_sum(buf_ptr, ONE_SECTOR_SIZE, sum2, TRUE, &res);
    got_result(&res, "single sector read beyond partition end");

    /* Test case 8: Read three sectors way beyond the partition end. */
    simple_xfer(sub0_minor, OFFSET_WAY_BEYOND, buf_ptr, buf_size,
        FALSE, 0, &res);

    /* Note: 'sum' here refers to the value assigned in Test case 5. */
    test_sum(buf_ptr, buf_size, sum, TRUE, &res);

    /* Test case 9: Read with negative offset. */
    simple_xfer(sub1_minor, OFFSET_NEGATIVE,
        buf_ptr, ONE_SECTOR_SIZE, FALSE, 0, &res);

    /* Note: 'sum2' here refers to the value assigned in Test case 5. */
    test_sum(buf_ptr, ONE_SECTOR_SIZE, sum2, TRUE, &res);
    got_result(&res, "read with negative offset");

    /* Clean up. */
    free_dma_memory(buf_ptr, buf_size);
}

static void write_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size)
{
    u8_t *buffer = NULL;
    size_t buffer_size;
    result_t test_result = {0};

    /* Sums for various test steps, renamed for clarity. */
    u32_t current_op_sum;
    u32_t initial_sub1_sum;
    u32_t write_pattern_1_sector_1_sum; /* Sum for the 1st sector of buffer in first cross-limit write. */
    u32_t write_pattern_1_sector_2_sum; /* Sum for the 2nd sector of buffer in first cross-limit write. */
    u32_t read_pattern_1_buffer_tail_sum; /* Sum for the untouched part of buffer after first cross-limit read. */
    u32_t write_pattern_2_sector_1_sum; /* Sum for the 1st sector of buffer in second cross-limit write. */
    u32_t read_pattern_2_buffer_tail_sum; /* Sum for the untouched part of buffer after second cross-limit read. */
    u32_t last_sector_sub0_original_sum; /* Sum of the last sector of sub0 after initial write-up-to-limit. */

    test_group("write around subpartition limits", may_write);

    if (!may_write)
        return;

    buffer_size = sector_size * 3;
    buffer = alloc_dma_memory(buffer_size);
    if (buffer == NULL) {
        /* Failed to allocate DMA memory. This is a critical error for the test. */
        /* Depending on the test framework, an error message or test failure might be appropriate here. */
        return;
    }

    /* Write to the start of the second subpartition, so that we can
     * reliably check whether its contents have changed later.
     */
    initial_sub1_sum = fill_rand(buffer, buffer_size);
    simple_xfer(sub1_minor, 0ULL, buffer, buffer_size, TRUE, buffer_size, &test_result);
    got_result(&test_result, "write to second subpartition (initial data)");

    /* Write one sector, up to the first subpartition limit. */
    current_op_sum = fill_rand(buffer, sector_size); /* Sum of the data just written. */
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buffer, sector_size, TRUE, sector_size, &test_result);
    got_result(&test_result, "write up to first subpartition end (1 sector)");

    /* Store this sum as it represents the content of the last sector of sub0. */
    last_sector_sub0_original_sum = current_op_sum;

    /* Read back to make sure the results have persisted. */
    fill_rand(buffer, sector_size * 2); /* Overwrite buffer to ensure fresh read. */
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size * 2, buffer,
        sector_size * 2, FALSE, sector_size * 2, &test_result);
    /* Verify the sector that was just written (it's now at buffer + sector_size). */
    test_sum(buffer + sector_size, sector_size, last_sector_sub0_original_sum, TRUE, &test_result);
    got_result(&test_result, "read back up to first subpartition end (confirm)");

    /* Write three sectors (buffer_size), two up to and one beyond the partition end.
     * Expected successful write length is `sector_size * 2`.
     */
    fill_rand(buffer, buffer_size);
    write_pattern_1_sector_2_sum = get_sum(buffer + sector_size, sector_size);
    write_pattern_1_sector_1_sum = get_sum(buffer, sector_size);

    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size * 2, buffer,
        buffer_size, TRUE, sector_size * 2, &test_result);
    got_result(&test_result, "write somewhat across partition end (2 sectors OK)");

    /* Read three sectors (buffer_size), one up to and two beyond the partition end.
     * Expected successful read length is `sector_size`.
     */
    fill_rand(buffer, buffer_size); /* Overwrite buffer with new random data. */
    /* Calculate sum for the part of buffer that will NOT be overwritten by the read operation. */
    read_pattern_1_buffer_tail_sum = get_sum(buffer + sector_size, sector_size * 2);

    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buffer,
        buffer_size, FALSE, sector_size, &test_result);
    /* Verify the first sector of the buffer (which holds data from `sub_size - sector_size`).
     * This should match `write_pattern_1_sector_2_sum` from the previous write. */
    test_sum(buffer, sector_size, write_pattern_1_sector_2_sum, TRUE, &test_result);
    /* Verify the remainder of the buffer, which should be unchanged from fill_rand. */
    test_sum(buffer + sector_size, sector_size * 2, read_pattern_1_buffer_tail_sum, TRUE, &test_result);
    got_result(&test_result, "read mostly across partition end");

    /* Repeat this but with write and read start positions effectively swapped. */
    /* Write three sectors (buffer_size), one up to and two beyond the partition end.
     * Expected successful write length is `sector_size`.
     */
    fill_rand(buffer, buffer_size);
    write_pattern_2_sector_1_sum = get_sum(buffer, sector_size);

    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buffer,
        buffer_size, TRUE, sector_size, &test_result);
    got_result(&test_result, "write mostly across partition end (1 sector OK)");

    /* Read three sectors (buffer_size), two up to and one beyond the partition end.
     * Expected successful read length is `sector_size * 2`.
     */
    fill_rand(buffer, buffer_size); /* Overwrite buffer with new random data. */
    /* Calculate sum for the part of buffer that will NOT be overwritten by the read operation. */
    read_pattern_2_buffer_tail_sum = get_sum(buffer + sector_size * 2, sector_size);

    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size * 2, buffer,
        buffer_size, FALSE, sector_size * 2, &test_result);
    /* Verify the data in the buffer:
     * buffer[0] (data from `sub_size - sector_size * 2`) should match `write_pattern_1_sector_1_sum`.
     * buffer[1] (data from `sub_size - sector_size`) should match `write_pattern_2_sector_1_sum`.
     * buffer[2] (data not read, so from `fill_rand`) should match `read_pattern_2_buffer_tail_sum`.
     */
    test_sum(buffer, sector_size, write_pattern_1_sector_1_sum, TRUE, &test_result);
    test_sum(buffer + sector_size, sector_size, write_pattern_2_sector_1_sum, TRUE, &test_result);
    test_sum(buffer + sector_size * 2, sector_size, read_pattern_2_buffer_tail_sum, TRUE, &test_result);
    got_result(&test_result, "read somewhat across partition end");

    /* Write one sector at the partition end (expected to fail with 0 bytes transferred). */
    fill_rand(buffer, sector_size);
    simple_xfer(sub0_minor, (u64_t)sub_size, buffer, sector_size, TRUE, 0, &test_result);
    got_result(&test_result, "write at partition end (expected 0 bytes written)");

    /* Write one sector beyond the end of the partition (expected to fail with 0 bytes transferred). */
    simple_xfer(sub0_minor, (u64_t)sub_size + sector_size, buffer, sector_size, TRUE, 0, &test_result);
    got_result(&test_result, "write beyond partition end (expected 0 bytes written)");

    /* Read from the start of the second subpartition, and verify if it
     * matches what we wrote into it earlier (`initial_sub1_sum`).
     */
    fill_rand(buffer, buffer_size); /* Wipe buffer before reading. */
    simple_xfer(sub1_minor, 0ULL, buffer, buffer_size, FALSE, buffer_size, &test_result);
    test_sum(buffer, buffer_size, initial_sub1_sum, TRUE, &test_result);
    got_result(&test_result, "read from second subpartition (verify unchanged)");

    /* Test offset wrapping, but this time for writes. */
    fill_rand(buffer, sector_size);
    simple_xfer(sub1_minor, 0xffffffffffffffffULL - sector_size + 1, buffer, sector_size, TRUE, 0, &test_result);
    got_result(&test_result, "write with negative offset (expected 0 bytes written)");

    /* If the last request erroneously succeeded, it would have overwritten
     * the last sector of the first subpartition. Verify its integrity.
     */
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buffer, sector_size, FALSE, sector_size, &test_result);
    /* This sector should still contain the `last_sector_sub0_original_sum` from earlier. */
    test_sum(buffer, sector_size, last_sector_sub0_original_sum, TRUE, &test_result);
    got_result(&test_result, "read last sector of first subpartition (verify integrity)");

    /* Clean up. */
    free_dma_memory(buffer, buffer_size);
}

static result_t perform_subpartition_ops_and_verify(dev_t minor, struct part_geom *target_geom,
                                                    const char *set_description, const char *get_description)
{
    result_t res;
    struct part_geom retrieved_geom;

    vir_ioctl(minor, DIOCSETP, target_geom, OK, &res);
    got_result(&res, set_description);
    if (res.type != RESULT_OK) {
        return res;
    }

    vir_ioctl(minor, DIOCGETP, &retrieved_geom, OK, &res);

    if (res.type == RESULT_OK) {
        if (target_geom->base != retrieved_geom.base || target_geom->size != retrieved_geom.size) {
            res.type = RESULT_BADVALUE;
            res.value = 0;
        }
    }
    got_result(&res, get_description);

    return res;
}


static void vir_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
    struct part_geom subpart;
    u64_t sub_size;
    result_t res;

    test_group("virtual subpartition limits", TRUE);

    open_device(sub0_minor);
    open_device(sub1_minor);

    sub_size = (u64_t)sector_size * part_secs;

    subpart = part;
    subpart.size = sub_size;

    res = perform_subpartition_ops_and_verify(sub0_minor, &subpart,
                                              "ioctl to set first subpartition",
                                              "ioctl to get first subpartition");
    if (res.type != RESULT_OK) {
        goto cleanup;
    }

    subpart = part;
    subpart.base += sub_size;
    subpart.size = sub_size;

    res = perform_subpartition_ops_and_verify(sub1_minor, &subpart,
                                              "ioctl to set second subpartition",
                                              "ioctl to get second subpartition");
    if (res.type != RESULT_OK) {
        goto cleanup;
    }

    read_limits(sub0_minor, sub1_minor, sub_size);
    write_limits(sub0_minor, sub1_minor, sub_size);

cleanup:
    close_device(sub1_minor);
    close_device(sub0_minor);
}

#define MBR_SIGNATURE_OFFSET_0 510
#define MBR_SIGNATURE_OFFSET_1 511
#define MBR_SIGNATURE_BYTE_0 0x55
#define MBR_SIGNATURE_BYTE_1 0xAA

static void write_partition_table_and_reset_driver(dev_t driver_minor, u8_t *buf_ptr, size_t buf_size, const char *action_description)
{
    result_t res;
    simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
    got_result(&res, action_description);

    close_device(driver_minor);
    open_device(driver_minor);
}

static void check_subpartition_properties(
    dev_t sub_minor,
    u64_t expected_base,
    u64_t expected_size,
    bool check_for_zero_size,
    const char *description_suffix
) {
    result_t res;
    struct part_geom subpart;

    vir_ioctl(sub_minor, DIOCGETP, &subpart, 0, &res);

    if (res.type == RESULT_OK) {
        if (check_for_zero_size) {
            if (subpart.size != 0) {
                res.type = RESULT_BADVALUE;
                res.value = ex64lo(subpart.size);
            }
        } else {
            if (subpart.base != expected_base || subpart.size != expected_size) {
                res.type = RESULT_BADVALUE;
                res.value = 0;
            }
        }
    }
    got_result(&res, description_suffix);
}

static void real_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
    u8_t *buf_ptr = NULL;
    size_t buf_size;
    size_t sub_size;
    struct part_entry *entry;

    test_group("real subpartition limits", may_write);

    if (!may_write) {
        return;
    }

    sub_size = (size_t)sector_size * part_secs;

    buf_size = sector_size;
    buf_ptr = alloc_dma_memory(buf_size);
    if (buf_ptr == NULL) {
        goto cleanup_dma;
    }

    memset(buf_ptr, 0, buf_size);

    write_partition_table_and_reset_driver(driver_minor, buf_ptr, buf_size, "write of invalid partition table");

    open_device(sub0_minor);
    open_device(sub1_minor);

    check_subpartition_properties(sub0_minor, 0, 0, true, "ioctl to get first subpartition (after invalid write)");
    check_subpartition_properties(sub1_minor, 0, 0, true, "ioctl to get second subpartition (after invalid write)");

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

    buf_ptr[MBR_SIGNATURE_OFFSET_0] = MBR_SIGNATURE_BYTE_0;
    buf_ptr[MBR_SIGNATURE_OFFSET_1] = MBR_SIGNATURE_BYTE_1;

    write_partition_table_and_reset_driver(driver_minor, buf_ptr, buf_size, "write of valid partition table");

    open_device(sub0_minor);
    open_device(sub1_minor);

    check_subpartition_properties(
        sub0_minor,
        part.base + sector_size,
        (u64_t)part_secs * sector_size,
        false,
        "ioctl to get first subpartition (after valid write)"
    );

    check_subpartition_properties(
        sub1_minor,
        part.base + ((u64_t)1 + part_secs) * sector_size,
        (u64_t)part_secs * sector_size,
        false,
        "ioctl to get second subpartition (after valid write)"
    );

    read_limits(sub0_minor, sub1_minor, sub_size);
    write_limits(sub0_minor, sub1_minor, sub_size);

    close_device(sub1_minor);
    close_device(sub0_minor);

cleanup_dma:
    if (buf_ptr != NULL) {
        free_dma_memory(buf_ptr, buf_size);
    }
}

static dev_t get_first_subpartition_minor(dev_t current_driver_minor)
{
	const dev_t partition_index_on_drive = current_driver_minor % DEV_PER_DRIVE;

	if (partition_index_on_drive > 0) {
		const dev_t drive_index = current_driver_minor / DEV_PER_DRIVE;
		const dev_t primary_partition_0_indexed = partition_index_on_drive - 1;

		const dev_t subpartition_block_index = (drive_index * NR_PARTITIONS) + primary_partition_0_indexed;

		return MINOR_d0p0s0 + (subpartition_block_index * NR_PARTITIONS);
	} else {
		return current_driver_minor + 1;
	}
}

static void part_limits(void)
{
	if (driver_minor >= MINOR_d0p0s0) {
		output("WARNING: operating on subpartition, "
			"skipping partition tests\n");
		return;
	}

	const dev_t sub0_minor = get_first_subpartition_minor(driver_minor);
	const dev_t sub1_minor = sub0_minor + 1;

	const int part_secs_value = 9; /* sectors in each partition. must be >= 4. */

	vir_limits(sub0_minor, sub1_minor, part_secs_value);

	real_limits(sub0_minor, sub1_minor, part_secs_value - 1);
}

static void setup_pattern_iov_and_checksums(UnalignedIOPattern pattern,
    u8_t *buf_ptr, u8_t *sec_ptr[2], size_t total_size,
    iovec_t iovt[3], u32_t rsum_out[3], int *nr_req_out)
{
    switch (pattern) {
        case UNALIGNED_PATTERN_LEFT_SMALL:
            iovt[0].iov_addr = (vir_bytes) sec_ptr[0];
            iovt[0].iov_size = element_size;

            iovt[1].iov_addr = (vir_bytes) buf_ptr;
            iovt[1].iov_size = total_size - element_size;
            rsum_out[1] = get_sum(buf_ptr + iovt[1].iov_size, element_size);

            *nr_req_out = 2;
            break;
        case UNALIGNED_PATTERN_RIGHT_SMALL:
            iovt[0].iov_addr = (vir_bytes) buf_ptr;
            iovt[0].iov_size = total_size - element_size;
            rsum_out[1] = get_sum(buf_ptr + iovt[0].iov_size, element_size);

            iovt[1].iov_addr = (vir_bytes) sec_ptr[0];
            iovt[1].iov_size = element_size;

            *nr_req_out = 2;
            break;
        case UNALIGNED_PATTERN_BOTH_SIDES_SMALL:
            iovt[0].iov_addr = (vir_bytes) sec_ptr[0];
            iovt[0].iov_size = element_size;

            iovt[1].iov_addr = (vir_bytes) buf_ptr;
            iovt[1].iov_size = total_size - element_size * 2;
            rsum_out[1] = get_sum(buf_ptr + iovt[1].iov_size, element_size * 2);

            fill_rand(sec_ptr[1], sector_size);
            iovt[2].iov_addr = (vir_bytes) sec_ptr[1];
            iovt[2].iov_size = element_size;
            rsum_out[2] = get_sum(sec_ptr[1] + element_size, sector_size - element_size);

            *nr_req_out = 3;
            break;
        default:
            assert(0);
    }
}

static void verify_read_and_reconstruct_buffer(UnalignedIOPattern pattern,
    u8_t *buf_ptr, u8_t *sec_ptr[2], iovec_t iovt[3], u32_t rsum[3], result_t *res)
{
    test_sum(sec_ptr[0] + element_size, sector_size - element_size, rsum[0], TRUE, res);

    switch (pattern) {
        case UNALIGNED_PATTERN_LEFT_SMALL:
            test_sum(buf_ptr + iovt[1].iov_size, element_size, rsum[1], TRUE, res);
            memmove(buf_ptr + element_size, buf_ptr, iovt[1].iov_size);
            memcpy(buf_ptr, sec_ptr[0], element_size);
            break;
        case UNALIGNED_PATTERN_RIGHT_SMALL:
            test_sum(buf_ptr + iovt[0].iov_size, element_size, rsum[1], TRUE, res);
            memcpy(buf_ptr + iovt[0].iov_size, sec_ptr[0], element_size);
            break;
        case UNALIGNED_PATTERN_BOTH_SIDES_SMALL:
            test_sum(buf_ptr + iovt[1].iov_size, element_size * 2, rsum[1], TRUE, res);
            test_sum(sec_ptr[1] + element_size, sector_size - element_size, rsum[2], TRUE, res);
            memmove(buf_ptr + element_size, buf_ptr, iovt[1].iov_size);
            memcpy(buf_ptr, sec_ptr[0], element_size);
            memcpy(buf_ptr + element_size + iovt[1].iov_size, sec_ptr[1], element_size);
            break;
        default:
            assert(0);
    }
}

static void prepare_buffers_for_write(UnalignedIOPattern pattern,
    u8_t *buf_ptr, u8_t *sec_ptr[2], iovec_t iovt[3],
    u32_t ssum[5], int sectors)
{
    for (int i = 0; i < sectors; i++) {
        ssum[1 + i] = fill_rand(buf_ptr + sector_size * i, sector_size);
    }

    switch (pattern) {
        case UNALIGNED_PATTERN_LEFT_SMALL:
            memcpy(sec_ptr[0], buf_ptr, element_size);
            memmove(buf_ptr, buf_ptr + element_size, iovt[1].iov_size);
            fill_rand(buf_ptr + iovt[1].iov_size, element_size);
            break;
        case UNALIGNED_PATTERN_RIGHT_SMALL:
            memcpy(sec_ptr[0], buf_ptr + iovt[0].iov_size, element_size);
            fill_rand(buf_ptr + iovt[0].iov_size, element_size);
            break;
        case UNALIGNED_PATTERN_BOTH_SIDES_SMALL:
            memcpy(sec_ptr[0], buf_ptr, element_size);
            memcpy(sec_ptr[1], buf_ptr + element_size + iovt[1].iov_size, element_size);
            memmove(buf_ptr, buf_ptr + element_size, iovt[1].iov_size);
            fill_rand(buf_ptr + iovt[1].iov_size, element_size * 2);
            break;
        default:
            assert(0);
    }
}

typedef enum {
    UNALIGNED_PATTERN_LEFT_SMALL = 0,
    UNALIGNED_PATTERN_RIGHT_SMALL = 1,
    UNALIGNED_PATTERN_BOTH_SIDES_SMALL = 2
} UnalignedIOPattern;

static void unaligned_size_io(u64_t base_pos, u8_t *buf_ptr, size_t buf_size,
	u8_t *sec_ptr[2], int sectors, int pattern_int, u32_t ssum[5])
{
	iovec_t iov[3], iovt[3];
	u32_t rsum[3];
	result_t res;
	size_t total_size;
	int nr_req;
    UnalignedIOPattern pattern = (UnalignedIOPattern)pattern_int;

	base_pos += sector_size;
	total_size = sector_size * sectors;

	if (sector_size / element_size == 2 && sectors == 1 && pattern == UNALIGNED_PATTERN_BOTH_SIDES_SMALL) {
		return;
    }

	fill_rand(sec_ptr[0], sector_size);
	rsum[0] = get_sum(sec_ptr[0] + element_size, sector_size - element_size);
	fill_rand(buf_ptr, buf_size);

    setup_pattern_iov_and_checksums(pattern, buf_ptr, sec_ptr, total_size, iovt, rsum, &nr_req);

	memcpy(iov, iovt, sizeof(iovec_t) * nr_req);
	vir_xfer(driver_minor, base_pos, iov, nr_req, FALSE, total_size, &res);

    verify_read_and_reconstruct_buffer(pattern, buf_ptr, sec_ptr, iovt, rsum, &res);

	for (int i = 0; i < sectors; i++) {
		test_sum(buf_ptr + sector_size * i, sector_size, ssum[1 + i], TRUE, &res);
    }
	got_result(&res, "read with small elements");

	if (!may_write) {
		return;
    }

    prepare_buffers_for_write(pattern, buf_ptr, sec_ptr, iovt, ssum, sectors);

	memcpy(iov, iovt, sizeof(iovec_t) * nr_req);
	vir_xfer(driver_minor, base_pos, iov, nr_req, TRUE, total_size, &res);

	got_result(&res, "write with small elements");

	fill_rand(buf_ptr, sector_size * 3);

	simple_xfer(driver_minor, base_pos, buf_ptr, sector_size * 3, FALSE,
		sector_size * 3, &res);

	for (int i = 0; i < 3; i++) {
		test_sum(buf_ptr + sector_size * i, sector_size, ssum[1 + i],
			TRUE, &res);
    }

	got_result(&res, "readback verification");
}

static void unaligned_size(void)
{
    /* Test sector-unaligned sizes in I/O vector elements. The total size
     * of the request, however, has to add up to the sector size.
     */

    /* Constants for improved readability and maintainability */
#define NUM_BASELINE_SECTORS 5
#define BASELINE_SECTOR_OFFSET 2 /* Start I/O at sector 2 (0-indexed) */
#define NUM_UNALIGNED_SUBTESTS 9
#define UNALIGNED_SUBTEST_TRIPLET_SIZE 3

    test_group("sector-unaligned elements", sector_size != element_size);

    if (sector_size == element_size) {
        return;
    }

    /* Precondition check: sector size must be a multiple of element size.
     * For test code, assert is generally acceptable here.
     */
    assert(sector_size % element_size == 0);

    size_t buf_size = (size_t)sector_size * NUM_BASELINE_SECTORS;
    u64_t base_pos = (u64_t)sector_size * BASELINE_SECTOR_OFFSET;

    u8_t *buf_ptr = alloc_dma_memory(buf_size);
    if (buf_ptr == NULL) {
        /* Allocation failed. In a test environment, this is often a fatal error. */
        return;
    }

    u8_t *sec_ptr[2];
    sec_ptr[0] = alloc_dma_memory(sector_size);
    if (sec_ptr[0] == NULL) {
        free_dma_memory(buf_ptr, buf_size);
        return;
    }
    sec_ptr[1] = alloc_dma_memory(sector_size);
    if (sec_ptr[1] == NULL) {
        free_dma_memory(sec_ptr[0], sector_size);
        free_dma_memory(buf_ptr, buf_size);
        return;
    }

    u32_t expected_total_sum = 0L;
    u32_t ssum[NUM_BASELINE_SECTORS];
    result_t res;
    int i;

    /* Establish a baseline by writing and reading back five sectors;
     * or by reading only, if writing is disabled.
     */
    if (may_write) {
        expected_total_sum = fill_rand(buf_ptr, buf_size);
        for (i = 0; i < NUM_BASELINE_SECTORS; i++) {
            ssum[i] = get_sum(buf_ptr + (size_t)sector_size * i, sector_size);
        }

        simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE, buf_size, &res);
        if (!got_result(&res, "write several sectors (baseline)")) {
            /* Handle write error. Depending on test harness, could exit or skip. */
        }
    }

    /* Read back the baseline sectors. The buf_ptr content before this read is irrelevant
     * as simple_xfer will overwrite it with data from the device.
     */
    simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);
    if (!got_result(&res, "read several sectors (baseline)")) {
        /* Handle read error. If read fails, subsequent sum checks will be invalid. */
    }

    if (may_write) {
        /* Verify the data read back matches what was written. */
        test_sum(buf_ptr, buf_size, expected_total_sum, TRUE, &res);
    } else {
        /* If writing is disabled, populate ssum from the data read from disk.
         * This 'read' data now becomes the 'expected' data for later verification.
         */
        for (i = 0; i < NUM_BASELINE_SECTORS; i++) {
            ssum[i] = get_sum(buf_ptr + (size_t)sector_size * i, sector_size);
        }
    }

    /* We do nine subtests. The first three involve only the second sector;
     * the second three involve the second and third sectors, and the third
     * three involve all of the middle sectors. Each triplet tests small
     * elements at the left, at the right, and at both the left and the
     * right of the area. For each operation, we first do an unaligned
     * read, and if writing is enabled, an unaligned write and an aligned
     * read.
     */
    for (i = 0; i < NUM_UNALIGNED_SUBTESTS; i++) {
        int middle_sectors_count = (i / UNALIGNED_SUBTEST_TRIPLET_SIZE) + 1; /* 1, 2, or 3 middle sectors */
        int alignment_type = i % UNALIGNED_SUBTEST_TRIPLET_SIZE; /* Left, Right, or Both alignment */
        unaligned_size_io(base_pos, buf_ptr, buf_size, sec_ptr,
                          middle_sectors_count, alignment_type, ssum);
    }

    /* If writing was enabled, make sure that the first and fifth sector
     * have remained untouched by the unaligned I/O operations.
     */
    if (may_write) {
        /* Read back the entire baseline area to check boundary sectors.
         * The buf_ptr content before this read is irrelevant.
         */
        simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);
        if (!got_result(&res, "read sectors for boundary check")) {
            /* Handle read error. */
        }

        test_sum(buf_ptr, sector_size, ssum[0], TRUE, &res); /* Check first sector */
        test_sum(buf_ptr + (size_t)sector_size * (NUM_BASELINE_SECTORS - 1), sector_size, ssum[NUM_BASELINE_SECTORS - 1], TRUE, &res); /* Check last sector */

        got_result(&res, "check first and last sectors untouched");
    }

    /* Clean up allocated memory. */
    free_dma_memory(sec_ptr[1], sector_size);
    free_dma_memory(sec_ptr[0], sector_size);
    free_dma_memory(buf_ptr, buf_size);

#undef NUM_BASELINE_SECTORS
#undef BASELINE_SECTOR_OFFSET
#undef NUM_UNALIGNED_SUBTESTS
#undef UNALIGNED_SUBTEST_TRIPLET_SIZE
}

#include <stddef.h>
#include <assert.h>

#define NUM_BASELINE_SECTORS 3

static u8_t* safe_alloc_dma_memory(size_t size, const char* name)
{
    u8_t* ptr = alloc_dma_memory(size);
    if (ptr == NULL) {
        test_fail_abort("%s: Failed to allocate %zu bytes of DMA memory.", name, size);
    }
    return ptr;
}

static int setup_baseline_data(u64_t base_pos, u8_t* buf_ptr, size_t buf_size, u32_t* initial_write_sum_out)
{
    result_t res = {0};

    if (may_write) {
        *initial_write_sum_out = fill_rand(buf_ptr, buf_size);
        simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE, buf_size, &res);
        if (!res.passed) {
            got_result(&res, "write several sectors (baseline)");
            return 0;
        }
        got_result(&res, "write several sectors (baseline)");
    }

    simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);
    if (!res.passed) {
        got_result(&res, "read several sectors (baseline)");
        return 0;
    }

    if (may_write) {
        test_sum(buf_ptr, buf_size, *initial_write_sum_out, TRUE, &res);
        if (!res.passed) {
            got_result(&res, "read several sectors (baseline) verification");
            return 0;
        }
    }
    got_result(&res, "read several sectors (baseline)");

    return 1;
}

static int perform_read_and_verify(
    u64_t device_read_pos,
    u8_t* target_buffer,
    size_t target_buffer_offset,
    size_t transfer_size,
    size_t conceptual_buffer_start_offset,
    size_t conceptual_buffer_length,
    u64_t source_device_base_pos,
    u8_t* source_buffer_copy,
    size_t target_buffer_total_allocated_size,
    const char* test_description)
{
    result_t res = {0};

    assert(conceptual_buffer_start_offset + conceptual_buffer_length <= target_buffer_total_allocated_size);
    assert(target_buffer_offset >= conceptual_buffer_start_offset);
    assert(target_buffer_offset + transfer_size <= conceptual_buffer_start_offset + conceptual_buffer_length);

    fill_rand(target_buffer + conceptual_buffer_start_offset, conceptual_buffer_length);

    u32_t sum_untouched_lead = 0;
    size_t size_untouched_lead = 0;
    if (target_buffer_offset > conceptual_buffer_start_offset) {
        size_untouched_lead = target_buffer_offset - conceptual_buffer_start_offset;
        sum_untouched_lead = get_sum(target_buffer + conceptual_buffer_start_offset, size_untouched_lead);
    }

    u32_t sum_untouched_trail = 0;
    size_t size_untouched_trail = 0;
    size_t end_of_transfer_in_target = target_buffer_offset + transfer_size;
    size_t end_of_conceptual_buffer = conceptual_buffer_start_offset + conceptual_buffer_length;
    if (end_of_transfer_in_target < end_of_conceptual_buffer) {
        size_untouched_trail = end_of_conceptual_buffer - end_of_transfer_in_target;
        sum_untouched_trail = get_sum(target_buffer + end_of_transfer_in_target, size_untouched_trail);
    }

    simple_xfer(driver_minor, device_read_pos, target_buffer + target_buffer_offset,
                transfer_size, FALSE, transfer_size, &res);
    if (!res.passed) {
        got_result(&res, test_description);
        return 0;
    }

    u64_t source_offset_in_copy = device_read_pos - source_device_base_pos;
    test_sum(target_buffer + target_buffer_offset, transfer_size,
             get_sum(source_buffer_copy + source_offset_in_copy, transfer_size),
             TRUE, &res);
    if (!res.passed) {
        got_result(&res, test_description);
        return 0;
    }

    if (size_untouched_lead > 0) {
        test_sum(target_buffer + conceptual_buffer_start_offset, size_untouched_lead,
                 sum_untouched_lead, TRUE, &res);
        if (!res.passed) {
            got_result(&res, test_description);
            return 0;
        }
    }

    if (size_untouched_trail > 0) {
        test_sum(target_buffer + end_of_transfer_in_target, size_untouched_trail,
                 sum_untouched_trail, TRUE, &res);
        if (!res.passed) {
            got_result(&res, test_description);
            return 0;
        }
    }

    got_result(&res, test_description);
    return 1;
}

static void unaligned_pos1(void)
{
    u8_t *buf_ptr = NULL, *buf2_ptr = NULL;
    size_t buf_size = 0, buf2_size = 0;
    u32_t baseline_data_sum = 0;
    u64_t base_pos;

    test_group("sector-unaligned positions, part one", min_read != sector_size);

    if (min_read == sector_size) {
        return;
    }

    assert(sector_size % min_read == 0);
    assert(min_read % element_size == 0);

    buf_size = (size_t)sector_size * NUM_BASELINE_SECTORS;
    buf2_size = (size_t)sector_size * NUM_BASELINE_SECTORS;

    base_pos = (u64_t)sector_size * NUM_BASELINE_SECTORS;

    buf_ptr = safe_alloc_dma_memory(buf_size, "buf_ptr");
    buf2_ptr = safe_alloc_dma_memory(buf2_size, "buf2_ptr");

    if (!setup_baseline_data(base_pos, buf_ptr, buf_size, &baseline_data_sum)) {
        goto cleanup;
    }

    // --- Single sector tests ---

    if (!perform_read_and_verify(
        base_pos + sector_size - min_read,
        buf2_ptr,
        0,
        min_read,
        0,
        sector_size,
        base_pos,
        buf_ptr,
        buf2_size,
        "single sector read with lead"
    )) {
        goto cleanup;
    }

    if (!perform_read_and_verify(
        base_pos,
        buf2_ptr,
        sector_size - min_read,
        min_read,
        0,
        sector_size,
        base_pos,
        buf_ptr,
        buf2_size,
        "single sector read with trail"
    )) {
        goto cleanup;
    }

    if (!perform_read_and_verify(
        base_pos + min_read,
        buf2_ptr,
        min_read,
        min_read,
        0,
        sector_size,
        base_pos,
        buf_ptr,
        buf2_size,
        "single sector read with lead and trail"
    )) {
        goto cleanup;
    }

    // --- Multi-sector tests ---
    size_t multi_sector_read_size = min_read + (size_t)sector_size * 2;

    if (!perform_read_and_verify(
        base_pos + sector_size - min_read,
        buf2_ptr,
        0,
        multi_sector_read_size,
        0,
        buf2_size,
        base_pos,
        buf_ptr,
        buf2_size,
        "multisector read with lead"
    )) {
        goto cleanup;
    }

    if (!perform_read_and_verify(
        base_pos,
        buf2_ptr,
        0,
        multi_sector_read_size,
        0,
        buf2_size,
        base_pos,
        buf_ptr,
        buf2_size,
        "multisector read with trail"
    )) {
        goto cleanup;
    }

    if (!perform_read_and_verify(
        base_pos + min_read,
        buf2_ptr,
        0,
        sector_size,
        0,
        buf2_size,
        base_pos,
        buf_ptr,
        buf2_size,
        "multisector read with lead and trail"
    )) {
        goto cleanup;
    }

cleanup:
    if (buf2_ptr != NULL) {
        free_dma_memory(buf2_ptr, buf2_size);
    }
    if (buf_ptr != NULL) {
        free_dma_memory(buf_ptr, buf_size);
    }
}

static void unaligned_pos2(void)
{
	u8_t *buf_ptr = NULL;
	u8_t *buf2_ptr = NULL;
	size_t buf_size;
	size_t buf2_size;
	size_t max_block;
	u32_t sum = 0L, sum2 = 0L;
	u32_t rsum[NR_IOREQS];
	u64_t base_pos;
	iovec_t iov[NR_IOREQS];
	result_t res;
	int i;

	test_group("sector-unaligned positions, part two",
		min_read != sector_size);

	if (min_read == sector_size) {
		return;
	}

	buf_size = max_size + sector_size;
	buf2_size = max_size + sector_size;

	base_pos = (u64_t)sector_size * 3;

	buf_ptr = alloc_dma_memory(buf_size);
	if (buf_ptr == NULL) {
		/* Failed to allocate primary buffer. Returning early. */
		return;
	}

	buf2_ptr = alloc_dma_memory(buf2_size);
	if (buf2_ptr == NULL) {
		/* Failed to allocate secondary buffer. Free primary buffer before returning. */
		free_dma_memory(buf_ptr, buf_size);
		return;
	}

	/* First establish a baseline for read/write operations. */
	if (may_write) {
		sum = fill_rand(buf_ptr, max_size);
		simple_xfer(driver_minor, base_pos, buf_ptr, max_size, TRUE,
			max_size, &res);
		got_result(&res, "large baseline write");

		sum2 = fill_rand(buf_ptr + max_size, sector_size);
		simple_xfer(driver_minor, base_pos + max_size,
			buf_ptr + max_size, sector_size, TRUE, sector_size,
			&res);
		got_result(&res, "small baseline write");
	}

	/* Prepare buffer for baseline reads: fill with random data to verify that
	 * the read operations correctly overwrite it. */
	fill_rand(buf_ptr, buf_size);

	/* Perform large baseline read. */
	simple_xfer(driver_minor, base_pos, buf_ptr, max_size, FALSE, max_size,
		&res);
	if (may_write) {
		/* Only test sum if a baseline write was performed, meaning 'sum' is valid. */
		test_sum(buf_ptr, max_size, sum, TRUE, &res);
	}
	got_result(&res, "large baseline read");

	/* Perform small baseline read. */
	simple_xfer(driver_minor, base_pos + max_size, buf_ptr + max_size,
		sector_size, FALSE, sector_size, &res);
	if (may_write) {
		/* Only test sum if a baseline write was performed, meaning 'sum2' is valid. */
		test_sum(buf_ptr + max_size, sector_size, sum2, TRUE, &res);
	}
	got_result(&res, "small baseline read");

	/* Test: small fully unaligned filled vector. */
	fill_rand(buf2_ptr, buf2_size);

	for (i = 0; i < NR_IOREQS; i++) {
		iov[i].iov_addr = (vir_bytes)(buf2_ptr + (size_t)i * sector_size);
		iov[i].iov_size = min_read;
		/* Calculate sum of the *unaffected* part of the sector. */
		rsum[i] = get_sum(buf2_ptr + (size_t)i * sector_size + min_read,
			sector_size - min_read);
	}

	vir_xfer(driver_minor, base_pos + min_read, iov, NR_IOREQS, FALSE,
		(size_t)min_read * NR_IOREQS, &res);

	for (i = 0; i < NR_IOREQS; i++) {
		/* Verify the part of the sector that should not have been read. */
		test_sum(buf2_ptr + (size_t)i * sector_size + min_read,
			sector_size - min_read, rsum[i], TRUE, &res);
		/* Move the actual read data to the front of the iov block for final verification. */
		memmove(buf2_ptr + (size_t)i * min_read, buf2_ptr + (size_t)i * sector_size,
			min_read);
	}

	/* Verify the total read data by comparing against the original data from buf_ptr. */
	test_sum(buf2_ptr, (size_t)min_read * NR_IOREQS, get_sum(buf_ptr + min_read,
		(size_t)min_read * NR_IOREQS), TRUE, &res);

	got_result(&res, "small fully unaligned filled vector");

	/* Test: large fully unaligned single element. */
	fill_rand(buf2_ptr, buf2_size);

	simple_xfer(driver_minor, base_pos + min_read, buf2_ptr, max_size,
		FALSE, max_size, &res);

	test_sum(buf2_ptr, max_size, get_sum(buf_ptr + min_read, max_size),
		TRUE, &res);

	got_result(&res, "large fully unaligned single element");

	/* Test: large fully unaligned filled vector. Each element is as large as possible. */
	max_block = max_size / NR_IOREQS;
	/* Ensure max_block is a multiple of sector_size. */
	max_block -= max_block % sector_size;

	fill_rand(buf2_ptr, buf2_size);

	for (i = 0; i < NR_IOREQS; i++) {
		iov[i].iov_addr = (vir_bytes)(buf2_ptr + (size_t)i * max_block);
		iov[i].iov_size = max_block;
	}

	vir_xfer(driver_minor, base_pos + min_read, iov, NR_IOREQS, FALSE,
		max_block * NR_IOREQS, &res);

	test_sum(buf2_ptr, max_block * NR_IOREQS, get_sum(buf_ptr + min_read,
		max_block * NR_IOREQS), TRUE, &res);

	got_result(&res, "large fully unaligned filled vector");

	/* Clean up allocated DMA memory. */
	free_dma_memory(buf2_ptr, buf2_size);
	free_dma_memory(buf_ptr, buf_size);
}

static void perform_xfer_and_check(u64_t pos, u8_t *buffer, size_t len, int is_write, result_t *res_out, const char *action_desc) {
    simple_xfer(driver_minor, pos, buffer, len, is_write, len, res_out);
    got_result(res_out, action_desc);
}

static void update_sector_checksums(u32_t *checksum_array, const u8_t *buffer, size_t start_idx, size_t num_sectors_to_update) {
    for (size_t k = 0; k < num_sectors_to_update; ++k) {
        checksum_array[start_idx + k] = get_sum(buffer + (u64_t)sector_size * k, sector_size);
    }
}

static void verify_sector_checksums(const u32_t *checksum_array, const u8_t *buffer, size_t start_idx, size_t num_sectors_to_verify, result_t *res_out) {
    for (size_t k = 0; k < num_sectors_to_verify; ++k) {
        test_sum(buffer + (u64_t)sector_size * k, sector_size, checksum_array[start_idx + k], TRUE, res_out);
    }
}

static void sweep_area(u64_t base_pos)
{
    const size_t FULL_AREA_SECTORS = 8;
    const size_t SUB_AREA_SECTORS = 3;
    const size_t NUM_SUB_AREA_SWEEPS = FULL_AREA_SECTORS - SUB_AREA_SECTORS + 1;

    const size_t full_area_byte_size = (size_t)sector_size * FULL_AREA_SECTORS;
    const size_t sub_area_chunk_byte_size = (size_t)sector_size * SUB_AREA_SECTORS;

    u8_t *dma_buffer = NULL;
    u32_t initial_full_area_checksum = 0U;
    u32_t sector_checksums[FULL_AREA_SECTORS];
    result_t operation_result;
    size_t i;

    dma_buffer = alloc_dma_memory(full_area_byte_size);
    if (dma_buffer == NULL) {
        return;
    }

    if (may_write) {
        initial_full_area_checksum = fill_rand(dma_buffer, full_area_byte_size);
        perform_xfer_and_check(base_pos, dma_buffer, full_area_byte_size, TRUE, &operation_result, "write to full area");
    }

    fill_rand(dma_buffer, full_area_byte_size);
    perform_xfer_and_check(base_pos, dma_buffer, full_area_byte_size, FALSE, &operation_result, "read from full area");

    if (may_write) {
        test_sum(dma_buffer, full_area_byte_size, initial_full_area_checksum, TRUE, &operation_result);
    }
    update_sector_checksums(sector_checksums, dma_buffer, 0, FULL_AREA_SECTORS);

    for (i = 0; i < NUM_SUB_AREA_SWEEPS; ++i) {
        u64_t current_sub_area_pos = base_pos + (u64_t)sector_size * i;

        fill_rand(dma_buffer, sub_area_chunk_byte_size);
        perform_xfer_and_check(current_sub_area_pos, dma_buffer, sub_area_chunk_byte_size, FALSE, &operation_result, "read from subarea");
        verify_sector_checksums(sector_checksums, dma_buffer, i, SUB_AREA_SECTORS, &operation_result);

        if (!may_write) {
            continue;
        }

        fill_rand(dma_buffer, sub_area_chunk_byte_size);
        perform_xfer_and_check(current_sub_area_pos, dma_buffer, sub_area_chunk_byte_size, TRUE, &operation_result, "write to subarea");
        update_sector_checksums(sector_checksums, dma_buffer, i, SUB_AREA_SECTORS);
    }

    if (may_write) {
        fill_rand(dma_buffer, full_area_byte_size);
        perform_xfer_and_check(base_pos, dma_buffer, full_area_byte_size, FALSE, &operation_result, "readback from full area");
        verify_sector_checksums(sector_checksums, dma_buffer, 0, FULL_AREA_SECTORS, &operation_result);
    }

    free_dma_memory(dma_buffer, full_area_byte_size);
}

typedef unsigned long long u64_t;
typedef unsigned char u8_t;
typedef unsigned int u32_t;

typedef struct {
    int status_code; // 0 for success, non-zero for error
} result_t;

static inline int is_successful(result_t res) {
    return res.status_code == 0;
}

extern size_t sector_size;
extern int driver_minor;
extern int may_write;

extern u8_t *alloc_dma_memory(size_t size);
extern void free_dma_memory(u8_t *ptr, size_t size);
extern u32_t fill_rand(u8_t *buf, size_t size);
extern void simple_xfer(int minor, u64_t offset, u8_t *buf, size_t size, int is_write, size_t actual_size, result_t *res);
extern void got_result(result_t *res, const char *description);
extern void sweep_area(u64_t pos);
extern void test_sum(u8_t *buf, size_t size, u32_t expected_sum, int is_final_check, result_t *res);
extern u32_t get_sum(u8_t *buf, size_t size);

static int perform_io(int minor, u64_t offset, u8_t *buf, size_t size, int is_write, const char *description) {
    result_t res;
    simple_xfer(minor, offset, buf, size, is_write, size, &res);
    got_result(&res, description);
    if (!is_successful(res)) {
        return -1;
    }
    return 0;
}

static int setup_integrity_zone(u8_t *buf_ptr, size_t buf_size, u32_t *out_integrity_sum) {
    u32_t current_sum = 0;
    result_t res_check;

    if (may_write) {
        current_sum = fill_rand(buf_ptr, buf_size);
        if (perform_io(driver_minor, 0ULL, buf_ptr, buf_size, 1, "write integrity zone") != 0) {
            return -1;
        }
    }

    if (perform_io(driver_minor, 0ULL, buf_ptr, buf_size, 0, "read integrity zone (initial)") != 0) {
        return -1;
    }

    if (may_write) {
        test_sum(buf_ptr, buf_size, current_sum, 1, &res_check);
        got_result(&res_check, "verify integrity zone (post-write)");
        if (!is_successful(res_check)) {
            return -1;
        }
    } else {
        current_sum = get_sum(buf_ptr, buf_size);
    }

    *out_integrity_sum = current_sum;
    return 0;
}

static int verify_integrity_zone_post_sweep(u8_t *buf_ptr, size_t buf_size, u32_t expected_sum) {
    result_t res_check;

    if (perform_io(driver_minor, 0ULL, buf_ptr, buf_size, 0, "read integrity zone (post-sweep)") != 0) {
        return -1;
    }

    test_sum(buf_ptr, buf_size, expected_sum, 1, &res_check);
    got_result(&res_check, "verify integrity zone (post-sweep)");
    if (!is_successful(res_check)) {
        return -1;
    }
    return 0;
}


static void sweep_and_check(u64_t pos, int check_integ) {
    u8_t *buf_ptr = NULL;
    size_t buf_size = 0;
    u32_t integrity_sum = 0;
    int ret = 0;

    if (check_integ) {
        buf_size = sector_size * 3;
        buf_ptr = alloc_dma_memory(buf_size);
        if (buf_ptr == NULL) {
            return;
        }

        ret = setup_integrity_zone(buf_ptr, buf_size, &integrity_sum);
        if (ret != 0) {
            goto cleanup;
        }
    }

    sweep_area(pos);

    if (check_integ && ret == 0) {
        ret = verify_integrity_zone_post_sweep(buf_ptr, buf_size, integrity_sum);
        if (ret != 0) {
            // Error already logged by helper, proceed to cleanup.
        }
    }

cleanup:
    if (buf_ptr != NULL) {
        free_dma_memory(buf_ptr, buf_size);
    }
}

static void basic_sweep(void)
{
	test_group("basic area sweep", 1);

	int sweep_result = sweep_area((u64_t)sector_size);

	if (sweep_result != 0) {
		fprintf(stderr, "Error: Failed to perform basic area sweep. Error code: %d\n", sweep_result);
	}
}

static void high_disk_pos(void)
{
    const u64_t FOUR_GIGABYTES = 0x100000000ULL;
    const u64_t SECTORS_ABOVE_4GB_INITIAL_OFFSET = 4;
    const u64_t SECTORS_BELOW_4GB_ADJUSTMENT = 8;

    u64_t target_abs_pos_upper;
    u64_t target_abs_pos_lower;
    u64_t test_offset_relative_to_partition_base;

    target_abs_pos_upper = FOUR_GIGABYTES + (SECTORS_ABOVE_4GB_INITIAL_OFFSET * sector_size);
    target_abs_pos_upper -= target_abs_pos_upper % sector_size;

    if (part.base + part.size < target_abs_pos_upper) {
        test_group("high disk positions", FALSE);
        return;
    }

    target_abs_pos_lower = target_abs_pos_upper - (SECTORS_BELOW_4GB_ADJUSTMENT * sector_size);

    if (target_abs_pos_lower < part.base) {
        test_group("high disk positions", FALSE);
        return;
    }

    test_group("high disk positions", TRUE);

    test_offset_relative_to_partition_base = target_abs_pos_lower - part.base;

    sweep_and_check(test_offset_relative_to_partition_base, part.base == 0ULL);
}

static void high_part_pos(void)
{
    const u64_t FOUR_GIGABYTES = 0x100000000ULL;
    const unsigned int MIN_INITIAL_EXTRA_SECTORS = 4;
    const unsigned int SWEEP_OFFSET_SECTORS = 8;

    u64_t test_position;

    if (part.base == 0ULL) {
        return;
    }

    u64_t target_unaligned_pos = FOUR_GIGABYTES + (u64_t)sector_size * MIN_INITIAL_EXTRA_SECTORS;

    test_position = target_unaligned_pos - (target_unaligned_pos % sector_size);

    if (part.size < test_position) {
        test_group("high partition positions", FALSE);
        return;
    }

    test_group("high partition positions", TRUE);

    test_position -= (u64_t)sector_size * SWEEP_OFFSET_SECTORS;

    sweep_and_check(test_position, TRUE);
}

static void high_lba_pos1(void)
{
	const u64_t LBA_24BIT_BOUNDARY_SECTORS = (1ULL << 24);
	const u64_t SWEEP_OFFSET_SECTORS = 8;

	u64_t lba_boundary_byte_pos = LBA_24BIT_BOUNDARY_SECTORS * sector_size;
	u64_t sweep_start_absolute_pos = lba_boundary_byte_pos - (SWEEP_OFFSET_SECTORS * sector_size);

	bool test_passed = true;

	if (part.base + part.size < lba_boundary_byte_pos) {
		test_passed = false;
	}

	if (test_passed && sweep_start_absolute_pos < part.base) {
		test_passed = false;
	}

	test_group("high LBA positions, part one", test_passed);

	if (!test_passed) {
		return;
	}

	u64_t sweep_start_relative_to_partition = sweep_start_absolute_pos - part.base;

	sweep_and_check(sweep_start_relative_to_partition, part.base == 0ULL);
}

#define LBA_28BIT_THRESHOLD_SECTORS (1ULL << 28)
#define SECTOR_ADJUSTMENT_FOR_START_CHECK 8ULL

static void high_lba_pos2(void)
{
    const char* test_name = "high LBA positions, part two";
    _Bool all_conditions_met = 1; // Use _Bool for standard C compatibility if <stdbool.h> isn't guaranteed.

    u64_t lba_threshold_byte_pos = LBA_28BIT_THRESHOLD_SECTORS * sector_size;

    if (part.base + part.size < lba_threshold_byte_pos) {
        all_conditions_met = 0;
    }

    if (all_conditions_met) {
        u64_t max_partition_start_byte_pos = lba_threshold_byte_pos - (SECTOR_ADJUSTMENT_FOR_START_CHECK * sector_size);

        if (max_partition_start_byte_pos < part.base) {
            all_conditions_met = 0;
        }
    }

    test_group(test_name, all_conditions_met);

    if (all_conditions_met) {
        u64_t sweep_start_offset_in_partition = (LBA_28BIT_THRESHOLD_SECTORS * sector_size) -
                                                 (SECTOR_ADJUSTMENT_FOR_START_CHECK * sector_size) -
                                                 part.base;

        sweep_and_check(sweep_start_offset_in_partition, part.base == 0ULL);
    }
}

static int high_pos(void)
{
	if (basic_sweep() != 0) {
		return -1;
	}

	if (high_disk_pos() != 0) {
		return -1;
	}

	if (high_part_pos() != 0) {
		return -1;
	}

	if (high_lba_pos1() != 0) {
		return -1;
	}

	if (high_lba_pos2() != 0) {
		return -1;
	}

	return 0;
}

static void open_primary(void)
{
    int status = open_device(driver_minor);

    if (status != 0) {
        fprintf(stderr, "Error: Failed to open primary device (status: %d)\n", status);
        return;
    }
}

static void close_primary(void)
{
    // Remove test_group, as it is typically a testing/debugging construct and not part of core production logic.
    // Its presence in production code can reduce maintainability and might not be desired for SonarCloud analysis.

    // Call close_device and explicitly check its return value for errors.
    // This improves reliability by ensuring that failures during device closure are detected and reported,
    // rather than silently failing or leading to undefined behavior.
    if (close_device(driver_minor) != 0) {
        // Log the error. Assuming a `log_error` function is available in the system
        // for reporting critical issues without crashing the application.
        // This provides crucial information for debugging and system monitoring.
        log_error("Failed to close primary device with minor %d. Possible resource leak or system issue.", driver_minor);
    }

    // Replace the assert with a conditional check and error logging.
    // `assert` is typically used for development-time debugging and terminates the program on failure,
    // which is undesirable for reliability in production environments.
    // Checking `nr_opened` after device closure verifies a critical post-condition.
    if (nr_opened != 0) {
        // Log this condition as a severe error. If `nr_opened` is not 0, it indicates a
        // potential resource leak, an unhandled open device, or a logic error in resource management.
        log_error("CRITICAL ERROR: Device count `nr_opened` is %d after closing primary device; expected 0. System state inconsistent.", nr_opened);
        // Depending on system requirements, further actions might be implemented here,
        // such as attempting recovery, alerting administrators, or entering a safe mode.
    }
}

static void do_tests(void)
{
    int ret = 0;
    int primary_opened = 0;
    int test_failures_occurred = 0;

    ret = open_primary();
    if (ret != 0) {
        test_failures_occurred = 1;
        goto end_tests;
    }
    primary_opened = 1;

    ret = misc_ioctl();
    if (ret != 0) {
        test_failures_occurred = 1;
    }

    ret = bad_read1();
    if (ret != 0) {
        test_failures_occurred = 1;
    }

    ret = bad_read2();
    if (ret != 0) {
        test_failures_occurred = 1;
    }

    ret = bad_write();
    if (ret != 0) {
        test_failures_occurred = 1;
    }

    ret = vector_and_large();
    if (ret != 0) {
        test_failures_occurred = 1;
    }

    ret = part_limits();
    if (ret != 0) {
        test_failures_occurred = 1;
    }

    ret = unaligned_size();
    if (ret != 0) {
        test_failures_occurred = 1;
    }

    ret = unaligned_pos1();
    if (ret != 0) {
        test_failures_occurred = 1;
    }

    ret = unaligned_pos2();
    if (ret != 0) {
        test_failures_occurred = 1;
    }

    ret = high_pos();
    if (ret != 0) {
        test_failures_occurred = 1;
    }

end_tests:
    if (primary_opened) {
        ret = close_primary();
        if (ret != 0) {
            test_failures_occurred = 1;
        }
    }
}

#define DRIVER_MINOR_MAX 255

static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
	if (env_argc > 1) {
		optset_parse(optset_table, env_argv[1]);
	}

	if (driver_label[0] == '\0') {
		panic("no driver label given");
	}

	if (ds_retrieve_label_endpt(driver_label, &driver_endpt)) {
		panic("unable to resolve driver label");
	}

	if (driver_minor > DRIVER_MINOR_MAX) {
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

	return (failed_tests) ? EINVAL : OK;
}

#include <stdio.h>
#include <stdlib.h>

static void sef_local_startup(void)
{
	if (sef_setcb_init_fresh(sef_cb_init_fresh) != 0) {
		fprintf(stderr, "CRITICAL ERROR: Failed to set SEF initialization callback.\n");
		exit(EXIT_FAILURE);
	}

	if (sef_startup() != 0) {
		fprintf(stderr, "CRITICAL ERROR: SEF framework startup failed.\n");
		exit(EXIT_FAILURE);
	}
}

#include <stdlib.h> // Required for EXIT_SUCCESS and EXIT_FAILURE

// Function prototypes would typically be in a header file,
// but for this isolated refactoring, we assume they are defined elsewhere
// and their return types allow for error checking.
// We assume they return 0 for success and non-zero for failure.
// int env_setargs(int argc, char **argv);
// int sef_local_startup(void);

int main(int argc, char **argv)
{
	if (env_setargs(argc, argv) != 0) {
		// If env_setargs fails, return an error code
		return EXIT_FAILURE;
	}

	if (sef_local_startup() != 0) {
		// If sef_local_startup fails, return an error code
		return EXIT_FAILURE;
	}

	// If all operations succeed, return a success code
	return EXIT_SUCCESS;
}
