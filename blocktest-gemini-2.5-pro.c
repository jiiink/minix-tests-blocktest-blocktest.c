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
	if (silent || !fmt) {
		return;
	}

	va_list argp;
	va_start(argp, fmt);
	(void)vprintf(fmt, argp);
	va_end(argp);
}

static void *alloc_dma_memory(size_t size, bool is_contiguous)
{
    if (size == 0) {
        return NULL;
    }

    if (is_contiguous) {
        // Assuming alloc_contig returns NULL on failure.
        return alloc_contig(size, 0, NULL);
    }

    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PREALLOC | MAP_ANON, -1, 0);

    if (ptr == MAP_FAILED) {
        return NULL;
    }

    return ptr;
}

static void free_dma_memory(void *ptr, size_t size)
{
	/* Free memory previously allocated for direct DMA. */
	if (!ptr) {
		return;
	}

	if (contig) {
		free_contig(ptr, size);
	} else {
		if (munmap(ptr, size) != 0) {
			perror("Failed to unmap DMA memory");
		}
	}
}

static inline int set_result(result_t *res, int type, ssize_t value)
{
	if (res != NULL) {
		res->type = type;
		res->value = value;
	}
	return type;
}

static int accept_result(result_t *res, int type, ssize_t value)
{
	if (res && res->type == type && res->value == value) {
		set_result(res, RESULT_OK, 0);
		return TRUE;
	}

	return FALSE;
}

static void got_result(result_t *res, char *desc)
{
	if (res == NULL || desc == NULL) {
		return;
	}

	static int test_number = 0;
	total_tests++;

	const bool is_failure = (res->type != RESULT_OK);

	if (is_failure) {
		failed_tests++;
		if (!group_failure) {
			failed_groups++;
			group_failure = TRUE;
		}
	}

	output("#%02d: %-38s\t[%s]\n", ++test_number, desc,
		is_failure ? "FAIL" : "PASS");

	if (!is_failure) {
		return;
	}

	typedef struct {
		int type;
		const char *format;
		bool uses_value;
	} failure_detail_t;

	static const failure_detail_t details[] = {
		{ RESULT_DEATH, "- driver died\n", false },
		{ RESULT_COMMFAIL,
			"- communication failed; ipc_sendrec returned %d\n", true },
		{ RESULT_BADTYPE, "- bad type %d in reply message\n", true },
		{ RESULT_BADID, "- mismatched ID %d in reply message\n", true },
		{ RESULT_BADSTATUS,
			"- bad or unexpected status %d in reply message\n", true },
		{ RESULT_TRUNC, "- result size not as expected (%u bytes left)\n",
			true },
		{ RESULT_CORRUPT, "- buffer has been modified erroneously\n",
			false },
		{ RESULT_MISSING, "- buffer has been left untouched erroneously\n",
			false },
		{ RESULT_OVERFLOW, "- area around target buffer modified\n",
			false },
		{ RESULT_BADVALUE,
			"- bad or unexpected return value %d from call\n", true },
	};

	const failure_detail_t *found_detail = NULL;
	for (size_t i = 0; i < sizeof(details) / sizeof(details[0]); ++i) {
		if (details[i].type == res->type) {
			found_detail = &details[i];
			break;
		}
	}

	if (found_detail != NULL) {
		if (found_detail->uses_value) {
			output(found_detail->format, res->value);
		} else {
			output(found_detail->format);
		}
	} else {
		output("- unknown error type %d\n", res->type);
	}
}

static void test_group(const char *name, int exec)
{
	if (exec) {
		output("Test group: %s\n", name);
	} else {
		output("Test group: %s (skipping)\n", name);
	}

	group_failure = FALSE;
}

static void reopen_device(dev_t minor)
{
	const int access_flags = BDEV_R_BIT | (may_write ? BDEV_W_BIT : 0);

	message m = {
		.m_type = BDEV_OPEN,
		.m_lbdev_lblockdriver_msg.minor = minor,
		.m_lbdev_lblockdriver_msg.access = access_flags,
	};

	(void)ipc_sendrec(driver_endpt, &m);
}

static void recover_driver(void)
{
	endpoint_t last_endpt;
	int r;

	output("WARNING: driver has died, attempting to proceed\n");

	driver_deaths++;

	last_endpt = driver_endpt;
	do {
		r = ds_retrieve_label_endpt(driver_label, &driver_endpt);
		if (r != OK || last_endpt == driver_endpt) {
			micro_delay(100000);
		}
	} while (r != OK || last_endpt == driver_endpt);

	for (int i = 0; i < nr_opened; i++) {
		reopen_device(opened[i]);
	}
}

static int sendrec_driver(message *m_ptr, ssize_t exp, result_t *res)
{
	const message m_orig = *m_ptr;
	int r;

	r = ipc_sendrec(driver_endpt, m_ptr);

	if (r == EDEADSRCDST) {
		recover_driver();
		return set_result(res, RESULT_DEATH, 0);
	}

	if (r != OK) {
		return set_result(res, RESULT_COMMFAIL, r);
	}

	const int reply_id = m_ptr->m_lblockdriver_lbdev_reply.id;
	const int reply_status = m_ptr->m_lblockdriver_lbdev_reply.status;

	if (m_ptr->m_type != BDEV_REPLY) {
		return set_result(res, RESULT_BADTYPE, m_ptr->m_type);
	}

	if (reply_id != m_orig.m_lbdev_lblockdriver_msg.id) {
		return set_result(res, RESULT_BADID, reply_id);
	}

	if ((exp < 0) != (reply_status < 0)) {
		return set_result(res, RESULT_BADSTATUS, reply_status);
	}

	return set_result(res, RESULT_OK, 0);
}

static void raw_xfer(dev_t minor, u64_t pos, iovec_s_t *iovec, int nr_req,
	int write, ssize_t exp, result_t *res)
{
	cp_grant_id_t grant;
	message m;
	int r;
	int revoke_status;
	ssize_t status;

	assert(nr_req <= NR_IOREQS);
	assert(!write || may_write);

	grant = cpf_grant_direct(driver_endpt, (vir_bytes) iovec,
		sizeof(*iovec) * nr_req, CPF_READ);
	if (grant == GRANT_INVALID) {
		set_result(res, RESULT_FAILURE, EIO);
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
	revoke_status = cpf_revoke(grant);

	if (r != RESULT_OK) {
		return;
	}

	if (revoke_status == -1) {
		set_result(res, RESULT_FAILURE, EIO);
		return;
	}

	status = m.m_lblockdriver_lbdev_reply.status;
	if (status == exp) {
		return;
	}

	if (exp < 0) {
		set_result(res, RESULT_BADSTATUS, status);
	} else {
		set_result(res, RESULT_TRUNC, exp - status);
	}
}

static void vir_xfer(dev_t minor, u64_t pos, iovec_t *iovec, int nr_req,
	int write, ssize_t exp, result_t *res)
{
	iovec_s_t iov_s[NR_IOREQS];

	assert(nr_req <= NR_IOREQS);

	const int grant_flags = write ? CPF_READ : CPF_WRITE;

	for (int i = 0; i < nr_req; i++) {
		iov_s[i].iov_size = iovec[i].iov_size;
		iov_s[i].iov_grant = cpf_grant_direct(driver_endpt,
			(vir_bytes) iovec[i].iov_addr, iovec[i].iov_size,
			grant_flags);

		if (iov_s[i].iov_grant == GRANT_INVALID) {
			for (int j = 0; j < i; j++) {
				(void)cpf_revoke(iov_s[j].iov_grant);
			}
			res->res_errno = ENOMEM;
			res->res_nbytes = 0;
			return;
		}
	}

	raw_xfer(minor, pos, iov_s, nr_req, write, exp, res);

	for (int i = 0; i < nr_req; i++) {
		iovec[i].iov_size = iov_s[i].iov_size;
		(void)cpf_revoke(iov_s[i].iov_grant);
	}
}

static void simple_xfer(dev_t minor, u64_t pos, u8_t *buf, size_t size,
	int write, ssize_t exp, result_t *res)
{
	vir_xfer(minor, pos, &(iovec_t){
		.iov_addr = (vir_bytes)buf,
		.iov_size = size
	}, 1, write, exp, res);
}

static int alloc_buf_and_grant(u8_t **ptr, cp_grant_id_t *grant,
	size_t size, int perms)
{
	u8_t *dma_buf;
	cp_grant_id_t new_grant;

	dma_buf = alloc_dma_memory(size);
	if (dma_buf == NULL) {
		return -1;
	}

	new_grant = cpf_grant_direct(driver_endpt, (vir_bytes)dma_buf, size,
		perms);
	if (new_grant == GRANT_INVALID) {
		free_dma_memory(dma_buf);
		return -1;
	}

	*ptr = dma_buf;
	*grant = new_grant;

	return 0;
}

static void free_buf_and_grant(u8_t *ptr, cp_grant_id_t grant, size_t size)
{
	cpf_revoke(grant);

	if (ptr != NULL) {
		free_dma_memory(ptr, size);
	}
}

static cp_grant_id_t create_grant_or_panic(endpoint_t endpt, vir_bytes addr,
					   size_t size, int perms)
{
	const cp_grant_id_t grant = cpf_grant_direct(endpt, addr, size, perms);

	if (grant == GRANT_INVALID)
		panic("unable to allocate grant");

	return grant;
}

static void check_normal_read_status(result_t *res, const message *m,
				     size_t expected_size)
{
	if (res->type == RESULT_OK &&
	    m->m_lblockdriver_lbdev_reply.status != (ssize_t)expected_size) {
		res->type = RESULT_TRUNC;
		res->value = m->m_lblockdriver_lbdev_reply.status;
	}
}

static void bad_read1(void)
{
	message msg_template, m;
	iovec_s_t iov_template, iov;
	cp_grant_id_t iov_grant, data_grant;
	u8_t *buf_ptr;
	result_t res;
	static const vir_bytes buf_size = 4096;

	test_group("bad read requests, part one", TRUE);

	alloc_buf_and_grant(&buf_ptr, &data_grant, buf_size, CPF_WRITE);

	iov_grant = create_grant_or_panic(driver_endpt, (vir_bytes)&iov,
		sizeof(iov), CPF_READ);

	memset(&iov_template, 0, sizeof(iov_template));
	iov_template.iov_grant = data_grant;
	iov_template.iov_size = buf_size;

	memset(&msg_template, 0, sizeof(msg_template));
	m_lbdev_lblockdriver_msg_t * const p = &msg_template.m_lbdev_lblockdriver_msg;
	msg_template.m_type = BDEV_GATHER;
	p->minor = driver_minor;
	p->pos = 0LL;
	p->count = 1;
	p->grant = iov_grant;
	p->id = lrand48();

	/* Test normal request. */
	m = msg_template;
	iov = iov_template;
	sendrec_driver(&m, OK, &res);
	check_normal_read_status(&res, &m, iov.iov_size);
	got_result(&res, "normal request");

	/* Test zero iovec elements. */
	m = msg_template;
	m.m_lbdev_lblockdriver_msg.count = 0;
	sendrec_driver(&m, EINVAL, &res);
	got_result(&res, "zero iovec elements");

	/* Test bad iovec grant. */
	m = msg_template;
	m.m_lbdev_lblockdriver_msg.grant = GRANT_INVALID;
	sendrec_driver(&m, EINVAL, &res);
	got_result(&res, "bad iovec grant");

	/* Test revoked iovec grant. */
	cp_grant_id_t revoked_grant = create_grant_or_panic(driver_endpt,
		(vir_bytes)&iov, sizeof(iov), CPF_READ);
	cpf_revoke(revoked_grant);
	m = msg_template;
	iov = iov_template;
	m.m_lbdev_lblockdriver_msg.grant = revoked_grant;
	sendrec_driver(&m, EINVAL, &res);
	accept_result(&res, RESULT_BADSTATUS, EPERM);
	got_result(&res, "revoked iovec grant");

	/* Test normal request (final check). */
	m = msg_template;
	iov = iov_template;
	sendrec_driver(&m, OK, &res);
	check_normal_read_status(&res, &m, iov.iov_size);
	got_result(&res, "normal request");

	/* Clean up. */
	free_buf_and_grant(buf_ptr, data_grant, buf_size);
	cpf_revoke(iov_grant);
}

static u32_t get_sum(const u8_t *ptr, size_t size)
{
    if (ptr == NULL) {
        return 0;
    }

    u32_t sum = 0;
    for (size_t i = 0; i < size; ++i) {
        sum = sum ^ (sum << 5) ^ ptr[i];
    }

    return sum;
}

static u32_t fill_rand(u8_t *ptr, size_t size)
{
	if (!ptr) {
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
	if (!res || res->type != RESULT_OK) {
		return;
	}

	const u32_t actual_sum = get_sum(ptr, size);

	if (should_match) {
		if (sum != actual_sum) {
			res->type = RESULT_CORRUPT;
			res->value = 0;
		}
	} else {
		if (sum == actual_sum) {
			res->type = RESULT_MISSING;
			res->value = 0;
		}
	}
}

#include <limits.h>

#define IOV_COUNT 3

typedef struct {
	u8_t *ptr;
	cp_grant_id_t grant;
	size_t size;
	u32_t sum;
} buffer_info_t;

static void setup_buffers(buffer_info_t bufs[IOV_COUNT])
{
	for (int i = 0; i < IOV_COUNT; i++) {
		bufs[i].size = BUF_SIZE;
		alloc_buf_and_grant(&bufs[i].ptr, &bufs[i].grant, bufs[i].size,
			CPF_WRITE);
	}
}

static void cleanup_buffers(buffer_info_t bufs[IOV_COUNT])
{
	for (int i = IOV_COUNT - 1; i >= 0; i--) {
		free_buf_and_grant(bufs[i].ptr, bufs[i].grant, bufs[i].size);
	}
}

static void fill_all_buffers(buffer_info_t bufs[IOV_COUNT])
{
	for (int i = 0; i < IOV_COUNT; i++) {
		bufs[i].sum = fill_rand(bufs[i].ptr, bufs[i].size);
	}
}

static void verify_all_sums(buffer_info_t bufs[IOV_COUNT], bool unchanged,
	result_t *res)
{
	for (int i = 0; i < IOV_COUNT; i++) {
		test_sum(bufs[i].ptr, bufs[i].size, bufs[i].sum, unchanged,
			res);
	}
}

static void run_simple_failure_test(const iovec_s_t iov[IOV_COUNT],
	buffer_info_t bufs[IOV_COUNT], const char *test_name)
{
	result_t res;
	raw_xfer(driver_minor, 0ULL, iov, IOV_COUNT, FALSE, EINVAL, &res);
	verify_all_sums(bufs, TRUE, &res);
	got_result(&res, test_name);
}

static void run_grant_failure_test(const iovec_s_t iov[IOV_COUNT],
	buffer_info_t bufs[IOV_COUNT], int expected_status, const char *test_name)
{
	result_t res;

	fill_all_buffers(bufs);
	raw_xfer(driver_minor, 0ULL, iov, IOV_COUNT, FALSE, EINVAL, &res);

	accept_result(&res, RESULT_BADSTATUS, expected_status);

	test_sum(bufs[1].ptr, bufs[1].size, bufs[1].sum, TRUE, &res);
	test_sum(bufs[2].ptr, bufs[2].size, bufs[2].sum, TRUE, &res);
	got_result(&res, test_name);
}

static void bad_read2(void)
{
	buffer_info_t bufs[IOV_COUNT];
	iovec_s_t iovt[IOV_COUNT], iov[IOV_COUNT];
	result_t res;

	test_group("bad read requests, part two", TRUE);

	setup_buffers(bufs);

	for (int i = 0; i < IOV_COUNT; i++) {
		iovt[i].iov_grant = bufs[i].grant;
		iovt[i].iov_size = bufs[i].size;
	}

	memcpy(iov, iovt, sizeof(iovt));
	fill_all_buffers(bufs);
	raw_xfer(driver_minor, 0ULL, iov, IOV_COUNT, FALSE, BUF_SIZE * IOV_COUNT, &res);
	verify_all_sums(bufs, FALSE, &res);
	got_result(&res, "normal vector request");

	memcpy(iov, iovt, sizeof(iovt));
	iov[1].iov_size = 0;
	fill_all_buffers(bufs);
	run_simple_failure_test(iov, bufs, "zero size in iovec element");

	memcpy(iov, iovt, sizeof(iovt));
	iov[1].iov_size = (vir_bytes)LONG_MAX + 1;
	run_simple_failure_test(iov, bufs, "negative size in iovec element");

	memcpy(iov, iovt, sizeof(iovt));
	iov[0].iov_size = LONG_MAX / 2 - 1;
	iov[1].iov_size = LONG_MAX / 2 - 1;
	run_simple_failure_test(iov, bufs, "negative total size");

	memcpy(iov, iovt, sizeof(iovt));
	iov[0].iov_size = LONG_MAX - 1;
	iov[1].iov_size = LONG_MAX - 1;
	run_simple_failure_test(iov, bufs, "wrapping total size");

	{
		memcpy(iov, iovt, sizeof(iovt));
		iov[1].iov_size--;
		fill_all_buffers(bufs);
		const u8_t c1 = bufs[1].ptr[bufs[1].size - 1];

		raw_xfer(driver_minor, 0ULL, iov, IOV_COUNT, FALSE,
			BUF_SIZE * IOV_COUNT - 1, &res);

		if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
			test_sum(bufs[1].ptr, bufs[1].size, bufs[1].sum, TRUE, &res);
			test_sum(bufs[2].ptr, bufs[2].size, bufs[2].sum, TRUE, &res);
		} else {
			verify_all_sums(bufs, FALSE, &res);
			if (c1 != bufs[1].ptr[bufs[1].size - 1])
				set_result(&res, RESULT_CORRUPT, 0);
		}
		got_result(&res, "word-unaligned size in iovec element");
	}

	memcpy(iov, iovt, sizeof(iovt));
	iov[1].iov_grant = GRANT_INVALID;
	run_grant_failure_test(iov, bufs, EINVAL, "invalid grant in iovec element");

	{
		cp_grant_id_t grant;
		memcpy(iov, iovt, sizeof(iovt));
		grant = cpf_grant_direct(driver_endpt, (vir_bytes)bufs[1].ptr, bufs[1].size, CPF_WRITE);
		if (grant == GRANT_INVALID)
			panic("unable to allocate grant");
		cpf_revoke(grant);
		iov[1].iov_grant = grant;

		run_grant_failure_test(iov, bufs, EPERM, "revoked grant in iovec element");
	}

	{
		cp_grant_id_t grant;
		memcpy(iov, iovt, sizeof(iovt));
		grant = cpf_grant_direct(driver_endpt, (vir_bytes)bufs[1].ptr, bufs[1].size, CPF_READ);
		if (grant == GRANT_INVALID)
			panic("unable to allocate grant");
		iov[1].iov_grant = grant;

		run_grant_failure_test(iov, bufs, EPERM, "read-only grant in iovec element");
		cpf_revoke(grant);
	}

	{
		cp_grant_id_t grant;
		memcpy(iov, iovt, sizeof(iovt));
		grant = cpf_grant_direct(driver_endpt, (vir_bytes)(bufs[1].ptr + 1), bufs[1].size - 2, CPF_WRITE);
		if (grant == GRANT_INVALID)
			panic("unable to allocate grant");

		iov[1].iov_grant = grant;
		iov[1].iov_size = bufs[1].size - 2;

		fill_all_buffers(bufs);
		const u8_t c1 = bufs[1].ptr[0];
		const u8_t c2 = bufs[1].ptr[bufs[1].size - 1];

		raw_xfer(driver_minor, 0ULL, iov, IOV_COUNT, FALSE, BUF_SIZE * IOV_COUNT - 2, &res);

		if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
			test_sum(bufs[1].ptr, bufs[1].size, bufs[1].sum, TRUE, &res);
			test_sum(bufs[2].ptr, bufs[2].size, bufs[2].sum, TRUE, &res);
		} else {
			verify_all_sums(bufs, FALSE, &res);
			if (c1 != bufs[1].ptr[0] || c2 != bufs[1].ptr[bufs[1].size - 1])
				set_result(&res, RESULT_CORRUPT, 0);
		}
		got_result(&res, "word-unaligned buffer in iovec element");
		cpf_revoke(grant);
	}

	if (min_read > 1) {
		memcpy(iov, iovt, sizeof(iovt));
		fill_all_buffers(bufs);
		raw_xfer(driver_minor, 1ULL, iov, IOV_COUNT, FALSE, EINVAL, &res);
		verify_all_sums(bufs, TRUE, &res);
		got_result(&res, "word-unaligned position");
	}

	memcpy(iov, iovt, sizeof(iovt));
	fill_all_buffers(bufs);
	raw_xfer(driver_minor, 0ULL, iov, IOV_COUNT, FALSE, BUF_SIZE * IOV_COUNT, &res);
	verify_all_sums(bufs, FALSE, &res);
	got_result(&res, "normal vector request");

	cleanup_buffers(bufs);
}

static void bad_write(void)
{
	/* Test various illegal write transfer requests, if writing is allowed.
	 * If handled correctly, these requests will not actually write data.
	 * This part of the test set is in need of further expansion.
	 */
#define NUM_BUFS 3
	u8_t *buffers[NUM_BUFS];
	cp_grant_id_t grants[NUM_BUFS];
	u32_t sums[NUM_BUFS];
	iovec_s_t iov_template[NUM_BUFS], iov[NUM_BUFS];
	result_t res;
	int i;

	test_group("bad write requests", may_write);

	if (!may_write)
		return;

	for (i = 0; i < NUM_BUFS; i++) {
		alloc_buf_and_grant(&buffers[i], &grants[i], BUF_SIZE,
			CPF_READ);
		iov_template[i].iov_grant = grants[i];
		iov_template[i].iov_size = BUF_SIZE;
	}

	/* Only perform write alignment tests if writes require alignment. */
	if (min_write == 0)
		min_write = sector_size;

	if (min_write > 1) {
		size_t sector_unalign = (min_write > 2) ? 2 : 1;

		/* Test sector-unaligned write position. */
		memcpy(iov, iov_template, sizeof(iov_template));

		for (i = 0; i < NUM_BUFS; i++)
			sums[i] = fill_rand(buffers[i], BUF_SIZE);

		raw_xfer(driver_minor, (u64_t)sector_unalign, iov, NUM_BUFS,
			TRUE, EINVAL, &res);

		for (i = 0; i < NUM_BUFS; i++)
			test_sum(buffers[i], BUF_SIZE, sums[i], TRUE, &res);

		got_result(&res, "sector-unaligned write position");

		/* Test sector-unaligned write size. */
		memcpy(iov, iov_template, sizeof(iov_template));
		iov[1].iov_size -= sector_unalign;

		for (i = 0; i < NUM_BUFS; i++)
			sums[i] = fill_rand(buffers[i], BUF_SIZE);

		raw_xfer(driver_minor, 0ULL, iov, NUM_BUFS, TRUE, EINVAL,
			&res);

		for (i = 0; i < NUM_BUFS; i++)
			test_sum(buffers[i], BUF_SIZE, sums[i], TRUE, &res);

		got_result(&res, "sector-unaligned write size");
	}

	/* Test write-only grant in iovec element. */
	memcpy(iov, iov_template, sizeof(iov_template));
	cp_grant_id_t grant = cpf_grant_direct(driver_endpt,
		(vir_bytes)buffers[1], BUF_SIZE, CPF_WRITE);
	if (grant == GRANT_INVALID)
		panic("unable to allocate grant");

	iov[1].iov_grant = grant;

	for (i = 0; i < NUM_BUFS; i++)
		sums[i] = fill_rand(buffers[i], BUF_SIZE);

	raw_xfer(driver_minor, 0ULL, iov, NUM_BUFS, TRUE, EINVAL, &res);

	accept_result(&res, RESULT_BADSTATUS, EPERM);

	for (i = 0; i < NUM_BUFS; i++)
		test_sum(buffers[i], BUF_SIZE, sums[i], TRUE, &res);

	got_result(&res, "write-only grant in iovec element");

	cpf_revoke(grant);

	/* Clean up. */
	for (i = NUM_BUFS - 1; i >= 0; i--)
		free_buf_and_grant(buffers[i], grants[i], BUF_SIZE);
}

static const u32_t LARGE_BUF_GUARD_START = 0xCAFEBABEL;
static const u32_t LARGE_BUF_GUARD_END   = 0xDECAFBADL;
static const u32_t SMALL_CHUNK_GUARD_PRE = 0xDEADBEEFL;
static const u32_t SMALL_CHUNK_GUARD_POST= 0xFEEDFACEL;

static void vector_and_large_sub(size_t small_size)
{
	const size_t large_size = small_size * NR_IOREQS;
	const size_t large_buf_size = large_size + sizeof(u32_t) * 2;
	const size_t small_chunks_buf_size = large_size + sizeof(u32_t) * (NR_IOREQS + 1);
	const size_t small_chunk_stride = small_size + sizeof(u32_t);
	const u64_t base_pos = (u64_t)sector_size;

	u8_t *large_buf = NULL;
	u8_t *small_chunks_buf = NULL;
	iovec_t iovec[NR_IOREQS];
	result_t res;
	int i;

	large_buf = alloc_dma_memory(large_buf_size);
	small_chunks_buf = alloc_dma_memory(small_chunks_buf_size);
	if (large_buf == NULL || small_chunks_buf == NULL) {
		set_result(&res, RESULT_FATAL, "DMA memory allocation failed");
		got_result(&res, "setup");
		goto cleanup;
	}

	u8_t * const large_data = large_buf + sizeof(u32_t);

	if (may_write) {
		fill_rand(large_buf, large_buf_size);
		iovec[0].iov_addr = (vir_bytes)large_data;
		iovec[0].iov_size = large_size;
		vir_xfer(driver_minor, base_pos, iovec, 1, TRUE, large_size, &res);
		got_result(&res, "large write");
	}

	for (i = 0; i < NR_IOREQS; i++) {
		u8_t *chunk_data = small_chunks_buf + sizeof(u32_t) + i * small_chunk_stride;
		*(u32_t *)(chunk_data - sizeof(u32_t)) = SMALL_CHUNK_GUARD_PRE + i;
		iovec[i].iov_addr = (vir_bytes)chunk_data;
		iovec[i].iov_size = small_size;
	}
	*(u32_t *)(small_chunks_buf + NR_IOREQS * small_chunk_stride) = SMALL_CHUNK_GUARD_POST;

	vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, FALSE, large_size, &res);

	if (res.type == RESULT_OK) {
		for (i = 0; i < NR_IOREQS; i++) {
			u8_t *chunk_data = small_chunks_buf + sizeof(u32_t) + i * small_chunk_stride;
			if (*(u32_t *)(chunk_data - sizeof(u32_t)) != SMALL_CHUNK_GUARD_PRE + i)
				set_result(&res, RESULT_OVERFLOW, 0);
		}
		if (*(u32_t *)(small_chunks_buf + NR_IOREQS * small_chunk_stride) != SMALL_CHUNK_GUARD_POST)
			set_result(&res, RESULT_OVERFLOW, 0);
	}

	if (res.type == RESULT_OK && may_write) {
		for (i = 0; i < NR_IOREQS; i++) {
			u8_t *sub_chunk_in_large = large_data + i * small_size;
			u8_t *small_chunk = small_chunks_buf + sizeof(u32_t) + i * small_chunk_stride;
			test_sum(small_chunk, small_size, get_sum(sub_chunk_in_large, small_size), TRUE, &res);
		}
	}
	got_result(&res, "vectored read");

	if (may_write) {
		fill_rand(small_chunks_buf, small_chunks_buf_size);
		for (i = 0; i < NR_IOREQS; i++) {
			iovec[i].iov_addr = (vir_bytes)(small_chunks_buf + sizeof(u32_t) + i * small_chunk_stride);
			iovec[i].iov_size = small_size;
		}
		vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, TRUE, large_size, &res);
		got_result(&res, "vectored write");
	}

	*(u32_t *)large_buf = LARGE_BUF_GUARD_START;
	*(u32_t *)(large_data + large_size) = LARGE_BUF_GUARD_END;

	iovec[0].iov_addr = (vir_bytes)large_data;
	iovec[0].iov_size = large_size;
	vir_xfer(driver_minor, base_pos, iovec, 1, FALSE, large_size, &res);

	if (res.type == RESULT_OK) {
		if (*(u32_t *)large_buf != LARGE_BUF_GUARD_START)
			set_result(&res, RESULT_OVERFLOW, 0);
		if (*(u32_t *)(large_data + large_size) != LARGE_BUF_GUARD_END)
			set_result(&res, RESULT_OVERFLOW, 0);
	}

	if (res.type == RESULT_OK) {
		for (i = 0; i < NR_IOREQS; i++) {
			u8_t *sub_chunk_in_large = large_data + i * small_size;
			u8_t *small_chunk = small_chunks_buf + sizeof(u32_t) + i * small_chunk_stride;
			test_sum(small_chunk, small_size, get_sum(sub_chunk_in_large, small_size), TRUE, &res);
		}
	}
	got_result(&res, "large read");

cleanup:
	free_dma_memory(small_chunks_buf, small_chunks_buf_size);
	free_dma_memory(large_buf, large_buf_size);
}

static void vector_and_large(void)
{
	const size_t COMMON_BLOCK_SIZE = 4096;
	const size_t MARGIN_IN_SECTORS = 4;
	const size_t margin_bytes = sector_size * MARGIN_IN_SECTORS;

	if (part.size <= margin_bytes || NR_IOREQS == 0 || sector_size == 0) {
		return;
	}

	size_t available_size = part.size - margin_bytes;
	if (max_size > available_size) {
		max_size = available_size;
	}

	size_t max_block = (max_size / NR_IOREQS / sector_size) * sector_size;

	test_group("vector and large, common block", TRUE);
	vector_and_large_sub(COMMON_BLOCK_SIZE);

	if (max_block > 0 && max_block != COMMON_BLOCK_SIZE) {
		test_group("vector and large, large block", TRUE);
		vector_and_large_sub(max_block);
	}
}

static void open_device(dev_t minor)
{
	if (nr_opened >= NR_OPENED) {
		return;
	}

	message m;
	result_t res;
	const char *description;

	memset(&m, 0, sizeof(m));
	m.m_type = BDEV_OPEN;
	m.m_lbdev_lblockdriver_msg.minor = minor;
	m.m_lbdev_lblockdriver_msg.access = may_write ? (BDEV_R_BIT | BDEV_W_BIT) : BDEV_R_BIT;
	m.m_lbdev_lblockdriver_msg.id = lrand48();

	sendrec_driver(&m, OK, &res);

	description = (minor == driver_minor) ? "opening the main partition"
		: "opening a subpartition";

	got_result(&res, description);

	if (res == OK) {
		opened[nr_opened++] = minor;
	}
}

static void close_device(dev_t minor)
{
	result_t res;
	message m = {
		.m_type = BDEV_CLOSE,
		.m_lbdev_lblockdriver_msg = {
			.minor = minor,
			.id = lrand48()
		}
	};

	sendrec_driver(&m, OK, &res);

	assert(nr_opened > 0);
	for (int i = 0; i < nr_opened; i++) {
		if (opened[i] == minor) {
			opened[i] = opened[--nr_opened];
			break;
		}
	}

	const char *description = (minor == driver_minor)
		? "closing the main partition"
		: "closing a subpartition";
	got_result(&res, description);
}

static int vir_ioctl(dev_t minor, unsigned long req, void *ptr, ssize_t exp,
	result_t *res)
{
	if (_MINIX_IOCTL_BIG(req))
		return ENOTTY;

	int perm = 0;
	if (_MINIX_IOCTL_IOR(req)) perm |= CPF_WRITE;
	if (_MINIX_IOCTL_IOW(req)) perm |= CPF_READ;

	cp_grant_id_t grant = cpf_grant_direct(driver_endpt, (vir_bytes)ptr,
	    _MINIX_IOCTL_SIZE(req), perm);
	if (grant == GRANT_INVALID)
		return ENOMEM;

	message m = {
		.m_type = BDEV_IOCTL,
		.m_lbdev_lblockdriver_msg.minor = minor,
		.m_lbdev_lblockdriver_msg.request = req,
		.m_lbdev_lblockdriver_msg.grant = grant,
		.m_lbdev_lblockdriver_msg.user = NONE,
		.m_lbdev_lblockdriver_msg.id = lrand48()
	};

	int r = sendrec_driver(&m, exp, res);

	if (cpf_revoke(grant) != 0) {
		if (r == OK)
			r = EIO;
	}

	return r;
}

static void test_open_count(int expected_count, const char *description)
{
	result_t res;
	int openct = 0x0badcafe;

	vir_ioctl(driver_minor, DIOCOPENCT, &openct, OK, &res);

	if (res.type == RESULT_OK && openct != expected_count) {
		res.type = RESULT_BADVALUE;
		res.value = openct;
	}

	got_result(&res, description);
}

static void misc_ioctl(void)
{
	result_t res;

	test_group("test miscellaneous ioctls", TRUE);

	vir_ioctl(driver_minor, DIOCGETP, &part, OK, &res);
	got_result(&res, "ioctl to get partition");

	if (res.type == RESULT_OK && part.size < (u64_t)max_size * 2) {
		output("WARNING: small partition, some tests may fail\n");
	}

	test_open_count(1, "ioctl to get open count");

	open_device(driver_minor);
	test_open_count(2, "increased open count after opening");

	close_device(driver_minor);
	test_open_count(1, "decreased open count after closing");
}

#include <stddef.h>
#include <stdint.h>

typedef struct {
	u32_t last_sector;
	u32_t penultimate_two_sectors;
} partition_checksums_t;

static void establish_checksums_and_test_up_to_limit(dev_t minor, u64_t limit,
	u8_t *buf, size_t buf_size, partition_checksums_t *checksums)
{
	result_t res;

	fill_rand(buf, buf_size);
	simple_xfer(minor, limit - sector_size, buf, sector_size, FALSE,
		sector_size, &res);
	checksums->last_sector = get_sum(buf, sector_size);
	got_result(&res, "one sector read up to partition end");

	fill_rand(buf, buf_size);
	simple_xfer(minor, limit - buf_size, buf, buf_size, FALSE, buf_size,
		&res);
	test_sum(buf + sector_size * 2, sector_size, checksums->last_sector,
		TRUE, &res);
	checksums->penultimate_two_sectors = get_sum(buf, sector_size * 2);
	got_result(&res, "multisector read up to partition end");
}

static void test_read_across_limit(dev_t minor, u64_t limit, u8_t *buf,
	size_t buf_size, const partition_checksums_t *checksums)
{
	result_t res;
	u32_t expected_untouched_sum;

	fill_rand(buf, buf_size);
	expected_untouched_sum = get_sum(buf + sector_size * 2, sector_size);
	simple_xfer(minor, limit - sector_size * 2, buf, buf_size, FALSE,
		sector_size * 2, &res);
	test_sum(buf, sector_size * 2, checksums->penultimate_two_sectors,
		TRUE, &res);
	test_sum(buf + sector_size * 2, sector_size, expected_untouched_sum,
		TRUE, &res);
	got_result(&res, "read somewhat across partition end");

	fill_rand(buf, buf_size);
	expected_untouched_sum = get_sum(buf + sector_size, sector_size * 2);
	simple_xfer(minor, limit - sector_size, buf, buf_size, FALSE,
		sector_size, &res);
	test_sum(buf, sector_size, checksums->last_sector, TRUE, &res);
	test_sum(buf + sector_size, sector_size * 2, expected_untouched_sum,
		TRUE, &res);
	got_result(&res, "read mostly across partition end");
}

static void test_failed_reads(dev_t sub0_minor, dev_t sub1_minor, u64_t limit,
	u8_t *buf, size_t buf_size)
{
	result_t res;
	const u64_t way_beyond_offset = 0x1000000000000000ULL;

	const u32_t untouched_buffer_sum = fill_rand(buf, buf_size);
	const u32_t untouched_first_sector_sum = get_sum(buf, sector_size);

	simple_xfer(sub0_minor, limit, buf, sector_size, FALSE, 0, &res);
	test_sum(buf, sector_size, untouched_first_sector_sum, TRUE, &res);
	got_result(&res, "one sector read at partition end");

	simple_xfer(sub0_minor, limit, buf, buf_size, FALSE, 0, &res);
	test_sum(buf, buf_size, untouched_buffer_sum, TRUE, &res);
	got_result(&res, "multisector read at partition end");

	simple_xfer(sub0_minor, limit + sector_size, buf, buf_size, FALSE, 0,
		&res);
	test_sum(buf, sector_size, untouched_first_sector_sum, TRUE, &res);
	got_result(&res, "single sector read beyond partition end");

	simple_xfer(sub0_minor, way_beyond_offset, buf, buf_size, FALSE, 0,
		&res);
	test_sum(buf, buf_size, untouched_buffer_sum, TRUE, &res);
	got_result(&res, "multisector read way beyond partition end");

	const u64_t negative_offset = (u64_t)-1 - sector_size + 1;
	simple_xfer(sub1_minor, negative_offset, buf, sector_size, FALSE, 0,
		&res);
	test_sum(buf, sector_size, untouched_first_sector_sum, TRUE, &res);
	got_result(&res, "read with negative offset");
}

static void read_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size)
{
	test_group("read around subpartition limits", TRUE);

	const size_t buf_size = sector_size * 3;
	u8_t *buf_ptr = alloc_dma_memory(buf_size);
	if (buf_ptr == NULL) {
		return;
	}

	const u64_t partition_limit = (u64_t)sub_size;
	partition_checksums_t checksums;

	establish_checksums_and_test_up_to_limit(sub0_minor, partition_limit,
		buf_ptr, buf_size, &checksums);

	test_read_across_limit(sub0_minor, partition_limit, buf_ptr, buf_size,
		&checksums);

	test_failed_reads(sub0_minor, sub1_minor, partition_limit, buf_ptr,
		buf_size);

	free_dma_memory(buf_ptr, buf_size);
}

static u32_t prepare_sentinel_partition(dev_t sub1_minor, u8_t *buf,
    size_t buf_size)
{
	result_t res;
	const u32_t sum = fill_rand(buf, buf_size);

	simple_xfer(sub1_minor, 0ULL, buf, buf_size, TRUE, buf_size, &res);
	got_result(&res, "write to second subpartition");

	return sum;
}

static void test_write_and_read_edge(dev_t sub0_minor, u64_t sub_size_64,
    u8_t *buf)
{
	result_t res;
	const u64_t edge_offset = sub_size_64 - sector_size;
	const u32_t sum = fill_rand(buf, sector_size);

	simple_xfer(sub0_minor, edge_offset, buf, sector_size, TRUE, sector_size,
	    &res);
	got_result(&res, "write up to partition end");

	const u64_t read_offset = sub_size_64 - sector_size * 2;
	fill_rand(buf, sector_size * 2);
	simple_xfer(sub0_minor, read_offset, buf, sector_size * 2, FALSE,
	    sector_size * 2, &res);
	test_sum(buf + sector_size, sector_size, sum, TRUE, &res);
	got_result(&res, "read up to partition end");
}

static u32_t perform_straddle_tests(dev_t sub0_minor, u64_t sub_size_64,
    u8_t *buf, size_t buf_size)
{
	result_t res;
	u32_t read_sum;

	fill_rand(buf, buf_size);
	const u32_t second_last_sector_sum = get_sum(buf, sector_size);
	const u32_t pre_swap_last_sector_sum = get_sum(buf + sector_size,
	    sector_size);

	simple_xfer(sub0_minor, sub_size_64 - sector_size * 2, buf,
	    buf_size, TRUE, sector_size * 2, &res);
	got_result(&res, "write somewhat across partition end");

	fill_rand(buf, buf_size);
	read_sum = get_sum(buf + sector_size, sector_size * 2);

	simple_xfer(sub0_minor, sub_size_64 - sector_size, buf, buf_size,
	    FALSE, sector_size, &res);
	test_sum(buf, sector_size, pre_swap_last_sector_sum, TRUE, &res);
	test_sum(buf + sector_size, sector_size * 2, read_sum, TRUE, &res);
	got_result(&res, "read mostly across partition end");

	fill_rand(buf, buf_size);
	const u32_t final_last_sector_sum = get_sum(buf, sector_size);

	simple_xfer(sub0_minor, sub_size_64 - sector_size, buf, buf_size,
	    TRUE, sector_size, &res);
	got_result(&res, "write mostly across partition end");

	fill_rand(buf, buf_size);
	read_sum = get_sum(buf + sector_size * 2, sector_size);

	simple_xfer(sub0_minor, sub_size_64 - sector_size * 2, buf,
	    buf_size, FALSE, sector_size * 2, &res);
	test_sum(buf, sector_size, second_last_sector_sum, TRUE, &res);
	test_sum(buf + sector_size, sector_size, final_last_sector_sum, TRUE,
	    &res);
	test_sum(buf + sector_size * 2, sector_size, read_sum, TRUE, &res);
	got_result(&res, "read somewhat across partition end");

	return final_last_sector_sum;
}

static void test_invalid_writes_and_verify_integrity(dev_t sub0_minor,
    dev_t sub1_minor, u64_t sub_size_64, u8_t *buf, size_t buf_size,
    u32_t sub1_sum, u32_t last_sector_sum)
{
	result_t res;

	fill_rand(buf, sector_size);
	simple_xfer(sub0_minor, sub_size_64, buf, sector_size, TRUE, 0, &res);
	got_result(&res, "write at partition end");

	simple_xfer(sub0_minor, sub_size_64 + sector_size, buf, sector_size,
	    TRUE, 0, &res);
	got_result(&res, "write beyond partition end");

	simple_xfer(sub1_minor, (u64_t)-sector_size, buf, sector_size,
	    TRUE, 0, &res);
	got_result(&res, "write with negative offset");

	fill_rand(buf, buf_size);
	simple_xfer(sub1_minor, 0ULL, buf, buf_size, FALSE, buf_size, &res);
	test_sum(buf, buf_size, sub1_sum, TRUE, &res);
	got_result(&res, "read from second subpartition");

	simple_xfer(sub0_minor, sub_size_64 - sector_size, buf, sector_size,
	    FALSE, sector_size, &res);
	test_sum(buf, sector_size, last_sector_sum, TRUE, &res);
	got_result(&res, "read up to partition end");
}

static void write_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size)
{
	test_group("write around subpartition limits", may_write);
	if (!may_write)
		return;

	const size_t num_buf_sectors = 3;
	const size_t buf_size = sector_size * num_buf_sectors;
	u8_t *buf = alloc_dma_memory(buf_size);

	if (buf == NULL) {
		test_result(RESULT_FATAL, "Failed to allocate DMA memory");
		return;
	}

	const u64_t sub_size_64 = (u64_t)sub_size;

	const u32_t sub1_sum = prepare_sentinel_partition(sub1_minor, buf,
	    buf_size);
	test_write_and_read_edge(sub0_minor, sub_size_64, buf);
	const u32_t last_sector_sum = perform_straddle_tests(sub0_minor,
	    sub_size_64, buf, buf_size);
	test_invalid_writes_and_verify_integrity(sub0_minor, sub1_minor,
	    sub_size_64, buf, buf_size, sub1_sum, last_sector_sum);

	free_dma_memory(buf, buf_size);
}

static void test_set_get_subpartition(dev_t minor_dev,
    const struct part_geom *geom_to_set, const char *set_desc,
    const char *get_desc)
{
	struct part_geom retrieved_geom;
	result_t res;

	vir_ioctl(minor_dev, DIOCSETP, geom_to_set, OK, &res);
	got_result(&res, set_desc);

	vir_ioctl(minor_dev, DIOCGETP, &retrieved_geom, OK, &res);

	if (res.type == RESULT_OK &&
	    (geom_to_set->base != retrieved_geom.base ||
	     geom_to_set->size != retrieved_geom.size)) {
		res.type = RESULT_BADVALUE;
		res.value = 0;
	}
	got_result(&res, get_desc);
}

static void vir_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
	struct part_geom subpart;
	size_t sub_size;

	test_group("virtual subpartition limits", TRUE);

	open_device(sub0_minor);
	open_device(sub1_minor);

	sub_size = sector_size * part_secs;

	/* Set and check the first subpartition. */
	subpart = part;
	subpart.size = (u64_t)sub_size;
	test_set_get_subpartition(sub0_minor, &subpart,
	    "ioctl to set first subpartition",
	    "ioctl to get first subpartition");

	/* Set and check the second subpartition. */
	subpart.base += sub_size;
	test_set_get_subpartition(sub1_minor, &subpart,
	    "ioctl to set second subpartition",
	    "ioctl to get second subpartition");

	/* Perform the actual I/O tests. */
	read_limits(sub0_minor, sub1_minor, sub_size);
	write_limits(sub0_minor, sub1_minor, sub_size);

	/* Clean up. */
	close_device(sub1_minor);
	close_device(sub0_minor);
}

#define MBR_SIGNATURE_OFFSET 510
#define MBR_SIGNATURE_B0 0x55
#define MBR_SIGNATURE_B1 0xAA

static void reread_partition_table(dev_t minor)
{
	close_device(minor);
	open_device(minor);
}

static void check_zero_subpartition(dev_t minor, const char *desc)
{
	struct part_geom subpart;
	result_t res;

	vir_ioctl(minor, DIOCGETP, &subpart, 0, &res);

	if (res.type == RESULT_OK && subpart.size != 0) {
		res.type = RESULT_BADVALUE;
		res.value = ex64lo(subpart.size);
	}

	got_result(&res, desc);
}

static void check_valid_subpartition(dev_t minor, u64_t expected_base,
	u64_t expected_size, const char *desc)
{
	struct part_geom subpart;
	result_t res;

	vir_ioctl(minor, DIOCGETP, &subpart, 0, &res);

	if (res.type == RESULT_OK &&
		(subpart.base != expected_base || subpart.size != expected_size)) {
		res.type = RESULT_BADVALUE;
		res.value = 0;
	}

	got_result(&res, desc);
}

static void real_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
	u8_t *buf_ptr;
	size_t buf_size;
	struct part_entry *entry;
	result_t res;
	const u64_t sub_size = (u64_t)sector_size * part_secs;

	test_group("real subpartition limits", may_write);

	if (!may_write) {
		return;
	}

	buf_size = sector_size;
	buf_ptr = alloc_dma_memory(buf_size);
	if (buf_ptr == NULL) {
		res.type = RESULT_NOMEM;
		res.value = buf_size;
		got_result(&res, "allocating DMA memory");
		return;
	}

	memset(buf_ptr, 0, buf_size);
	simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
	got_result(&res, "write of invalid partition table");

	reread_partition_table(driver_minor);

	open_device(sub0_minor);
	open_device(sub1_minor);
	check_zero_subpartition(sub0_minor, "ioctl to get first subpartition");
	check_zero_subpartition(sub1_minor, "ioctl to get second subpartition");
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

	buf_ptr[MBR_SIGNATURE_OFFSET] = MBR_SIGNATURE_B0;
	buf_ptr[MBR_SIGNATURE_OFFSET + 1] = MBR_SIGNATURE_B1;

	simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
	got_result(&res, "write of valid partition table");

	reread_partition_table(driver_minor);

	open_device(sub0_minor);
	open_device(sub1_minor);

	const u64_t expected_size = (u64_t)part_secs * sector_size;
	const u64_t expected_base0 = part.base + sector_size;
	check_valid_subpartition(sub0_minor, expected_base0, expected_size,
		"ioctl to get first subpartition");

	const u64_t expected_base1 =
		part.base + (1 + (u64_t)part_secs) * sector_size;
	check_valid_subpartition(sub1_minor, expected_base1, expected_size,
		"ioctl to get second subpartition");

	read_limits(sub0_minor, sub1_minor, sub_size);
	write_limits(sub0_minor, sub1_minor, sub_size);

	close_device(sub0_minor);
	close_device(sub1_minor);

	free_dma_memory(buf_ptr, buf_size);
}

static dev_t get_first_subpartition_minor(dev_t minor)
{
	const dev_t partition_on_drive = minor % DEV_PER_DRIVE;

	if (partition_on_drive > 0) {
		const dev_t drive_nr = minor / DEV_PER_DRIVE;
		const dev_t primary_part_idx = partition_on_drive - 1;
		const dev_t base_part_idx = drive_nr * NR_PARTITIONS + primary_part_idx;
		return MINOR_d0p0s0 + base_part_idx * NR_PARTITIONS;
	}

	return minor + 1;
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

	const unsigned int part_secs = 9;
	vir_limits(sub0_minor, sub1_minor, part_secs);
	real_limits(sub0_minor, sub1_minor, part_secs - 1);
}

static void unaligned_size_io(u64_t base_pos, u8_t *buf_ptr, size_t buf_size,
	u8_t *sec_ptr[2], int sectors, int pattern, u32_t ssum[5])
{
	assert(sectors <= 4);

	iovec_t iov[3], iov_template[3];
	u32_t rsum[3] = {0};
	result_t res;
	int nr_req;

	base_pos += sector_size;
	const size_t total_size = sector_size * sectors;

	if (sector_size / element_size == 2 && sectors == 1 && pattern == 2) {
		return;
	}

	fill_rand(sec_ptr[0], sector_size);
	rsum[0] =
		get_sum(sec_ptr[0] + element_size, sector_size - element_size);

	fill_rand(buf_ptr, buf_size);

	switch (pattern) {
	case 0: {
		const size_t large_size = total_size - element_size;
		iov_template[0] = (iovec_t){ .iov_addr = (vir_bytes)sec_ptr[0], .iov_size = element_size };
		iov_template[1] = (iovec_t){ .iov_addr = (vir_bytes)buf_ptr, .iov_size = large_size };
		rsum[1] = get_sum(buf_ptr + large_size, element_size);
		nr_req = 2;
		break;
	}
	case 1: {
		const size_t large_size = total_size - element_size;
		iov_template[0] = (iovec_t){ .iov_addr = (vir_bytes)buf_ptr, .iov_size = large_size };
		iov_template[1] = (iovec_t){ .iov_addr = (vir_bytes)sec_ptr[0], .iov_size = element_size };
		rsum[1] = get_sum(buf_ptr + large_size, element_size);
		nr_req = 2;
		break;
	}
	case 2: {
		const size_t medium_size = total_size - 2 * element_size;
		iov_template[0] = (iovec_t){ .iov_addr = (vir_bytes)sec_ptr[0], .iov_size = element_size };
		iov_template[1] = (iovec_t){ .iov_addr = (vir_bytes)buf_ptr, .iov_size = medium_size };
		fill_rand(sec_ptr[1], sector_size);
		iov_template[2] = (iovec_t){ .iov_addr = (vir_bytes)sec_ptr[1], .iov_size = element_size };
		rsum[1] = get_sum(buf_ptr + medium_size, 2 * element_size);
		rsum[2] = get_sum(sec_ptr[1] + element_size, sector_size - element_size);
		nr_req = 3;
		break;
	}
	default:
		assert(0 && "Invalid pattern");
		return;
	}

	memcpy(iov, iov_template, sizeof(iov));
	vir_xfer(driver_minor, base_pos, iov, nr_req, FALSE, total_size, &res);

	test_sum(sec_ptr[0] + element_size, sector_size - element_size,
		rsum[0], TRUE, &res);

	switch (pattern) {
	case 0: {
		const size_t buf_part_size = total_size - element_size;
		test_sum(buf_ptr + buf_part_size, element_size, rsum[1], TRUE, &res);
		memmove(buf_ptr + element_size, buf_ptr, buf_part_size);
		memcpy(buf_ptr, sec_ptr[0], element_size);
		break;
	}
	case 1: {
		const size_t buf_part_size = total_size - element_size;
		test_sum(buf_ptr + buf_part_size, element_size, rsum[1], TRUE, &res);
		memcpy(buf_ptr + buf_part_size, sec_ptr[0], element_size);
		break;
	}
	case 2: {
		const size_t buf_part_size = total_size - 2 * element_size;
		test_sum(buf_ptr + buf_part_size, 2 * element_size, rsum[1], TRUE, &res);
		test_sum(sec_ptr[1] + element_size, sector_size - element_size, rsum[2], TRUE, &res);
		memmove(buf_ptr + element_size, buf_ptr, buf_part_size);
		memcpy(buf_ptr, sec_ptr[0], element_size);
		memcpy(buf_ptr + element_size + buf_part_size, sec_ptr[1], element_size);
		break;
	}
	}

	for (int i = 0; i < sectors; i++) {
		test_sum(buf_ptr + sector_size * i, sector_size, ssum[1 + i],
			TRUE, &res);
	}
	got_result(&res, "read with small elements");

	if (!may_write) {
		return;
	}

	for (int i = 0; i < sectors; i++) {
		ssum[1 + i] = fill_rand(buf_ptr + sector_size * i, sector_size);
	}

	switch (pattern) {
	case 0: {
		const size_t buf_part_size = total_size - element_size;
		memcpy(sec_ptr[0], buf_ptr, element_size);
		memmove(buf_ptr, buf_ptr + element_size, buf_part_size);
		fill_rand(buf_ptr + buf_part_size, element_size);
		break;
	}
	case 1: {
		const size_t buf_part_size = total_size - element_size;
		memcpy(sec_ptr[0], buf_ptr + buf_part_size, element_size);
		fill_rand(buf_ptr + buf_part_size, element_size);
		break;
	}
	case 2: {
		const size_t buf_part_size = total_size - 2 * element_size;
		memcpy(sec_ptr[0], buf_ptr, element_size);
		memcpy(sec_ptr[1], buf_ptr + element_size + buf_part_size, element_size);
		memmove(buf_ptr, buf_ptr + element_size, buf_part_size);
		fill_rand(buf_ptr + buf_part_size, 2 * element_size);
		break;
	}
	}

	memcpy(iov, iov_template, sizeof(iov));
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
	const int num_sectors = 5;
	const int base_sector_offset = 2;
	const int num_sector_configs = 3;
	const int num_align_modes = 3;

	u8_t *buf_ptr = NULL;
	u8_t *sec_ptr[2] = { NULL, NULL };
	const size_t buf_size = sector_size * num_sectors;

	test_group("sector-unaligned elements", sector_size != element_size);

	if (sector_size == element_size) {
		return;
	}

	if (sector_size % element_size != 0) {
		return;
	}

	buf_ptr = alloc_dma_memory(buf_size);
	if (!buf_ptr) {
		goto cleanup;
	}
	sec_ptr[0] = alloc_dma_memory(sector_size);
	if (!sec_ptr[0]) {
		goto cleanup;
	}
	sec_ptr[1] = alloc_dma_memory(sector_size);
	if (!sec_ptr[1]) {
		goto cleanup;
	}

	const u64_t base_pos = (u64_t)sector_size * base_sector_offset;
	u32_t ssum[5];
	u32_t sum = 0;
	result_t res;

	if (may_write) {
		sum = fill_rand(buf_ptr, buf_size);

		for (int i = 0; i < num_sectors; i++) {
			ssum[i] = get_sum(buf_ptr + sector_size * i,
				sector_size);
		}

		simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE,
			buf_size, &res);
		got_result(&res, "write several sectors");
	}

	fill_rand(buf_ptr, buf_size);

	simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE,
		buf_size, &res);

	if (may_write) {
		test_sum(buf_ptr, buf_size, sum, TRUE, &res);
	} else {
		for (int i = 0; i < num_sectors; i++) {
			ssum[i] = get_sum(buf_ptr + sector_size * i,
				sector_size);
		}
	}
	got_result(&res, "read several sectors");

	for (int sectors_to_test = 1; sectors_to_test <= num_sector_configs;
		sectors_to_test++) {
		for (int align_mode = 0; align_mode < num_align_modes; align_mode++) {
			unaligned_size_io(base_pos, buf_ptr, buf_size, sec_ptr,
				sectors_to_test, align_mode, ssum);
		}
	}

	if (may_write) {
		fill_rand(buf_ptr, buf_size);

		simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE,
			buf_size, &res);

		test_sum(buf_ptr, sector_size, ssum[0], TRUE, &res);
		test_sum(buf_ptr + sector_size * (num_sectors - 1),
			sector_size, ssum[num_sectors - 1], TRUE, &res);

		got_result(&res, "check first and last sectors");
	}

cleanup:
	if (sec_ptr[1]) {
		free_dma_memory(sec_ptr[1], sector_size);
	}
	if (sec_ptr[0]) {
		free_dma_memory(sec_ptr[0], sector_size);
	}
	if (buf_ptr) {
		free_dma_memory(buf_ptr, buf_size);
	}
}

static void setup_baseline(u64_t base_pos, u8_t *buf, size_t size)
{
	result_t res;
	u32_t sum = 0;

	if (may_write) {
		sum = fill_rand(buf, size);
		simple_xfer(driver_minor, base_pos, buf, size, TRUE, size, &res);
		got_result(&res, "write several sectors");
	}

	fill_rand(buf, size);

	simple_xfer(driver_minor, base_pos, buf, size, FALSE, size, &res);

	if (may_write) {
		test_sum(buf, size, sum, TRUE, &res);
	}

	got_result(&res, "read several sectors");
}

static void test_single_sector_reads(u64_t base_pos, const u8_t *ref_buf,
	u8_t *test_buf)
{
	result_t res;
	u32_t sum, sum2;

	fill_rand(test_buf, sector_size);
	sum = get_sum(test_buf + min_read, sector_size - min_read);
	simple_xfer(driver_minor, base_pos + sector_size - min_read,
		test_buf, min_read, FALSE, min_read, &res);
	test_sum(test_buf, min_read, get_sum(ref_buf + sector_size - min_read,
		min_read), TRUE, &res);
	test_sum(test_buf + min_read, sector_size - min_read, sum, TRUE,
		&res);
	got_result(&res, "single sector read with lead");

	fill_rand(test_buf, sector_size);
	sum = get_sum(test_buf, sector_size - min_read);
	simple_xfer(driver_minor, base_pos, test_buf + sector_size - min_read,
		min_read, FALSE, min_read, &res);
	test_sum(test_buf + sector_size - min_read, min_read, get_sum(ref_buf,
		min_read), TRUE, &res);
	test_sum(test_buf, sector_size - min_read, sum, TRUE, &res);
	got_result(&res, "single sector read with trail");

	fill_rand(test_buf, sector_size);
	sum = get_sum(test_buf, min_read);
	sum2 = get_sum(test_buf + min_read * 2, sector_size - min_read * 2);
	simple_xfer(driver_minor, base_pos + min_read, test_buf + min_read,
		min_read, FALSE, min_read, &res);
	test_sum(test_buf + min_read, min_read, get_sum(ref_buf + min_read,
		min_read), TRUE, &res);
	test_sum(test_buf, min_read, sum, TRUE, &res);
	test_sum(test_buf + min_read * 2, sector_size - min_read * 2, sum2,
		TRUE, &res);
	got_result(&res, "single sector read with lead and trail");
}

static void test_multi_sector_reads(u64_t base_pos, const u8_t *ref_buf,
	u8_t *test_buf, size_t test_buf_size)
{
	result_t res;
	u32_t sum;
	size_t size;

	size = min_read + sector_size * 2;
	fill_rand(test_buf, test_buf_size);
	sum = get_sum(test_buf + size, test_buf_size - size);
	simple_xfer(driver_minor, base_pos + sector_size - min_read, test_buf,
		size, FALSE, size, &res);
	test_sum(test_buf, size, get_sum(ref_buf + sector_size - min_read,
		size), TRUE, &res);
	test_sum(test_buf + size, test_buf_size - size, sum, TRUE, &res);
	got_result(&res, "multisector read with lead");

	fill_rand(test_buf, test_buf_size);
	sum = get_sum(test_buf + size, test_buf_size - size);
	simple_xfer(driver_minor, base_pos, test_buf, size, FALSE, size, &res);
	test_sum(test_buf, size, get_sum(ref_buf, size), TRUE, &res);
	test_sum(test_buf + size, test_buf_size - size, sum, TRUE, &res);
	got_result(&res, "multisector read with trail");

	fill_rand(test_buf, test_buf_size);
	sum = get_sum(test_buf + sector_size, test_buf_size - sector_size);
	simple_xfer(driver_minor, base_pos + min_read, test_buf, sector_size,
		FALSE, sector_size, &res);
	test_sum(test_buf, sector_size, get_sum(ref_buf + min_read,
		sector_size), TRUE, &res);
	test_sum(test_buf + sector_size, test_buf_size - sector_size, sum,
		TRUE, &res);
	got_result(&res, "multisector read with lead and trail");
}

static void unaligned_pos1(void)
{
	u8_t *buf_ptr = NULL;
	u8_t *buf2_ptr = NULL;
	const size_t num_sectors = 3;
	const size_t buf_size = sector_size * num_sectors;
	const u64_t base_pos = (u64_t)sector_size * num_sectors;

	test_group("sector-unaligned positions, part one",
		min_read != sector_size);

	if (min_read == sector_size)
		return;

	assert(sector_size % min_read == 0);
	assert(min_read % element_size == 0);

	buf_ptr = alloc_dma_memory(buf_size);
	if (buf_ptr == NULL)
		goto cleanup;

	buf2_ptr = alloc_dma_memory(buf_size);
	if (buf2_ptr == NULL)
		goto cleanup;

	setup_baseline(base_pos, buf_ptr, buf_size);
	test_single_sector_reads(base_pos, buf_ptr, buf2_ptr);
	test_multi_sector_reads(base_pos, buf_ptr, buf2_ptr, buf_size);

cleanup:
	if (buf2_ptr != NULL)
		free_dma_memory(buf2_ptr, buf_size);
	if (buf_ptr != NULL)
		free_dma_memory(buf_ptr, buf_size);
}

static void establish_baseline(u64_t base_pos, u8_t *buf_ptr)
{
	result_t res;
	u32_t sum = 0;
	u32_t sum2 = 0;
	const size_t total_size = max_size + sector_size;

	if (may_write) {
		sum = fill_rand(buf_ptr, max_size);
		simple_xfer(driver_minor, base_pos, buf_ptr, max_size,
			TRUE, max_size, &res);
		got_result(&res, "large baseline write");

		sum2 = fill_rand(buf_ptr + max_size, sector_size);
		simple_xfer(driver_minor, base_pos + max_size,
			buf_ptr + max_size, sector_size, TRUE, sector_size,
			&res);
		got_result(&res, "small baseline write");
	}

	fill_rand(buf_ptr, total_size);

	simple_xfer(driver_minor, base_pos, buf_ptr, max_size,
		FALSE, max_size, &res);
	if (may_write)
		test_sum(buf_ptr, max_size, sum, TRUE, &res);
	got_result(&res, "large baseline read");

	simple_xfer(driver_minor, base_pos + max_size, buf_ptr + max_size,
		sector_size, FALSE, sector_size, &res);
	if (may_write)
		test_sum(buf_ptr + max_size, sector_size, sum2, TRUE, &res);
	got_result(&res, "small baseline read");
}

static void test_small_unaligned_vector(u64_t base_pos,
	const u8_t *ref_buf, u8_t *test_buf, size_t test_buf_size)
{
	iovec_t iov[NR_IOREQS];
	u32_t rsum[NR_IOREQS];
	result_t res;
	const size_t total_size = min_read * NR_IOREQS;

	fill_rand(test_buf, test_buf_size);

	for (int i = 0; i < NR_IOREQS; i++) {
		iov[i].iov_addr = (vir_bytes)test_buf + i * sector_size;
		iov[i].iov_size = min_read;

		rsum[i] = get_sum(test_buf + i * sector_size + min_read,
			sector_size - min_read);
	}

	vir_xfer(driver_minor, base_pos + min_read, iov, NR_IOREQS, FALSE,
		total_size, &res);

	for (int i = 0; i < NR_IOREQS; i++) {
		test_sum(test_buf + i * sector_size + min_read,
			sector_size - min_read, rsum[i], TRUE, &res);
		memmove(test_buf + i * min_read, test_buf + i * sector_size,
			min_read);
	}

	const u32_t expected_sum = get_sum(ref_buf + min_read, total_size);
	test_sum(test_buf, total_size, expected_sum, TRUE, &res);

	got_result(&res, "small fully unaligned filled vector");
}

static void test_large_unaligned_single(u64_t base_pos,
	const u8_t *ref_buf, u8_t *test_buf, size_t test_buf_size)
{
	result_t res;

	fill_rand(test_buf, test_buf_size);

	simple_xfer(driver_minor, base_pos + min_read, test_buf, max_size,
		FALSE, max_size, &res);

	const u32_t expected_sum = get_sum(ref_buf + min_read, max_size);
	test_sum(test_buf, max_size, expected_sum, TRUE, &res);

	got_result(&res, "large fully unaligned single element");
}

static void test_large_unaligned_vector(u64_t base_pos,
	const u8_t *ref_buf, u8_t *test_buf, size_t test_buf_size)
{
	iovec_t iov[NR_IOREQS];
	result_t res;

	size_t max_block = max_size / NR_IOREQS;
	max_block -= max_block % sector_size;

	if (max_block == 0)
		return;

	fill_rand(test_buf, test_buf_size);

	for (int i = 0; i < NR_IOREQS; i++) {
		iov[i].iov_addr = (vir_bytes)test_buf + i * max_block;
		iov[i].iov_size = max_block;
	}

	const size_t total_size = max_block * NR_IOREQS;
	vir_xfer(driver_minor, base_pos + min_read, iov, NR_IOREQS, FALSE,
		total_size, &res);

	const u32_t expected_sum = get_sum(ref_buf + min_read, total_size);
	test_sum(test_buf, total_size, expected_sum, TRUE, &res);

	got_result(&res, "large fully unaligned filled vector");
}

static void unaligned_pos2(void)
{
	static const u64_t BASE_POS_SECTOR_MULTIPLIER = 3;

	test_group("sector-unaligned positions, part two",
		min_read != sector_size);

	if (min_read == sector_size)
		return;

	const size_t buffer_size = max_size + sector_size;
	u8_t *ref_buf = alloc_dma_memory(buffer_size);
	if (ref_buf == NULL)
		return;

	u8_t *test_buf = alloc_dma_memory(buffer_size);
	if (test_buf == NULL) {
		free_dma_memory(ref_buf, buffer_size);
		return;
	}

	const u64_t base_pos = (u64_t)sector_size * BASE_POS_SECTOR_MULTIPLIER;

	establish_baseline(base_pos, ref_buf);
	test_small_unaligned_vector(base_pos, ref_buf, test_buf, buffer_size);
	test_large_unaligned_single(base_pos, ref_buf, test_buf, buffer_size);
	test_large_unaligned_vector(base_pos, ref_buf, test_buf, buffer_size);

	free_dma_memory(test_buf, buffer_size);
	free_dma_memory(ref_buf, buffer_size);
}

#define SWEEP_AREA_SECTORS 8
#define SWEEP_CHUNK_SECTORS 3
#define SWEEP_SUB_AREAS (SWEEP_AREA_SECTORS - SWEEP_CHUNK_SECTORS + 1)

static void test_sector_checksums(const u8_t *buf, const u32_t *expected_ssums,
                                  size_t num_sectors, result_t *res)
{
	for (size_t i = 0; i < num_sectors; i++) {
		test_sum(buf + sector_size * i, sector_size, expected_ssums[i],
			 TRUE, res);
	}
}

static void update_sector_checksums(const u8_t *buf, u32_t *ssums,
                                    size_t num_sectors)
{
	for (size_t i = 0; i < num_sectors; i++) {
		ssums[i] = get_sum(buf + sector_size * i, sector_size);
	}
}

static void sweep_area(u64_t base_pos)
{
	const size_t buf_size = sector_size * SWEEP_AREA_SECTORS;
	const size_t chunk_size = sector_size * SWEEP_CHUNK_SECTORS;
	u8_t *buf_ptr;
	u32_t total_sum = 0;
	u32_t ssum[SWEEP_AREA_SECTORS];
	result_t res;
	size_t i;

	buf_ptr = alloc_dma_memory(buf_size);
	if (!buf_ptr) {
		return;
	}

	if (may_write) {
		total_sum = fill_rand(buf_ptr, buf_size);
		simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE,
			    buf_size, &res);
		got_result(&res, "write to full area");
	}

	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE,
		    buf_size, &res);

	if (may_write) {
		test_sum(buf_ptr, buf_size, total_sum, TRUE, &res);
	}
	update_sector_checksums(buf_ptr, ssum, SWEEP_AREA_SECTORS);
	got_result(&res, "read from full area");

	for (i = 0; i < SWEEP_SUB_AREAS; i++) {
		u64_t sub_area_pos = base_pos + sector_size * i;

		fill_rand(buf_ptr, chunk_size);
		simple_xfer(driver_minor, sub_area_pos, buf_ptr, chunk_size,
			    FALSE, chunk_size, &res);
		test_sector_checksums(buf_ptr, &ssum[i], SWEEP_CHUNK_SECTORS, &res);
		got_result(&res, "read from subarea");

		if (!may_write) {
			continue;
		}

		fill_rand(buf_ptr, chunk_size);
		simple_xfer(driver_minor, sub_area_pos, buf_ptr, chunk_size,
			    TRUE, chunk_size, &res);
		update_sector_checksums(buf_ptr, &ssum[i], SWEEP_CHUNK_SECTORS);
		got_result(&res, "write to subarea");
	}

	if (may_write) {
		fill_rand(buf_ptr, buf_size);
		simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE,
			    buf_size, &res);
		test_sector_checksums(buf_ptr, ssum, SWEEP_AREA_SECTORS, &res);
		got_result(&res, "readback from full area");
	}

	free_dma_memory(buf_ptr, buf_size);
}

static void read_integrity_zone(u8_t *buf, size_t size, result_t *res)
{
	fill_rand(buf, size);
	simple_xfer(driver_minor, 0ULL, buf, size, FALSE, size, res);
}

static void write_integrity_zone(const u8_t *buf, size_t size, result_t *res)
{
	simple_xfer(driver_minor, 0ULL, (u8_t *)buf, size, TRUE, size, res);
}

static void perform_integrity_check(void)
{
	result_t res;
	const size_t buf_size = sector_size * 3;
	u8_t *buf_ptr = alloc_dma_memory(buf_size);
	u32_t sum;

	if (may_write) {
		sum = fill_rand(buf_ptr, buf_size);
		write_integrity_zone(buf_ptr, buf_size, &res);
		got_result(&res, "write integrity zone");

		read_integrity_zone(buf_ptr, buf_size, &res);
		test_sum(buf_ptr, buf_size, sum, TRUE, &res);
	} else {
		read_integrity_zone(buf_ptr, buf_size, &res);
		sum = get_sum(buf_ptr, buf_size);
	}
	got_result(&res, "read integrity zone");

	sweep_area(pos);

	read_integrity_zone(buf_ptr, buf_size, &res);
	test_sum(buf_ptr, buf_size, sum, TRUE, &res);
	got_result(&res, "check integrity zone");

	free_dma_memory(buf_ptr, buf_size);
}

static void sweep_and_check(u64_t pos, int check_integ)
{
	if (check_integ) {
		perform_integrity_check();
	} else {
		sweep_area(pos);
	}
}

static void basic_sweep(void)
{
	assert(sector_size > 0);

	test_group("basic area sweep", true);
	sweep_area((uint64_t)sector_size);
}

static void high_disk_pos(void)
{
	const u64_t four_gb = 0x100000000ULL;
	const u64_t sectors_per_side = 4;
	const u64_t margin = sector_size * sectors_per_side;

	u64_t test_area_end = four_gb + margin;
	test_area_end -= test_area_end % sector_size;

	const u64_t test_area_start = test_area_end - (margin * 2);

	const int can_run_test = (part.base <= test_area_start) &&
				 ((part.base + part.size) >= test_area_end);

	test_group("high disk positions", can_run_test);

	if (can_run_test) {
		const u64_t sweep_start_offset = test_area_start - part.base;
		sweep_and_check(sweep_start_offset, part.base == 0ULL);
	}
}

#define FOUR_GIGABYTES (0x100000000ULL)
#define ADDITIONAL_SECTORS_NEEDED (4)
#define SWEEP_START_SECTOR_OFFSET (8)

static void high_part_pos(void)
{
	const u64_t min_testable_size =
		FOUR_GIGABYTES + (ADDITIONAL_SECTORS_NEEDED * sector_size);

	const int is_test_applicable =
		(part.base != 0ULL) && (part.size >= min_testable_size);

	test_group("high partition positions", is_test_applicable);

	if (is_test_applicable) {
		u64_t base_pos =
			min_testable_size - (SWEEP_START_SECTOR_OFFSET * sector_size);
		sweep_and_check(base_pos, TRUE);
	}
}

static void high_lba_pos1(void)
{
	/* Test 48-bit LBA positions, as opposed to *24-bit*. Drivers that only
	 * support 48-bit LBA ATA transfers, will treat the lower and upper 24
	 * bits differently. This is again relative to the disk start, not the
	 * partition start. For 512-byte sectors, the lowest position exceeding
	 * 24 bit is at 8GB. As usual, we need four sectors more, and fewer, on
	 * the other side. The partition that we're operating on, must cover
	 * this area.
	 */
	static const char * const test_name = "high LBA positions, part one";
	const u64_t lba24_boundary_bytes = (1ULL << 24) * sector_size;
	const u64_t test_start_offset = 8 * sector_size;

	const u64_t test_start_pos = lba24_boundary_bytes - test_start_offset;

	const bool can_run_test = (part.base <= test_start_pos) &&
				  (part.base + part.size >= lba24_boundary_bytes);

	test_group(test_name, can_run_test);

	if (can_run_test) {
		const u64_t relative_pos = test_start_pos - part.base;
		sweep_and_check(relative_pos, part.base == 0ULL);
	}
}

static void high_lba_pos2(void)
{
	static const char * const TEST_NAME = "high LBA positions, part two";
	const unsigned int LBA_28_BIT_SHIFT = 28;
	const unsigned int SWEEP_SECTOR_OFFSET = 8;

	const u64_t lba_28bit_boundary_bytes = (1ULL << LBA_28_BIT_SHIFT) * sector_size;
	const u64_t partition_end_bytes = part.base + part.size;
	const u64_t test_start_bytes = lba_28bit_boundary_bytes -
	                               (sector_size * SWEEP_SECTOR_OFFSET);

	const bool test_is_applicable =
		(partition_end_bytes >= lba_28bit_boundary_bytes) &&
		(part.base <= test_start_bytes);

	test_group(TEST_NAME, test_is_applicable);

	if (test_is_applicable) {
		const u64_t sweep_offset_bytes = test_start_bytes - part.base;
		sweep_and_check(sweep_offset_bytes, part.base == 0ULL);
	}
}

static int high_pos(void)
{
	int status = 0;

	status |= basic_sweep();
	status |= high_disk_pos();
	status |= high_part_pos();
	status |= high_lba_pos1();
	status |= high_lba_pos2();

	return status;
}

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static void open_primary(void)
{
    test_group("device open", true);

    if (open_device(driver_minor) != 0) {
        perror("Failed to open primary device");
        exit(EXIT_FAILURE);
    }
}

static void close_primary(void)
{
	test_group("device close", TRUE);

	const int result = close_device(driver_minor);
	(void)result;
	assert(result == 0);

	assert(nr_opened == 0);
}

static void do_tests(void)
{
	int (*const test_cases[])(void) = {
		misc_ioctl,
		bad_read1,
		bad_read2,
		/* It is assumed that the driver implementation uses shared
		 * code paths for read and write for the basic checks, so we do
		 * not repeat those for writes.
		 */
		bad_write,
		vector_and_large,
		part_limits,
		unaligned_size,
		unaligned_pos1,
		unaligned_pos2,
		high_pos,
	};
	const size_t num_tests = sizeof(test_cases) / sizeof(test_cases[0]);
	int has_failures = 0;

	if (open_primary() != 0) {
		return;
	}

	for (size_t i = 0; i < num_tests; ++i) {
		if (test_cases[i]() != 0) {
			has_failures = 1;
		}
	}

	close_primary();

	(void)has_failures;
}

static void initialize_and_verify_state(void)
{
	const int MAX_DRIVER_MINOR = 255;

	if (env_argc > 1) {
		optset_parse(optset_table, env_argv[1]);
	}

	if (driver_label[0] == '\0') {
		panic("no driver label given");
	}

	if (ds_retrieve_label_endpt(driver_label, &driver_endpt) != OK) {
		panic("unable to resolve driver label");
	}

	if (driver_minor > MAX_DRIVER_MINOR) {
		panic("invalid or no driver minor given");
	}

	srand48(getticks());

	output("BLOCKTEST: driver label '%s' (endpt %d), minor %d\n",
		driver_label, driver_endpt, driver_minor);
}

static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
	initialize_and_verify_state();

	do_tests();

	output("BLOCKTEST: summary: %d out of %d tests failed "
		"across %d group%s; %d driver deaths\n",
		failed_tests, total_tests, failed_groups,
		(failed_groups == 1) ? "" : "s", driver_deaths);

	/* The returned code will determine the outcome of the RS call, and
	 * thus the entire test. The actual error code does not matter.
	 */
	return (failed_tests > 0) ? EINVAL : OK;
}

static void sef_local_startup(void)
{
	int r;

	sef_setcb_init_fresh(sef_cb_init_fresh);

	if ((r = sef_startup()) != 0) {
		panic("SEF startup failed: %d", r);
	}
}

#include <stdlib.h>
#include <stdio.h>

/* Forward declarations for external functions. */
void env_setargs(int argc, char *argv[]);
int sef_local_startup(void);

int main(int argc, char *argv[])
{
	env_setargs(argc, argv);

	if (sef_local_startup() != 0) {
		fprintf(stderr, "SEF startup failed.\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
