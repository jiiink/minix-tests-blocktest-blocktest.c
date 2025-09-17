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

static void output(char *fmt, ...)
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

	if (contig)
		ptr = alloc_contig(size, 0, NULL);
	else
		ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_PREALLOC | MAP_ANON, -1, 0);

	if (ptr == MAP_FAILED)
		panic("unable to allocate %zu bytes of memory", size);

	return ptr;
}

static void free_dma_memory(void *ptr, size_t size)
{
	if (contig)
		free_contig(ptr, size);
	else
		munmap(ptr, size);
}

static int set_result(result_t *res, int type, ssize_t value)
{
	res->type = type;
	res->value = value;
	return type;
}

static int accept_result(result_t *res, int type, ssize_t value)
{
	if (res->type != type || res->value != value) {
		return FALSE;
	}

	set_result(res, RESULT_OK, 0);
	return TRUE;
}

static void update_statistics(result_t *res)
{
	total_tests++;
	if (res->type != RESULT_OK) {
		failed_tests++;
		if (group_failure == FALSE) {
			failed_groups++;
			group_failure = TRUE;
		}
	}
}

static void print_test_header(int test_number, char *desc, result_t *res)
{
	const char *status = (res->type == RESULT_OK) ? "PASS" : "FAIL";
	output("#%02d: %-38s\t[%s]\n", test_number, desc, status);
}

static void print_error_detail(result_t *res)
{
	switch (res->type) {
	case RESULT_DEATH:
		output("- driver died\n");
		break;
	case RESULT_COMMFAIL:
		output("- communication failed; ipc_sendrec returned %d\n", res->value);
		break;
	case RESULT_BADTYPE:
		output("- bad type %d in reply message\n", res->value);
		break;
	case RESULT_BADID:
		output("- mismatched ID %d in reply message\n", res->value);
		break;
	case RESULT_BADSTATUS:
		output("- bad or unexpected status %d in reply message\n", res->value);
		break;
	case RESULT_TRUNC:
		output("- result size not as expected (%u bytes left)\n", res->value);
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
		output("- bad or unexpected return value %d from call\n", res->value);
		break;
	}
}

static void got_result(result_t *res, char *desc)
{
	static int i = 0;
	
	update_statistics(res);
	print_test_header(++i, desc, res);
	print_error_detail(res);
}

static void test_group(char *name, int exec)
{
	const char *SKIP_MESSAGE = " (skipping)";
	const char *EXEC_MESSAGE = "";
	
	output("Test group: %s%s\n", name, exec ? EXEC_MESSAGE : SKIP_MESSAGE);
	group_failure = FALSE;
}

static void reopen_device(dev_t minor)
{
	message m;

	memset(&m, 0, sizeof(m));
	m.m_type = BDEV_OPEN;
	m.m_lbdev_lblockdriver_msg.minor = minor;
	m.m_lbdev_lblockdriver_msg.access = (may_write) ? (BDEV_R_BIT | BDEV_W_BIT) : BDEV_R_BIT;
	m.m_lbdev_lblockdriver_msg.id = 0;

	(void) ipc_sendrec(driver_endpt, &m);
}

static int wait_for_new_endpoint(endpoint_t *last_endpt)
{
	int r;
	
	for (;;) {
		r = ds_retrieve_label_endpt(driver_label, &driver_endpt);
		if (r == OK && *last_endpt != driver_endpt)
			break;
		micro_delay(100000);
	}
	return OK;
}

static void reopen_all_devices(void)
{
	int i;
	for (i = 0; i < nr_opened; i++)
		reopen_device(opened[i]);
}

static int handle_driver_death(result_t *res)
{
	endpoint_t last_endpt;
	
	output("WARNING: driver has died, attempting to proceed\n");
	driver_deaths++;
	
	last_endpt = driver_endpt;
	wait_for_new_endpoint(&last_endpt);
	reopen_all_devices();
	
	return set_result(res, RESULT_DEATH, 0);
}

static int validate_reply_type(message *m_ptr, result_t *res)
{
	if (m_ptr->m_type != BDEV_REPLY)
		return set_result(res, RESULT_BADTYPE, m_ptr->m_type);
	return OK;
}

static int validate_reply_id(message *m_ptr, message *m_orig, result_t *res)
{
	if (m_ptr->m_lblockdriver_lbdev_reply.id != m_orig->m_lbdev_lblockdriver_msg.id)
		return set_result(res, RESULT_BADID, m_ptr->m_lblockdriver_lbdev_reply.id);
	return OK;
}

static int validate_reply_status(message *m_ptr, ssize_t exp, result_t *res)
{
	int status = m_ptr->m_lblockdriver_lbdev_reply.status;
	
	if ((exp < 0 && status >= 0) || (exp >= 0 && status < 0))
		return set_result(res, RESULT_BADSTATUS, status);
	return OK;
}

static int sendrec_driver(message *m_ptr, ssize_t exp, result_t *res)
{
	message m_orig;
	int r;

	m_orig = *m_ptr;
	r = ipc_sendrec(driver_endpt, m_ptr);

	if (r == EDEADSRCDST)
		return handle_driver_death(res);

	if (r != OK)
		return set_result(res, RESULT_COMMFAIL, r);

	if (validate_reply_type(m_ptr, res) != OK)
		return res->type;

	if (validate_reply_id(m_ptr, &m_orig, res) != OK)
		return res->type;

	if (validate_reply_status(m_ptr, exp, res) != OK)
		return res->type;

	return set_result(res, RESULT_OK, 0);
}

static cp_grant_id_t allocate_grant(iovec_s_t *iovec, int nr_req)
{
	cp_grant_id_t grant = cpf_grant_direct(driver_endpt, (vir_bytes) iovec,
			sizeof(*iovec) * nr_req, CPF_READ);
	if (grant == GRANT_INVALID)
		panic("unable to allocate grant");
	return grant;
}

static void revoke_grant(cp_grant_id_t grant)
{
	if (cpf_revoke(grant) == -1)
		panic("unable to revoke grant");
}

static void prepare_message(message *m, dev_t minor, u64_t pos, int nr_req,
	cp_grant_id_t grant, int write)
{
	memset(m, 0, sizeof(*m));
	m->m_type = write ? BDEV_SCATTER : BDEV_GATHER;
	m->m_lbdev_lblockdriver_msg.minor = minor;
	m->m_lbdev_lblockdriver_msg.pos = pos;
	m->m_lbdev_lblockdriver_msg.count = nr_req;
	m->m_lbdev_lblockdriver_msg.grant = grant;
	m->m_lbdev_lblockdriver_msg.id = lrand48();
}

static void check_transfer_status(message *m, ssize_t exp, result_t *res)
{
	if (m->m_lblockdriver_lbdev_reply.status == exp)
		return;

	if (exp < 0)
		set_result(res, RESULT_BADSTATUS,
			m->m_lblockdriver_lbdev_reply.status);
	else
		set_result(res, RESULT_TRUNC,
			exp - m->m_lblockdriver_lbdev_reply.status);
}

static void raw_xfer(dev_t minor, u64_t pos, iovec_s_t *iovec, int nr_req,
	int write, ssize_t exp, result_t *res)
{
	message m;
	int r;

	assert(nr_req <= NR_IOREQS);
	assert(!write || may_write);

	cp_grant_id_t grant = allocate_grant(iovec, nr_req);
	prepare_message(&m, minor, pos, nr_req, grant, write);
	r = sendrec_driver(&m, exp, res);
	revoke_grant(grant);

	if (r != RESULT_OK)
		return;

	check_transfer_status(&m, exp, res);
}

static void create_grants(iovec_t *iovec, iovec_s_t *iov_s, int nr_req, int write)
{
	int i;
	int grant_flag = write ? CPF_READ : CPF_WRITE;

	for (i = 0; i < nr_req; i++) {
		iov_s[i].iov_size = iovec[i].iov_size;
		iov_s[i].iov_grant = cpf_grant_direct(driver_endpt,
			(vir_bytes) iovec[i].iov_addr, iovec[i].iov_size, grant_flag);
		
		if (iov_s[i].iov_grant == GRANT_INVALID)
			panic("unable to allocate grant");
	}
}

static void revoke_grants(iovec_t *iovec, iovec_s_t *iov_s, int nr_req)
{
	int i;

	for (i = 0; i < nr_req; i++) {
		iovec[i].iov_size = iov_s[i].iov_size;

		if (cpf_revoke(iov_s[i].iov_grant) == -1)
			panic("unable to revoke grant");
	}
}

static void vir_xfer(dev_t minor, u64_t pos, iovec_t *iovec, int nr_req,
	int write, ssize_t exp, result_t *res)
{
	iovec_s_t iov_s[NR_IOREQS];

	assert(nr_req <= NR_IOREQS);

	create_grants(iovec, iov_s, nr_req, write);
	raw_xfer(minor, pos, iov_s, nr_req, write, exp, res);
	revoke_grants(iovec, iov_s, nr_req);
}

static void simple_xfer(dev_t minor, u64_t pos, u8_t *buf, size_t size,
	int write, ssize_t exp, result_t *res)
{
	iovec_t iov;

	iov.iov_addr = (vir_bytes) buf;
	iov.iov_size = size;

	vir_xfer(minor, pos, &iov, 1, write, exp, res);
}

static void alloc_buf_and_grant(u8_t **ptr, cp_grant_id_t *grant,
	size_t size, int perms)
{
	*ptr = alloc_dma_memory(size);

	*grant = cpf_grant_direct(driver_endpt, (vir_bytes) *ptr, size, perms);
	
	if (*grant == GRANT_INVALID) {
		panic("unable to allocate grant");
	}
}

static void free_buf_and_grant(u8_t *ptr, cp_grant_id_t grant, size_t size)
{
	cpf_revoke(grant);
	free_dma_memory(ptr, size);
}

#define BUF_SIZE 4096

static void initialize_message_template(message *mt, cp_grant_id_t grant, int minor) {
    memset(mt, 0, sizeof(*mt));
    mt->m_type = BDEV_GATHER;
    mt->m_lbdev_lblockdriver_msg.minor = minor;
    mt->m_lbdev_lblockdriver_msg.pos = 0LL;
    mt->m_lbdev_lblockdriver_msg.count = 1;
    mt->m_lbdev_lblockdriver_msg.grant = grant;
    mt->m_lbdev_lblockdriver_msg.id = lrand48();
}

static void initialize_iovec_template(iovec_s_t *iovt, cp_grant_id_t grant2, vir_bytes buf_size) {
    memset(iovt, 0, sizeof(*iovt));
    iovt->iov_grant = grant2;
    iovt->iov_size = buf_size;
}

static void check_truncated_result(result_t *res, message *m, iovec_s_t *iov) {
    if (res->type == RESULT_OK && 
        m->m_lblockdriver_lbdev_reply.status != (ssize_t) iov->iov_size) {
        res->type = RESULT_TRUNC;
        res->value = m->m_lblockdriver_lbdev_reply.status;
    }
}

static void test_normal_request(message *mt, iovec_s_t *iovt) {
    message m = *mt;
    iovec_s_t iov = *iovt;
    result_t res;
    
    sendrec_driver(&m, OK, &res);
    check_truncated_result(&res, &m, &iov);
    got_result(&res, "normal request");
}

static void test_zero_iovec_elements(message *mt) {
    message m = *mt;
    result_t res;
    
    m.m_lbdev_lblockdriver_msg.count = 0;
    sendrec_driver(&m, EINVAL, &res);
    got_result(&res, "zero iovec elements");
}

static void test_bad_iovec_grant(message *mt) {
    message m = *mt;
    result_t res;
    
    m.m_lbdev_lblockdriver_msg.grant = GRANT_INVALID;
    sendrec_driver(&m, EINVAL, &res);
    got_result(&res, "bad iovec grant");
}

static void test_revoked_iovec_grant(message *mt, iovec_s_t *iovt) {
    message m = *mt;
    iovec_s_t iov = *iovt;
    result_t res;
    cp_grant_id_t grant3;
    
    if ((grant3 = cpf_grant_direct(driver_endpt, (vir_bytes) &iov,
            sizeof(iov), CPF_READ)) == GRANT_INVALID)
        panic("unable to allocate grant");
    
    cpf_revoke(grant3);
    m.m_lbdev_lblockdriver_msg.grant = grant3;
    
    sendrec_driver(&m, EINVAL, &res);
    accept_result(&res, RESULT_BADSTATUS, EPERM);
    got_result(&res, "revoked iovec grant");
}

static void bad_read1(void) {
    message mt;
    iovec_s_t iovt;
    cp_grant_id_t grant, grant2;
    u8_t *buf_ptr;
    vir_bytes buf_size;
    
    test_group("bad read requests, part one", TRUE);
    
    buf_size = BUF_SIZE;
    alloc_buf_and_grant(&buf_ptr, &grant2, buf_size, CPF_WRITE);
    
    if ((grant = cpf_grant_direct(driver_endpt, (vir_bytes) &iovt,
            sizeof(iovt), CPF_READ)) == GRANT_INVALID)
        panic("unable to allocate grant");
    
    initialize_message_template(&mt, grant, driver_minor);
    initialize_iovec_template(&iovt, grant2, buf_size);
    
    test_normal_request(&mt, &iovt);
    test_zero_iovec_elements(&mt);
    test_bad_iovec_grant(&mt);
    test_revoked_iovec_grant(&mt, &iovt);
    test_normal_request(&mt, &iovt);
    
    free_buf_and_grant(buf_ptr, grant2, buf_size);
    cpf_revoke(grant);
}

static u32_t get_sum(u8_t *ptr, size_t size)
{
	const u32_t CHECKSUM_SHIFT = 5;
	u32_t sum = 0;

	for (size_t i = 0; i < size; i++) {
		sum = sum ^ (sum << CHECKSUM_SHIFT) ^ ptr[i];
	}

	return sum;
}

static u32_t fill_rand(u8_t *ptr, size_t size)
{
	const int BYTE_MAX_VALUE = 256;
	size_t i;

	for (i = 0; i < size; i++)
		ptr[i] = lrand48() % BYTE_MAX_VALUE;

	return get_sum(ptr, size);
}

static void test_sum(u8_t *ptr, size_t size, u32_t sum, int should_match,
	result_t *res)
{
	u32_t sum2;

	if (res->type != RESULT_OK)
		return;

	sum2 = get_sum(ptr, size);

	if ((sum == sum2) != should_match) {
		res->type = should_match ? RESULT_CORRUPT : RESULT_MISSING;
		res->value = 0;
	}
}

static void initialize_buffers(u8_t **buf_ptr, u8_t **buf2_ptr, u8_t **buf3_ptr,
                               cp_grant_id_t *buf_grant, cp_grant_id_t *buf2_grant, 
                               cp_grant_id_t *buf3_grant, size_t buf_size)
{
    alloc_buf_and_grant(buf_ptr, buf_grant, buf_size, CPF_WRITE);
    alloc_buf_and_grant(buf2_ptr, buf2_grant, buf_size, CPF_WRITE);
    alloc_buf_and_grant(buf3_ptr, buf3_grant, buf_size, CPF_WRITE);
}

static void setup_iovec(iovec_s_t *iovt, cp_grant_id_t buf_grant, 
                       cp_grant_id_t buf2_grant, cp_grant_id_t buf3_grant,
                       size_t buf_size)
{
    iovt[0].iov_grant = buf_grant;
    iovt[0].iov_size = buf_size;
    iovt[1].iov_grant = buf2_grant;
    iovt[1].iov_size = buf_size;
    iovt[2].iov_grant = buf3_grant;
    iovt[2].iov_size = buf_size;
}

static void fill_buffers_random(u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                size_t buf_size, u32_t *buf_sum, u32_t *buf2_sum, 
                                u32_t *buf3_sum)
{
    *buf_sum = fill_rand(buf_ptr, buf_size);
    *buf2_sum = fill_rand(buf2_ptr, buf_size);
    *buf3_sum = fill_rand(buf3_ptr, buf_size);
}

static void verify_buffers_unchanged(u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                     size_t buf_size, u32_t buf_sum, u32_t buf2_sum,
                                     u32_t buf3_sum, result_t *res)
{
    test_sum(buf_ptr, buf_size, buf_sum, TRUE, res);
    test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, res);
    test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, res);
}

static void verify_buffers_changed(u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                   size_t buf_size, u32_t buf_sum, u32_t buf2_sum,
                                   u32_t buf3_sum, result_t *res)
{
    test_sum(buf_ptr, buf_size, buf_sum, FALSE, res);
    test_sum(buf2_ptr, buf_size, buf2_sum, FALSE, res);
    test_sum(buf3_ptr, buf_size, buf3_sum, FALSE, res);
}

static void verify_partial_buffers(u8_t *buf2_ptr, u8_t *buf3_ptr, size_t buf_size,
                                   u32_t buf2_sum, u32_t buf3_sum, result_t *res)
{
    test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, res);
    test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, res);
}

static void test_normal_vector(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr, 
                               u8_t *buf3_ptr, size_t buf_size)
{
    iovec_s_t iov[3];
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;
    
    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size, 
                       &buf_sum, &buf2_sum, &buf3_sum);
    
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, buf_size * 3, &res);
    
    verify_buffers_changed(buf_ptr, buf2_ptr, buf3_ptr, buf_size, 
                          buf_sum, buf2_sum, buf3_sum, &res);
    got_result(&res, "normal vector request");
}

static void test_zero_sized_element(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr,
                                    u8_t *buf3_ptr, size_t buf_size)
{
    iovec_s_t iov[3];
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;
    
    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[1].iov_size = 0;
    
    fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                       &buf_sum, &buf2_sum, &buf3_sum);
    
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    
    verify_buffers_unchanged(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                            buf_sum, buf2_sum, buf3_sum, &res);
    got_result(&res, "zero size in iovec element");
}

static void test_negative_sized_element(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr,
                                        u8_t *buf3_ptr, size_t buf_size)
{
    iovec_s_t iov[3];
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;
    
    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[1].iov_size = (vir_bytes)LONG_MAX + 1;
    
    fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                       &buf_sum, &buf2_sum, &buf3_sum);
    
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    
    verify_buffers_unchanged(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                            buf_sum, buf2_sum, buf3_sum, &res);
    got_result(&res, "negative size in iovec element");
}

static void test_negative_total_size(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr,
                                     u8_t *buf3_ptr, size_t buf_size)
{
    iovec_s_t iov[3];
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;
    
    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[0].iov_size = LONG_MAX / 2 - 1;
    iov[1].iov_size = LONG_MAX / 2 - 1;
    
    fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                       &buf_sum, &buf2_sum, &buf3_sum);
    
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    
    verify_buffers_unchanged(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                            buf_sum, buf2_sum, buf3_sum, &res);
    got_result(&res, "negative total size");
}

static void test_wrapping_total_size(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr,
                                     u8_t *buf3_ptr, size_t buf_size)
{
    iovec_s_t iov[3];
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;
    
    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[0].iov_size = LONG_MAX - 1;
    iov[1].iov_size = LONG_MAX - 1;
    
    fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                       &buf_sum, &buf2_sum, &buf3_sum);
    
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    
    verify_buffers_unchanged(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                            buf_sum, buf2_sum, buf3_sum, &res);
    got_result(&res, "wrapping total size");
}

static void test_unaligned_size(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr,
                                u8_t *buf3_ptr, size_t buf_size)
{
    iovec_s_t iov[3];
    u32_t buf_sum, buf2_sum, buf3_sum;
    u8_t c1;
    result_t res;
    
    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[1].iov_size--;
    
    fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                       &buf_sum, &buf2_sum, &buf3_sum);
    c1 = buf2_ptr[buf_size - 1];
    
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, buf_size * 3 - 1, &res);
    
    if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
        verify_partial_buffers(buf2_ptr, buf3_ptr, buf_size, buf2_sum, buf3_sum, &res);
    } else {
        verify_buffers_changed(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                              buf_sum, buf2_sum, buf3_sum, &res);
        if (c1 != buf2_ptr[buf_size - 1])
            set_result(&res, RESULT_CORRUPT, 0);
    }
    got_result(&res, "word-unaligned size in iovec element");
}

static void test_invalid_grant(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr,
                               u8_t *buf3_ptr, size_t buf_size)
{
    iovec_s_t iov[3];
    u32_t buf2_sum, buf3_sum;
    result_t res;
    
    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    iov[1].iov_grant = GRANT_INVALID;
    
    fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf_size);
    buf3_sum = fill_rand(buf3_ptr, buf_size);
    
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    
    verify_partial_buffers(buf2_ptr, buf3_ptr, buf_size, buf2_sum, buf3_sum, &res);
    got_result(&res, "invalid grant in iovec element");
}

static void test_revoked_grant(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr,
                               u8_t *buf3_ptr, size_t buf_size)
{
    iovec_s_t iov[3];
    u32_t buf_sum, buf2_sum, buf3_sum;
    cp_grant_id_t grant;
    result_t res;
    
    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    if ((grant = cpf_grant_direct(driver_endpt, (vir_bytes)buf2_ptr,
            buf_size, CPF_WRITE)) == GRANT_INVALID)
        panic("unable to allocate grant");
    
    cpf_revoke(grant);
    iov[1].iov_grant = grant;
    
    fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                       &buf_sum, &buf2_sum, &buf3_sum);
    
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    accept_result(&res, RESULT_BADSTATUS, EPERM);
    
    verify_partial_buffers(buf2_ptr, buf3_ptr, buf_size, buf2_sum, buf3_sum, &res);
    got_result(&res, "revoked grant in iovec element");
}

static void test_readonly_grant(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr,
                                u8_t *buf3_ptr, size_t buf_size)
{
    iovec_s_t iov[3];
    u32_t buf_sum, buf2_sum, buf3_sum;
    cp_grant_id_t grant;
    result_t res;
    
    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    if ((grant = cpf_grant_direct(driver_endpt, (vir_bytes)buf2_ptr,
            buf_size, CPF_READ)) == GRANT_INVALID)
        panic("unable to allocate grant");
    
    iov[1].iov_grant = grant;
    
    fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                       &buf_sum, &buf2_sum, &buf3_sum);
    
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    accept_result(&res, RESULT_BADSTATUS, EPERM);
    
    verify_partial_buffers(buf2_ptr, buf3_ptr, buf_size, buf2_sum, buf3_sum, &res);
    got_result(&res, "read-only grant in iovec element");
    
    cpf_revoke(grant);
}

static void test_unaligned_buffer(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr,
                                  u8_t *buf3_ptr, size_t buf_size)
{
    iovec_s_t iov[3];
    u32_t buf_sum, buf2_sum, buf3_sum;
    u8_t c1, c2;
    cp_grant_id_t grant;
    result_t res;
    
    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    if ((grant = cpf_grant_direct(driver_endpt, (vir_bytes)(buf2_ptr + 1),
            buf_size - 2, CPF_WRITE)) == GRANT_INVALID)
        panic("unable to allocate grant");
    
    iov[1].iov_grant = grant;
    iov[1].iov_size = buf_size - 2;
    
    fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                       &buf_sum, &buf2_sum, &buf3_sum);
    c1 = buf2_ptr[0];
    c2 = buf2_ptr[buf_size - 1];
    
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, buf_size * 3 - 2, &res);
    
    if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
        verify_partial_buffers(buf2_ptr, buf3_ptr, buf_size, buf2_sum, buf3_sum, &res);
    } else {
        verify_buffers_changed(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                              buf_sum, buf2_sum, buf3_sum, &res);
        if (c1 != buf2_ptr[0] || c2 != buf2_ptr[buf_size - 1])
            set_result(&res, RESULT_CORRUPT, 0);
    }
    got_result(&res, "word-unaligned buffer in iovec element");
    
    cpf_revoke(grant);
}

static void test_unaligned_position(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr,
                                    u8_t *buf3_ptr, size_t buf_size)
{
    if (min_read <= 1)
        return;
        
    iovec_s_t iov[3];
    u32_t buf_sum, buf2_sum, buf3_sum;
    result_t res;
    
    memcpy(iov, iovt, sizeof(iovec_s_t) * 3);
    
    fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                       &buf_sum, &buf2_sum, &buf3_sum);
    
    raw_xfer(driver_minor, 1ULL, iov, 3, FALSE, EINVAL, &res);
    
    verify_buffers_unchanged(buf_ptr, buf2_ptr, buf3_ptr, buf_size,
                            buf_sum, buf2_sum, buf3_sum, &res);
    got_result(&res, "word-unaligned position");
}

static void bad_read2(void)
{
    u8_t *buf_ptr, *buf2_ptr, *buf3_ptr;
    size_t buf_size;
    cp_grant_id_t buf_grant, buf2_grant, buf3_grant;
    iovec_s_t iovt[3];
    
    test_group("bad read requests, part two", TRUE);
    
    buf_size = BUF_SIZE;
    
    initialize_buffers(&buf_ptr, &buf2_ptr, &buf3_ptr,
                      &buf_grant, &buf2_grant, &buf3_grant, buf_size);
    
    setup_iovec(iovt, buf_grant, buf2_grant, buf3_grant, buf_size);
    
    test_normal_vector(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    test_zero_sized_element(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    test_negative_sized_element(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    test_negative_total_size(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    test_wrapping_total_size(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    test_unaligned_size(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    test_invalid_grant(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    test_revoked_grant(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    test_readonly_grant(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    test_unaligned_buffer(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    test_unaligned_position(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    test_normal_vector(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
    
    free_buf_and_grant(buf3_ptr, buf3_grant, buf_size);
    free_buf_and_grant(buf2_ptr, buf2_grant, buf_size);
    free_buf_and_grant(buf_ptr, buf_grant, buf_size);
}

static void allocate_test_buffers(u8_t **buf_ptr, u8_t **buf2_ptr, u8_t **buf3_ptr,
                                  cp_grant_id_t *buf_grant, cp_grant_id_t *buf2_grant, 
                                  cp_grant_id_t *buf3_grant, size_t buf_size)
{
	alloc_buf_and_grant(buf_ptr, buf_grant, buf_size, CPF_READ);
	alloc_buf_and_grant(buf2_ptr, buf2_grant, buf_size, CPF_READ);
	alloc_buf_and_grant(buf3_ptr, buf3_grant, buf_size, CPF_READ);
}

static void setup_iovec(iovec_s_t *iovt, cp_grant_id_t buf_grant, 
                       cp_grant_id_t buf2_grant, cp_grant_id_t buf3_grant, 
                       size_t buf_size)
{
	iovt[0].iov_grant = buf_grant;
	iovt[0].iov_size = buf_size;
	iovt[1].iov_grant = buf2_grant;
	iovt[1].iov_size = buf_size;
	iovt[2].iov_grant = buf3_grant;
	iovt[2].iov_size = buf_size;
}

static void fill_buffers_random(u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                                size_t buf_size, u32_t *buf_sum, u32_t *buf2_sum, 
                                u32_t *buf3_sum)
{
	*buf_sum = fill_rand(buf_ptr, buf_size);
	*buf2_sum = fill_rand(buf2_ptr, buf_size);
	*buf3_sum = fill_rand(buf3_ptr, buf_size);
}

static void verify_buffer_sums(u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                               size_t buf_size, u32_t buf_sum, u32_t buf2_sum, 
                               u32_t buf3_sum, result_t *res)
{
	test_sum(buf_ptr, buf_size, buf_sum, TRUE, res);
	test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, res);
	test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, res);
}

static void free_test_buffers(u8_t *buf_ptr, u8_t *buf2_ptr, u8_t *buf3_ptr,
                              cp_grant_id_t buf_grant, cp_grant_id_t buf2_grant, 
                              cp_grant_id_t buf3_grant, size_t buf_size)
{
	free_buf_and_grant(buf3_ptr, buf3_grant, buf_size);
	free_buf_and_grant(buf2_ptr, buf2_grant, buf_size);
	free_buf_and_grant(buf_ptr, buf_grant, buf_size);
}

static size_t calculate_sector_unalign(void)
{
	#define MIN_SECTOR_UNALIGN 1
	#define WORD_UNALIGN_THRESHOLD 2
	return (min_write > WORD_UNALIGN_THRESHOLD) ? WORD_UNALIGN_THRESHOLD : MIN_SECTOR_UNALIGN;
}

static void test_unaligned_position(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr, 
                                   u8_t *buf3_ptr, size_t buf_size, size_t sector_unalign)
{
	iovec_s_t iov[3];
	u32_t buf_sum, buf2_sum, buf3_sum;
	result_t res;
	
	memcpy(iov, iovt, sizeof(iov));
	fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size, &buf_sum, &buf2_sum, &buf3_sum);
	raw_xfer(driver_minor, (u64_t)sector_unalign, iov, 3, TRUE, EINVAL, &res);
	verify_buffer_sums(buf_ptr, buf2_ptr, buf3_ptr, buf_size, buf_sum, buf2_sum, buf3_sum, &res);
	got_result(&res, "sector-unaligned write position");
}

static void test_unaligned_size(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr, 
                               u8_t *buf3_ptr, size_t buf_size, size_t sector_unalign)
{
	iovec_s_t iov[3];
	u32_t buf_sum, buf2_sum, buf3_sum;
	result_t res;
	
	memcpy(iov, iovt, sizeof(iov));
	iov[1].iov_size -= sector_unalign;
	fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size, &buf_sum, &buf2_sum, &buf3_sum);
	raw_xfer(driver_minor, 0ULL, iov, 3, TRUE, EINVAL, &res);
	verify_buffer_sums(buf_ptr, buf2_ptr, buf3_ptr, buf_size, buf_sum, buf2_sum, buf3_sum, &res);
	got_result(&res, "sector-unaligned write size");
}

static void test_alignment(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr, 
                          u8_t *buf3_ptr, size_t buf_size)
{
	size_t sector_unalign;
	
	if (min_write == 0)
		min_write = sector_size;
		
	if (min_write <= 1)
		return;
		
	sector_unalign = calculate_sector_unalign();
	test_unaligned_position(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size, sector_unalign);
	test_unaligned_size(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size, sector_unalign);
}

static void test_write_only_grant(iovec_s_t *iovt, u8_t *buf_ptr, u8_t *buf2_ptr, 
                                 u8_t *buf3_ptr, size_t buf_size)
{
	iovec_s_t iov[3];
	u32_t buf_sum, buf2_sum, buf3_sum;
	cp_grant_id_t grant;
	result_t res;
	
	memcpy(iov, iovt, sizeof(iov));
	
	if ((grant = cpf_grant_direct(driver_endpt, (vir_bytes) buf2_ptr,
			buf_size, CPF_WRITE)) == GRANT_INVALID)
		panic("unable to allocate grant");
		
	iov[1].iov_grant = grant;
	fill_buffers_random(buf_ptr, buf2_ptr, buf3_ptr, buf_size, &buf_sum, &buf2_sum, &buf3_sum);
	raw_xfer(driver_minor, 0ULL, iov, 3, TRUE, EINVAL, &res);
	accept_result(&res, RESULT_BADSTATUS, EPERM);
	verify_buffer_sums(buf_ptr, buf2_ptr, buf3_ptr, buf_size, buf_sum, buf2_sum, buf3_sum, &res);
	got_result(&res, "write-only grant in iovec element");
	cpf_revoke(grant);
}

static void bad_write(void)
{
	u8_t *buf_ptr, *buf2_ptr, *buf3_ptr;
	size_t buf_size;
	cp_grant_id_t buf_grant, buf2_grant, buf3_grant;
	iovec_s_t iovt[3];

	test_group("bad write requests", may_write);

	if (!may_write)
		return;

	buf_size = BUF_SIZE;
	allocate_test_buffers(&buf_ptr, &buf2_ptr, &buf3_ptr, 
	                     &buf_grant, &buf2_grant, &buf3_grant, buf_size);
	setup_iovec(iovt, buf_grant, buf2_grant, buf3_grant, buf_size);
	test_alignment(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
	test_write_only_grant(iovt, buf_ptr, buf2_ptr, buf3_ptr, buf_size);
	free_test_buffers(buf_ptr, buf2_ptr, buf3_ptr, 
	                 buf_grant, buf2_grant, buf3_grant, buf_size);
}

static void initialize_guards(u8_t *buf_ptr, size_t large_size)
{
    *(u32_t *)buf_ptr = 0xCAFEBABEL;
    *(u32_t *)(buf_ptr + sizeof(u32_t) + large_size) = 0xDECAFBADL;
}

static void check_guards(u8_t *buf_ptr, size_t large_size, result_t *res)
{
    if (*(u32_t *)buf_ptr != 0xCAFEBABEL)
        set_result(res, RESULT_OVERFLOW, 0);
    if (*(u32_t *)(buf_ptr + sizeof(u32_t) + large_size) != 0xDECAFBADL)
        set_result(res, RESULT_OVERFLOW, 0);
}

static void setup_small_chunk_guards(u8_t *buf2_ptr, size_t small_size, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        u8_t *chunk_ptr = buf2_ptr + sizeof(u32_t) + i * (sizeof(u32_t) + small_size);
        *((u32_t *)chunk_ptr - 1) = 0xDEADBEEFL + i;
    }
    u8_t *last_ptr = buf2_ptr + sizeof(u32_t) + count * (sizeof(u32_t) + small_size);
    *((u32_t *)last_ptr - 1) = 0xFEEDFACEL;
}

static void check_small_chunk_guards(u8_t *buf2_ptr, size_t small_size, int count, result_t *res)
{
    int i;
    for (i = 0; i < count; i++) {
        u8_t *chunk_ptr = buf2_ptr + sizeof(u32_t) + i * (sizeof(u32_t) + small_size);
        if (*((u32_t *)chunk_ptr - 1) != 0xDEADBEEFL + i)
            set_result(res, RESULT_OVERFLOW, 0);
    }
    u8_t *last_ptr = buf2_ptr + sizeof(u32_t) + count * (sizeof(u32_t) + small_size);
    if (*((u32_t *)last_ptr - 1) != 0xFEEDFACEL)
        set_result(res, RESULT_OVERFLOW, 0);
}

static void setup_small_chunks_iovec(iovec_t *iovec, u8_t *buf2_ptr, size_t small_size, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        u8_t *chunk_ptr = buf2_ptr + sizeof(u32_t) + (i + 1) * sizeof(u32_t) + i * small_size;
        iovec[i].iov_addr = (vir_bytes)chunk_ptr;
        iovec[i].iov_size = small_size;
    }
}

static void verify_checksums(u8_t *buf_ptr, u8_t *buf2_ptr, size_t small_size, int count, result_t *res)
{
    int i;
    for (i = 0; i < count; i++) {
        u8_t *small_chunk = buf2_ptr + sizeof(u32_t) + (i + 1) * sizeof(u32_t) + i * small_size;
        u8_t *large_chunk = buf_ptr + sizeof(u32_t) + small_size * i;
        test_sum(small_chunk, small_size, get_sum(large_chunk, small_size), TRUE, res);
    }
}

static void perform_large_write(u8_t *buf_ptr, size_t buf_size, size_t large_size, u64_t base_pos)
{
    iovec_t iovec[1];
    result_t res;
    
    fill_rand(buf_ptr, buf_size);
    iovec[0].iov_addr = (vir_bytes)(buf_ptr + sizeof(u32_t));
    iovec[0].iov_size = large_size;
    vir_xfer(driver_minor, base_pos, iovec, 1, TRUE, large_size, &res);
    got_result(&res, "large write");
}

static void perform_vectored_read(u8_t *buf_ptr, u8_t *buf2_ptr, size_t small_size, size_t large_size, u64_t base_pos)
{
    iovec_t iovec[NR_IOREQS];
    result_t res;
    
    setup_small_chunk_guards(buf2_ptr, small_size, NR_IOREQS);
    setup_small_chunks_iovec(iovec, buf2_ptr, small_size, NR_IOREQS);
    vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, FALSE, large_size, &res);
    
    if (res.type == RESULT_OK) {
        check_small_chunk_guards(buf2_ptr, small_size, NR_IOREQS, &res);
        if (may_write) {
            verify_checksums(buf_ptr, buf2_ptr, small_size, NR_IOREQS, &res);
        }
    }
    got_result(&res, "vectored read");
}

static void perform_vectored_write(u8_t *buf2_ptr, size_t buf2_size, size_t small_size, size_t large_size, u64_t base_pos)
{
    iovec_t iovec[NR_IOREQS];
    result_t res;
    
    fill_rand(buf2_ptr, buf2_size);
    setup_small_chunks_iovec(iovec, buf2_ptr, small_size, NR_IOREQS);
    vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, TRUE, large_size, &res);
    got_result(&res, "vectored write");
}

static void perform_large_read(u8_t *buf_ptr, u8_t *buf2_ptr, size_t small_size, size_t large_size, u64_t base_pos)
{
    iovec_t iovec[1];
    result_t res;
    
    initialize_guards(buf_ptr, large_size);
    iovec[0].iov_addr = (vir_bytes)(buf_ptr + sizeof(u32_t));
    iovec[0].iov_size = large_size;
    vir_xfer(driver_minor, base_pos, iovec, 1, FALSE, large_size, &res);
    
    if (res.type == RESULT_OK) {
        check_guards(buf_ptr, large_size, &res);
        verify_checksums(buf_ptr, buf2_ptr, small_size, NR_IOREQS, &res);
    }
    got_result(&res, "large read");
}

static void vector_and_large_sub(size_t small_size)
{
    size_t large_size, buf_size, buf2_size;
    u8_t *buf_ptr, *buf2_ptr;
    u64_t base_pos;

    base_pos = (u64_t)sector_size;
    large_size = small_size * NR_IOREQS;
    buf_size = large_size + sizeof(u32_t) * 2;
    buf2_size = large_size + sizeof(u32_t) * (NR_IOREQS + 1);

    buf_ptr = alloc_dma_memory(buf_size);
    buf2_ptr = alloc_dma_memory(buf2_size);

    if (may_write) {
        perform_large_write(buf_ptr, buf_size, large_size, base_pos);
    }

    perform_vectored_read(buf_ptr, buf2_ptr, small_size, large_size, base_pos);

    if (may_write) {
        perform_vectored_write(buf2_ptr, buf2_size, small_size, large_size, base_pos);
    }

    perform_large_read(buf_ptr, buf2_ptr, small_size, large_size, base_pos);

    free_dma_memory(buf2_ptr, buf2_size);
    free_dma_memory(buf_ptr, buf_size);
}

static void adjust_max_size_for_device(void)
{
    const size_t DEVICE_MARGIN = sector_size * 4;
    
    if (max_size > part.size - DEVICE_MARGIN) {
        max_size = part.size - DEVICE_MARGIN;
    }
}

static size_t calculate_max_block_size(void)
{
    size_t max_block = max_size / NR_IOREQS;
    max_block -= max_block % sector_size;
    return max_block;
}

static void run_vector_test(const char *test_name, size_t block_size)
{
    test_group(test_name, TRUE);
    vector_and_large_sub(block_size);
}

static void vector_and_large(void)
{
    #define COMMON_BLOCK_SIZE 4096
    
    adjust_max_size_for_device();
    size_t max_block = calculate_max_block_size();
    
    run_vector_test("vector and large, common block", COMMON_BLOCK_SIZE);
    
    if (max_block != COMMON_BLOCK_SIZE) {
        run_vector_test("vector and large, large block", max_block);
    }
}

static void prepare_open_message(message *m, dev_t minor)
{
	memset(m, 0, sizeof(message));
	m->m_type = BDEV_OPEN;
	m->m_lbdev_lblockdriver_msg.minor = minor;
	m->m_lbdev_lblockdriver_msg.access = may_write ? (BDEV_R_BIT | BDEV_W_BIT) : BDEV_R_BIT;
	m->m_lbdev_lblockdriver_msg.id = lrand48();
}

static void record_opened_device(dev_t minor)
{
	assert(nr_opened < NR_OPENED);
	opened[nr_opened++] = minor;
}

static const char* get_partition_description(dev_t minor)
{
	return minor == driver_minor ? "opening the main partition" : "opening a subpartition";
}

static void open_device(dev_t minor)
{
	message m;
	result_t res;

	prepare_open_message(&m, minor);
	sendrec_driver(&m, OK, &res);
	record_opened_device(minor);
	got_result(&res, get_partition_description(minor));
}

static void close_device(dev_t minor)
{
	message m;
	result_t res;

	send_close_message(&m, &res, minor);
	remove_from_opened_devices(minor);
	report_close_result(&res, minor);
}

static void send_close_message(message *m, result_t *res, dev_t minor)
{
	memset(m, 0, sizeof(message));
	m->m_type = BDEV_CLOSE;
	m->m_lbdev_lblockdriver_msg.minor = minor;
	m->m_lbdev_lblockdriver_msg.id = lrand48();
	
	sendrec_driver(m, OK, res);
}

static void remove_from_opened_devices(dev_t minor)
{
	int device_index;
	
	assert(nr_opened > 0);
	
	device_index = find_device_index(minor);
	if (device_index >= 0) {
		replace_with_last_device(device_index);
		nr_opened--;
	}
}

static int find_device_index(dev_t minor)
{
	int i;
	
	for (i = 0; i < nr_opened; i++) {
		if (opened[i] == minor) {
			return i;
		}
	}
	return -1;
}

static void replace_with_last_device(int index)
{
	opened[index] = opened[nr_opened - 1];
}

static void report_close_result(result_t *res, dev_t minor)
{
	const char *operation_desc = get_operation_description(minor);
	got_result(res, operation_desc);
}

static const char* get_operation_description(dev_t minor)
{
	return (minor == driver_minor) ? "closing the main partition" : "closing a subpartition";
}

static int determine_grant_permissions(unsigned long req)
{
	int perm = 0;
	if (_MINIX_IOCTL_IOR(req)) perm |= CPF_WRITE;
	if (_MINIX_IOCTL_IOW(req)) perm |= CPF_READ;
	return perm;
}

static cp_grant_id_t allocate_grant(void *ptr, unsigned long req, int perm)
{
	cp_grant_id_t grant = cpf_grant_direct(driver_endpt, 
		(vir_bytes) ptr, _MINIX_IOCTL_SIZE(req), perm);
	if (grant == GRANT_INVALID)
		panic("unable to allocate grant");
	return grant;
}

static void prepare_ioctl_message(message *m, dev_t minor, unsigned long req, 
	cp_grant_id_t grant)
{
	memset(m, 0, sizeof(message));
	m->m_type = BDEV_IOCTL;
	m->m_lbdev_lblockdriver_msg.minor = minor;
	m->m_lbdev_lblockdriver_msg.request = req;
	m->m_lbdev_lblockdriver_msg.grant = grant;
	m->m_lbdev_lblockdriver_msg.user = NONE;
	m->m_lbdev_lblockdriver_msg.id = lrand48();
}

static void revoke_grant(cp_grant_id_t grant)
{
	if (cpf_revoke(grant) == -1)
		panic("unable to revoke grant");
}

static int vir_ioctl(dev_t minor, unsigned long req, void *ptr, ssize_t exp,
	result_t *res)
{
	cp_grant_id_t grant;
	message m;
	int r, perm;

	assert(!_MINIX_IOCTL_BIG(req));

	perm = determine_grant_permissions(req);
	grant = allocate_grant(ptr, req, perm);
	prepare_ioctl_message(&m, minor, req, grant);
	r = sendrec_driver(&m, exp, res);
	revoke_grant(grant);

	return r;
}

static void get_partition_info(result_t *res)
{
    vir_ioctl(driver_minor, DIOCGETP, &part, OK, res);
    got_result(res, "ioctl to get partition");
    
    if (res->type == RESULT_OK && part.size < (u64_t)max_size * 2)
        output("WARNING: small partition, some tests may fail\n");
}

static void verify_open_count(int expected_count, const char *test_description, result_t *res)
{
    int openct = 0x0badcafe;
    
    vir_ioctl(driver_minor, DIOCOPENCT, &openct, OK, res);
    
    if (res->type == RESULT_OK && openct != expected_count) {
        res->type = RESULT_BADVALUE;
        res->value = openct;
    }
    
    got_result(res, test_description);
}

static void test_open_count_changes(result_t *res)
{
    verify_open_count(1, "ioctl to get open count", res);
    
    open_device(driver_minor);
    verify_open_count(2, "increased open count after opening", res);
    
    close_device(driver_minor);
    verify_open_count(1, "decreased open count after closing", res);
}

static void misc_ioctl(void)
{
    result_t res;
    
    test_group("test miscellaneous ioctls", TRUE);
    
    get_partition_info(&res);
    test_open_count_changes(&res);
}

static void setup_test_buffer(u8_t **buf_ptr, size_t *buf_size)
{
	*buf_size = sector_size * 3;
	*buf_ptr = alloc_dma_memory(*buf_size);
}

static void test_read_up_to_limit(dev_t minor, u64_t sub_size, u8_t *buf_ptr, 
                                   size_t buf_size, u32_t *sum, u32_t *sum2)
{
	result_t res;
	
	fill_rand(buf_ptr, buf_size);
	simple_xfer(minor, sub_size - sector_size, buf_ptr, sector_size, 
	            FALSE, sector_size, &res);
	*sum = get_sum(buf_ptr, sector_size);
	got_result(&res, "one sector read up to partition end");

	fill_rand(buf_ptr, buf_size);
	simple_xfer(minor, sub_size - buf_size, buf_ptr, buf_size,
	            FALSE, buf_size, &res);
	test_sum(buf_ptr + sector_size * 2, sector_size, *sum, TRUE, &res);
	*sum2 = get_sum(buf_ptr + sector_size, sector_size * 2);
	got_result(&res, "multisector read up to partition end");
}

static void test_read_across_limit(dev_t minor, u64_t sub_size, u8_t *buf_ptr,
                                    size_t buf_size, u32_t sum, u32_t sum2)
{
	result_t res;
	u32_t sum3;
	
	fill_rand(buf_ptr, buf_size);
	sum3 = get_sum(buf_ptr + sector_size * 2, sector_size);
	simple_xfer(minor, sub_size - sector_size * 2, buf_ptr, buf_size, 
	            FALSE, sector_size * 2, &res);
	test_sum(buf_ptr, sector_size * 2, sum2, TRUE, &res);
	test_sum(buf_ptr + sector_size * 2, sector_size, sum3, TRUE, &res);
	got_result(&res, "read somewhat across partition end");

	fill_rand(buf_ptr, buf_size);
	sum2 = get_sum(buf_ptr + sector_size, sector_size * 2);
	simple_xfer(minor, sub_size - sector_size, buf_ptr, buf_size, 
	            FALSE, sector_size, &res);
	test_sum(buf_ptr, sector_size, sum, TRUE, &res);
	test_sum(buf_ptr + sector_size, sector_size * 2, sum2, TRUE, &res);
	got_result(&res, "read mostly across partition end");
}

static void test_read_at_limit(dev_t minor, u64_t sub_size, u8_t *buf_ptr,
                                size_t buf_size)
{
	result_t res;
	u32_t sum, sum2;
	
	sum = fill_rand(buf_ptr, buf_size);
	sum2 = get_sum(buf_ptr, sector_size);
	
	simple_xfer(minor, sub_size, buf_ptr, sector_size, FALSE, 0, &res);
	test_sum(buf_ptr, sector_size, sum2, TRUE, &res);
	got_result(&res, "one sector read at partition end");

	simple_xfer(minor, sub_size, buf_ptr, buf_size, FALSE, 0, &res);
	test_sum(buf_ptr, buf_size, sum, TRUE, &res);
	got_result(&res, "multisector read at partition end");
}

static void test_read_beyond_limit(dev_t minor, u64_t sub_size, u8_t *buf_ptr,
                                    size_t buf_size)
{
	result_t res;
	u32_t sum, sum2;
	
	sum = fill_rand(buf_ptr, buf_size);
	sum2 = get_sum(buf_ptr, sector_size);
	
	simple_xfer(minor, sub_size + sector_size, buf_ptr, buf_size, 
	            FALSE, 0, &res);
	test_sum(buf_ptr, sector_size, sum2, TRUE, &res);
	got_result(&res, "single sector read beyond partition end");

	simple_xfer(minor, 0x1000000000000000ULL, buf_ptr, buf_size,
	            FALSE, 0, &res);
	test_sum(buf_ptr, buf_size, sum, TRUE, &res);
}

static void test_negative_offset(dev_t minor, u8_t *buf_ptr)
{
	result_t res;
	u32_t sum2 = get_sum(buf_ptr, sector_size);
	
	simple_xfer(minor, 0xffffffffffffffffULL - sector_size + 1,
	            buf_ptr, sector_size, FALSE, 0, &res);
	test_sum(buf_ptr, sector_size, sum2, TRUE, &res);
	got_result(&res, "read with negative offset");
}

static void read_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size)
{
	u8_t *buf_ptr;
	size_t buf_size;
	u32_t sum, sum2;

	test_group("read around subpartition limits", TRUE);
	
	setup_test_buffer(&buf_ptr, &buf_size);
	test_read_up_to_limit(sub0_minor, sub_size, buf_ptr, buf_size, &sum, &sum2);
	test_read_across_limit(sub0_minor, sub_size, buf_ptr, buf_size, sum, sum2);
	test_read_at_limit(sub0_minor, sub_size, buf_ptr, buf_size);
	test_read_beyond_limit(sub0_minor, sub_size, buf_ptr, buf_size);
	test_negative_offset(sub1_minor, buf_ptr);
	
	free_dma_memory(buf_ptr, buf_size);
}

#define SECTORS_IN_TEST 3
#define SINGLE_SECTOR 1
#define TWO_SECTORS 2

static void write_to_second_subpartition(dev_t sub1_minor, u8_t *buf_ptr, size_t buf_size, u32_t *sub1_sum)
{
    result_t res;
    *sub1_sum = fill_rand(buf_ptr, buf_size);
    simple_xfer(sub1_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
    got_result(&res, "write to second subpartition");
}

static void test_write_up_to_partition_end(dev_t sub0_minor, size_t sub_size, u8_t *buf_ptr, u32_t *sum)
{
    result_t res;
    *sum = fill_rand(buf_ptr, sector_size);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr, sector_size, TRUE, sector_size, &res);
    got_result(&res, "write up to partition end");
}

static void verify_write_up_to_partition_end(dev_t sub0_minor, size_t sub_size, u8_t *buf_ptr, u32_t sum)
{
    result_t res;
    fill_rand(buf_ptr, sector_size * TWO_SECTORS);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size * TWO_SECTORS, buf_ptr, sector_size * TWO_SECTORS, FALSE, sector_size * TWO_SECTORS, &res);
    test_sum(buf_ptr + sector_size, sector_size, sum, TRUE, &res);
    got_result(&res, "read up to partition end");
}

static void test_write_across_partition_boundary(dev_t sub0_minor, size_t sub_size, u8_t *buf_ptr, size_t buf_size, u32_t *sum, u32_t *sum3)
{
    result_t res;
    fill_rand(buf_ptr, buf_size);
    *sum = get_sum(buf_ptr + sector_size, sector_size);
    *sum3 = get_sum(buf_ptr, sector_size);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size * TWO_SECTORS, buf_ptr, buf_size, TRUE, sector_size * TWO_SECTORS, &res);
    got_result(&res, "write somewhat across partition end");
}

static void test_read_across_partition_boundary(dev_t sub0_minor, size_t sub_size, u8_t *buf_ptr, size_t buf_size, u32_t sum)
{
    result_t res;
    fill_rand(buf_ptr, buf_size);
    u32_t sum2 = get_sum(buf_ptr + sector_size, sector_size * TWO_SECTORS);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr, buf_size, FALSE, sector_size, &res);
    test_sum(buf_ptr, sector_size, sum, TRUE, &res);
    test_sum(buf_ptr + sector_size, sector_size * TWO_SECTORS, sum2, TRUE, &res);
    got_result(&res, "read mostly across partition end");
}

static void test_write_mostly_across_boundary(dev_t sub0_minor, size_t sub_size, u8_t *buf_ptr, size_t buf_size, u32_t *sum)
{
    result_t res;
    fill_rand(buf_ptr, buf_size);
    *sum = get_sum(buf_ptr, sector_size);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr, buf_size, TRUE, sector_size, &res);
    got_result(&res, "write mostly across partition end");
}

static void test_read_somewhat_across_boundary(dev_t sub0_minor, size_t sub_size, u8_t *buf_ptr, size_t buf_size, u32_t sum3, u32_t sum)
{
    result_t res;
    fill_rand(buf_ptr, buf_size);
    u32_t sum2 = get_sum(buf_ptr + sector_size * TWO_SECTORS, sector_size);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size * TWO_SECTORS, buf_ptr, buf_size, FALSE, sector_size * TWO_SECTORS, &res);
    test_sum(buf_ptr, sector_size, sum3, TRUE, &res);
    test_sum(buf_ptr + sector_size, sector_size, sum, TRUE, &res);
    test_sum(buf_ptr + sector_size * TWO_SECTORS, sector_size, sum2, TRUE, &res);
    got_result(&res, "read somewhat across partition end");
}

static void test_write_at_and_beyond_end(dev_t sub0_minor, size_t sub_size, u8_t *buf_ptr)
{
    result_t res;
    fill_rand(buf_ptr, sector_size);
    simple_xfer(sub0_minor, (u64_t)sub_size, buf_ptr, sector_size, TRUE, 0, &res);
    got_result(&res, "write at partition end");
    
    simple_xfer(sub0_minor, (u64_t)sub_size + sector_size, buf_ptr, sector_size, TRUE, 0, &res);
    got_result(&res, "write beyond partition end");
}

static void verify_second_subpartition_unchanged(dev_t sub1_minor, u8_t *buf_ptr, size_t buf_size, u32_t sub1_sum)
{
    result_t res;
    fill_rand(buf_ptr, buf_size);
    simple_xfer(sub1_minor, 0ULL, buf_ptr, buf_size, FALSE, buf_size, &res);
    test_sum(buf_ptr, buf_size, sub1_sum, TRUE, &res);
    got_result(&res, "read from second subpartition");
}

static void test_negative_offset_write(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size, u8_t *buf_ptr, u32_t sum)
{
    result_t res;
    fill_rand(buf_ptr, sector_size);
    simple_xfer(sub1_minor, 0xffffffffffffffffULL - sector_size + 1, buf_ptr, sector_size, TRUE, 0, &res);
    got_result(&res, "write with negative offset");
    
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr, sector_size, FALSE, sector_size, &res);
    test_sum(buf_ptr, sector_size, sum, TRUE, &res);
    got_result(&res, "read up to partition end");
}

static void write_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size)
{
    u8_t *buf_ptr;
    size_t buf_size;
    u32_t sum, sum3, sub1_sum;

    test_group("write around subpartition limits", may_write);

    if (!may_write)
        return;

    buf_size = sector_size * SECTORS_IN_TEST;
    buf_ptr = alloc_dma_memory(buf_size);

    write_to_second_subpartition(sub1_minor, buf_ptr, buf_size, &sub1_sum);
    test_write_up_to_partition_end(sub0_minor, sub_size, buf_ptr, &sum);
    verify_write_up_to_partition_end(sub0_minor, sub_size, buf_ptr, sum);
    test_write_across_partition_boundary(sub0_minor, sub_size, buf_ptr, buf_size, &sum, &sum3);
    test_read_across_partition_boundary(sub0_minor, sub_size, buf_ptr, buf_size, sum);
    test_write_mostly_across_boundary(sub0_minor, sub_size, buf_ptr, buf_size, &sum);
    test_read_somewhat_across_boundary(sub0_minor, sub_size, buf_ptr, buf_size, sum3, sum);
    test_write_at_and_beyond_end(sub0_minor, sub_size, buf_ptr);
    verify_second_subpartition_unchanged(sub1_minor, buf_ptr, buf_size, sub1_sum);
    test_negative_offset_write(sub0_minor, sub1_minor, sub_size, buf_ptr, sum);

    free_dma_memory(buf_ptr, buf_size);
}

static void set_and_verify_subpartition(dev_t minor, struct part_geom *subpart, const char *description)
{
	struct part_geom subpart2;
	result_t res;

	vir_ioctl(minor, DIOCSETP, subpart, OK, &res);
	got_result(&res, description);

	vir_ioctl(minor, DIOCGETP, &subpart2, OK, &res);

	if (res.type == RESULT_OK && (subpart->base != subpart2.base ||
			subpart->size != subpart2.size)) {
		res.type = RESULT_BADVALUE;
		res.value = 0;
	}

	char verify_desc[128];
	snprintf(verify_desc, sizeof(verify_desc), "ioctl to get %s", description + 14);
	got_result(&res, verify_desc);
}

static void vir_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
	struct part_geom subpart;
	size_t sub_size;

	test_group("virtual subpartition limits", TRUE);

	open_device(sub0_minor);
	open_device(sub1_minor);

	sub_size = sector_size * part_secs;

	subpart = part;
	subpart.size = (u64_t)sub_size;
	set_and_verify_subpartition(sub0_minor, &subpart, "ioctl to set first subpartition");

	subpart = part;
	subpart.base += sub_size;
	subpart.size = (u64_t)sub_size;
	set_and_verify_subpartition(sub1_minor, &subpart, "ioctl to set second subpartition");

	read_limits(sub0_minor, sub1_minor, sub_size);
	write_limits(sub0_minor, sub1_minor, sub_size);

	close_device(sub1_minor);
	close_device(sub0_minor);
}

static void write_partition_table(u8_t *buf_ptr, size_t buf_size, int valid, int part_secs)
{
	result_t res;
	
	memset(buf_ptr, 0, buf_size);
	
	if (valid) {
		struct part_entry *entry = (struct part_entry *) &buf_ptr[PART_TABLE_OFF];
		
		entry[0].sysind = MINIX_PART;
		entry[0].lowsec = part.base / sector_size + 1;
		entry[0].size = part_secs;
		entry[1].sysind = MINIX_PART;
		entry[1].lowsec = entry[0].lowsec + entry[0].size;
		entry[1].size = part_secs;
		
		buf_ptr[510] = 0x55;
		buf_ptr[511] = 0xAA;
	}
	
	simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
	got_result(&res, valid ? "write of valid partition table" : "write of invalid partition table");
}

static void reopen_driver(void)
{
	close_device(driver_minor);
	open_device(driver_minor);
}

static void verify_subpartition_size(dev_t minor, u64_t expected_size, const char *description)
{
	struct part_geom subpart;
	result_t res;
	
	vir_ioctl(minor, DIOCGETP, &subpart, 0, &res);
	
	if (res.type == RESULT_OK && subpart.size != expected_size) {
		res.type = RESULT_BADVALUE;
		res.value = expected_size ? 0 : ex64lo(subpart.size);
	}
	
	got_result(&res, description);
}

static void verify_subpartition_geometry(dev_t minor, u64_t expected_base, u64_t expected_size, const char *description)
{
	struct part_geom subpart;
	result_t res;
	
	vir_ioctl(minor, DIOCGETP, &subpart, 0, &res);
	
	if (res.type == RESULT_OK && 
		(subpart.base != expected_base || subpart.size != expected_size)) {
		res.type = RESULT_BADVALUE;
		res.value = 0;
	}
	
	got_result(&res, description);
}

static void open_subpartitions(dev_t sub0_minor, dev_t sub1_minor)
{
	open_device(sub0_minor);
	open_device(sub1_minor);
}

static void close_subpartitions(dev_t sub0_minor, dev_t sub1_minor)
{
	close_device(sub0_minor);
	close_device(sub1_minor);
}

static void test_invalid_partition_table(u8_t *buf_ptr, size_t buf_size, dev_t sub0_minor, dev_t sub1_minor)
{
	write_partition_table(buf_ptr, buf_size, 0, 0);
	reopen_driver();
	open_subpartitions(sub0_minor, sub1_minor);
	verify_subpartition_size(sub0_minor, 0, "ioctl to get first subpartition");
	verify_subpartition_size(sub1_minor, 0, "ioctl to get second subpartition");
	close_subpartitions(sub1_minor, sub0_minor);
}

static void test_valid_partition_table(u8_t *buf_ptr, size_t buf_size, dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
	u64_t first_base = part.base + sector_size;
	u64_t first_size = (u64_t)part_secs * sector_size;
	u64_t second_base = part.base + (1 + part_secs) * sector_size;
	u64_t second_size = (u64_t)part_secs * sector_size;
	
	write_partition_table(buf_ptr, buf_size, 1, part_secs);
	reopen_driver();
	open_subpartitions(sub0_minor, sub1_minor);
	verify_subpartition_geometry(sub0_minor, first_base, first_size, "ioctl to get first subpartition");
	verify_subpartition_geometry(sub1_minor, second_base, second_size, "ioctl to get second subpartition");
}

static void real_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
	u8_t *buf_ptr;
	size_t buf_size, sub_size;

	test_group("real subpartition limits", may_write);

	if (!may_write)
		return;

	sub_size = sector_size * part_secs;
	buf_size = sector_size;
	buf_ptr = alloc_dma_memory(buf_size);

	test_invalid_partition_table(buf_ptr, buf_size, sub0_minor, sub1_minor);
	test_valid_partition_table(buf_ptr, buf_size, sub0_minor, sub1_minor, part_secs);

	read_limits(sub0_minor, sub1_minor, sub_size);
	write_limits(sub0_minor, sub1_minor, sub_size);

	close_subpartitions(sub0_minor, sub1_minor);
	free_dma_memory(buf_ptr, buf_size);
}

static void part_limits(void)
{
	dev_t par, sub0_minor, sub1_minor;

	if (driver_minor >= MINOR_d0p0s0) {
		output("WARNING: operating on subpartition, "
			"skipping partition tests\n");
		return;
	}
	
	par = driver_minor % DEV_PER_DRIVE;
	sub0_minor = calculate_sub0_minor(par);
	sub1_minor = sub0_minor + 1;

	#define PART_SECS	9

	vir_limits(sub0_minor, sub1_minor, PART_SECS);
	real_limits(sub0_minor, sub1_minor, PART_SECS - 1);
}

static dev_t calculate_sub0_minor(dev_t par)
{
	if (par > 0) {
		return MINOR_d0p0s0 + ((driver_minor / DEV_PER_DRIVE) *
			NR_PARTITIONS + par - 1) * NR_PARTITIONS;
	}
	return driver_minor + 1;
}

#define MAX_ELEMENTS 3
#define PATTERN_LEFT 0
#define PATTERN_RIGHT 1
#define PATTERN_BOTH 2

static void setup_left_pattern(iovec_t *iovt, u8_t *sec_ptr, u8_t *buf_ptr, 
    size_t total_size, u32_t *rsum)
{
    iovt[0].iov_addr = (vir_bytes) sec_ptr;
    iovt[0].iov_size = element_size;
    iovt[1].iov_addr = (vir_bytes) buf_ptr;
    iovt[1].iov_size = total_size - element_size;
    rsum[1] = get_sum(buf_ptr + iovt[1].iov_size, element_size);
}

static void setup_right_pattern(iovec_t *iovt, u8_t *sec_ptr, u8_t *buf_ptr, 
    size_t total_size, u32_t *rsum)
{
    iovt[0].iov_addr = (vir_bytes) buf_ptr;
    iovt[0].iov_size = total_size - element_size;
    rsum[1] = get_sum(buf_ptr + iovt[0].iov_size, element_size);
    iovt[1].iov_addr = (vir_bytes) sec_ptr;
    iovt[1].iov_size = element_size;
}

static void setup_both_pattern(iovec_t *iovt, u8_t **sec_ptr, u8_t *buf_ptr, 
    size_t total_size, u32_t *rsum)
{
    iovt[0].iov_addr = (vir_bytes) sec_ptr[0];
    iovt[0].iov_size = element_size;
    iovt[1].iov_addr = (vir_bytes) buf_ptr;
    iovt[1].iov_size = total_size - element_size * 2;
    rsum[1] = get_sum(buf_ptr + iovt[1].iov_size, element_size * 2);
    
    fill_rand(sec_ptr[1], sector_size);
    iovt[2].iov_addr = (vir_bytes) sec_ptr[1];
    iovt[2].iov_size = element_size;
    rsum[2] = get_sum(sec_ptr[1] + element_size, sector_size - element_size);
}

static int setup_io_pattern(int pattern, iovec_t *iovt, u8_t **sec_ptr, 
    u8_t *buf_ptr, size_t total_size, u32_t *rsum)
{
    switch (pattern) {
    case PATTERN_LEFT:
        setup_left_pattern(iovt, sec_ptr[0], buf_ptr, total_size, rsum);
        return 2;
    case PATTERN_RIGHT:
        setup_right_pattern(iovt, sec_ptr[0], buf_ptr, total_size, rsum);
        return 2;
    case PATTERN_BOTH:
        setup_both_pattern(iovt, sec_ptr, buf_ptr, total_size, rsum);
        return 3;
    default:
        assert(0);
        return 0;
    }
}

static void adjust_buffer_left_pattern(u8_t *buf_ptr, u8_t *sec_ptr, 
    size_t iov_size)
{
    memmove(buf_ptr + element_size, buf_ptr, iov_size);
    memcpy(buf_ptr, sec_ptr, element_size);
}

static void adjust_buffer_right_pattern(u8_t *buf_ptr, u8_t *sec_ptr, 
    size_t iov_size)
{
    memcpy(buf_ptr + iov_size, sec_ptr, element_size);
}

static void adjust_buffer_both_pattern(u8_t *buf_ptr, u8_t **sec_ptr, 
    size_t iov_size)
{
    memmove(buf_ptr + element_size, buf_ptr, iov_size);
    memcpy(buf_ptr, sec_ptr[0], element_size);
    memcpy(buf_ptr + element_size + iov_size, sec_ptr[1], element_size);
}

static void verify_read_results(int pattern, u8_t **sec_ptr, u8_t *buf_ptr, 
    iovec_t *iovt, u32_t *rsum, result_t *res)
{
    test_sum(sec_ptr[0] + element_size, sector_size - element_size, 
        rsum[0], TRUE, res);
    
    switch (pattern) {
    case PATTERN_LEFT:
        test_sum(buf_ptr + iovt[1].iov_size, element_size, rsum[1], TRUE, res);
        adjust_buffer_left_pattern(buf_ptr, sec_ptr[0], iovt[1].iov_size);
        break;
    case PATTERN_RIGHT:
        test_sum(buf_ptr + iovt[0].iov_size, element_size, rsum[1], TRUE, res);
        adjust_buffer_right_pattern(buf_ptr, sec_ptr[0], iovt[0].iov_size);
        break;
    case PATTERN_BOTH:
        test_sum(buf_ptr + iovt[1].iov_size, element_size * 2, rsum[1], 
            TRUE, res);
        test_sum(sec_ptr[1] + element_size, sector_size - element_size, 
            rsum[2], TRUE, res);
        adjust_buffer_both_pattern(buf_ptr, sec_ptr, iovt[1].iov_size);
        break;
    }
}

static void prepare_write_left_pattern(u8_t *buf_ptr, u8_t *sec_ptr, 
    size_t iov_size)
{
    memcpy(sec_ptr, buf_ptr, element_size);
    memmove(buf_ptr, buf_ptr + element_size, iov_size);
    fill_rand(buf_ptr + iov_size, element_size);
}

static void prepare_write_right_pattern(u8_t *buf_ptr, u8_t *sec_ptr, 
    size_t iov_size)
{
    memcpy(sec_ptr, buf_ptr + iov_size, element_size);
    fill_rand(buf_ptr + iov_size, element_size);
}

static void prepare_write_both_pattern(u8_t *buf_ptr, u8_t **sec_ptr, 
    size_t iov_size)
{
    memcpy(sec_ptr[0], buf_ptr, element_size);
    memcpy(sec_ptr[1], buf_ptr + element_size + iov_size, element_size);
    memmove(buf_ptr, buf_ptr + element_size, iov_size);
    fill_rand(buf_ptr + iov_size, element_size * 2);
}

static void prepare_write_data(int pattern, u8_t **sec_ptr, u8_t *buf_ptr, 
    iovec_t *iovt, u32_t *ssum, int sectors)
{
    int i;
    
    for (i = 0; i < sectors; i++)
        ssum[1 + i] = fill_rand(buf_ptr + sector_size * i, sector_size);
    
    switch (pattern) {
    case PATTERN_LEFT:
        prepare_write_left_pattern(buf_ptr, sec_ptr[0], iovt[1].iov_size);
        break;
    case PATTERN_RIGHT:
        prepare_write_right_pattern(buf_ptr, sec_ptr[0], iovt[0].iov_size);
        break;
    case PATTERN_BOTH:
        prepare_write_both_pattern(buf_ptr, sec_ptr, iovt[1].iov_size);
        break;
    }
}

static void perform_read_test(u64_t base_pos, u8_t **sec_ptr, u8_t *buf_ptr, 
    iovec_t *iovt, int nr_req, size_t total_size, int pattern, 
    u32_t *rsum, u32_t *ssum, int sectors)
{
    iovec_t iov[MAX_ELEMENTS];
    result_t res;
    int i;
    
    memcpy(iov, iovt, sizeof(iov));
    vir_xfer(driver_minor, base_pos, iov, nr_req, FALSE, total_size, &res);
    
    verify_read_results(pattern, sec_ptr, buf_ptr, iovt, rsum, &res);
    
    for (i = 0; i < sectors; i++)
        test_sum(buf_ptr + sector_size * i, sector_size, ssum[1 + i], 
            TRUE, &res);
    
    got_result(&res, "read with small elements");
}

static void perform_write_test(u64_t base_pos, u8_t **sec_ptr, u8_t *buf_ptr, 
    iovec_t *iovt, int nr_req, size_t total_size, int pattern, u32_t *ssum, 
    int sectors)
{
    iovec_t iov[MAX_ELEMENTS];
    result_t res;
    int i;
    
    prepare_write_data(pattern, sec_ptr, buf_ptr, iovt, ssum, sectors);
    
    memcpy(iov, iovt, sizeof(iov));
    vir_xfer(driver_minor, base_pos, iov, nr_req, TRUE, total_size, &res);
    got_result(&res, "write with small elements");
    
    fill_rand(buf_ptr, sector_size * 3);
    simple_xfer(driver_minor, base_pos, buf_ptr, sector_size * 3, FALSE,
        sector_size * 3, &res);
    
    for (i = 0; i < 3; i++)
        test_sum(buf_ptr + sector_size * i, sector_size, ssum[1 + i], 
            TRUE, &res);
    
    got_result(&res, "readback verification");
}

static void unaligned_size_io(u64_t base_pos, u8_t *buf_ptr, size_t buf_size,
    u8_t *sec_ptr[2], int sectors, int pattern, u32_t ssum[5])
{
    iovec_t iovt[MAX_ELEMENTS];
    u32_t rsum[MAX_ELEMENTS];
    size_t total_size;
    int nr_req;
    
    base_pos += sector_size;
    total_size = sector_size * sectors;
    
    if (sector_size / element_size == 2 && sectors == 1 && pattern == 2)
        return;
    
    fill_rand(sec_ptr[0], sector_size);
    rsum[0] = get_sum(sec_ptr[0] + element_size, sector_size - element_size);
    fill_rand(buf_ptr, buf_size);
    
    nr_req = setup_io_pattern(pattern, iovt, sec_ptr, buf_ptr, total_size, rsum);
    
    perform_read_test(base_pos, sec_ptr, buf_ptr, iovt, nr_req, total_size, 
        pattern, rsum, ssum, sectors);
    
    if (!may_write)
        return;
    
    perform_write_test(base_pos, sec_ptr, buf_ptr, iovt, nr_req, total_size, 
        pattern, ssum, sectors);
}

static void initialize_test_buffers(u8_t **buf_ptr, u8_t **sec_ptr, size_t buf_size) {
	*buf_ptr = alloc_dma_memory(buf_size);
	sec_ptr[0] = alloc_dma_memory(sector_size);
	sec_ptr[1] = alloc_dma_memory(sector_size);
}

static void cleanup_test_buffers(u8_t *buf_ptr, u8_t **sec_ptr, size_t buf_size) {
	free_dma_memory(sec_ptr[1], sector_size);
	free_dma_memory(sec_ptr[0], sector_size);
	free_dma_memory(buf_ptr, buf_size);
}

static void calculate_sector_sums(u8_t *buf_ptr, u32_t *ssum) {
	int i;
	for (i = 0; i < 5; i++) {
		ssum[i] = get_sum(buf_ptr + sector_size * i, sector_size);
	}
}

static u32_t write_baseline_data(u64_t base_pos, u8_t *buf_ptr, size_t buf_size, u32_t *ssum) {
	u32_t sum;
	result_t res;
	
	sum = fill_rand(buf_ptr, buf_size);
	calculate_sector_sums(buf_ptr, ssum);
	simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE, buf_size, &res);
	got_result(&res, "write several sectors");
	
	return sum;
}

static void read_baseline_data(u64_t base_pos, u8_t *buf_ptr, size_t buf_size, u32_t sum, u32_t *ssum) {
	result_t res;
	
	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);
	
	if (may_write) {
		test_sum(buf_ptr, buf_size, sum, TRUE, &res);
	} else {
		calculate_sector_sums(buf_ptr, ssum);
	}
	
	got_result(&res, "read several sectors");
}

static void run_unaligned_subtests(u64_t base_pos, u8_t *buf_ptr, size_t buf_size, u8_t **sec_ptr, u32_t *ssum) {
	int i;
	
	#define SUBTEST_COUNT 9
	#define TRIPLET_SIZE 3
	
	for (i = 0; i < SUBTEST_COUNT; i++) {
		unaligned_size_io(base_pos, buf_ptr, buf_size, sec_ptr,
			i / TRIPLET_SIZE + 1, i % TRIPLET_SIZE, ssum);
	}
}

static void verify_untouched_sectors(u64_t base_pos, u8_t *buf_ptr, size_t buf_size, u32_t *ssum) {
	result_t res;
	
	if (!may_write)
		return;
	
	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);
	test_sum(buf_ptr, sector_size, ssum[0], TRUE, &res);
	test_sum(buf_ptr + sector_size * 4, sector_size, ssum[4], TRUE, &res);
	got_result(&res, "check first and last sectors");
}

static void unaligned_size(void) {
	u8_t *buf_ptr, *sec_ptr[2];
	size_t buf_size;
	u32_t sum = 0L, ssum[5];
	u64_t base_pos;
	
	#define SECTOR_COUNT 5
	#define BASE_SECTOR_OFFSET 2
	
	test_group("sector-unaligned elements", sector_size != element_size);
	
	if (sector_size == element_size)
		return;
	
	assert(sector_size % element_size == 0);
	
	buf_size = sector_size * SECTOR_COUNT;
	base_pos = (u64_t)sector_size * BASE_SECTOR_OFFSET;
	
	initialize_test_buffers(&buf_ptr, sec_ptr, buf_size);
	
	if (may_write) {
		sum = write_baseline_data(base_pos, buf_ptr, buf_size, ssum);
	}
	
	read_baseline_data(base_pos, buf_ptr, buf_size, sum, ssum);
	run_unaligned_subtests(base_pos, buf_ptr, buf_size, sec_ptr, ssum);
	verify_untouched_sectors(base_pos, buf_ptr, buf_size, ssum);
	
	cleanup_test_buffers(buf_ptr, sec_ptr, buf_size);
}

static void setup_test_buffers(size_t size, u8_t **buf_ptr, u8_t **buf2_ptr)
{
	*buf_ptr = alloc_dma_memory(size);
	*buf2_ptr = alloc_dma_memory(size);
}

static void cleanup_buffers(u8_t *buf_ptr, u8_t *buf2_ptr, size_t size)
{
	free_dma_memory(buf2_ptr, size);
	free_dma_memory(buf_ptr, size);
}

static void establish_baseline(u64_t base_pos, u8_t *buf_ptr, size_t buf_size)
{
	result_t res;
	u32_t sum;

	if (may_write) {
		sum = fill_rand(buf_ptr, buf_size);
		simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE,
			buf_size, &res);
		got_result(&res, "write several sectors");
	}

	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);
	
	if (may_write)
		test_sum(buf_ptr, buf_size, sum, TRUE, &res);
	
	got_result(&res, "read several sectors");
}

static void test_single_sector_lead(u64_t base_pos, u8_t *buf_ptr, u8_t *buf2_ptr)
{
	result_t res;
	u32_t sum;

	fill_rand(buf2_ptr, sector_size);
	sum = get_sum(buf2_ptr + min_read, sector_size - min_read);

	simple_xfer(driver_minor, base_pos + sector_size - min_read,
		buf2_ptr, min_read, FALSE, min_read, &res);

	test_sum(buf2_ptr, min_read, get_sum(buf_ptr + sector_size - min_read,
		min_read), TRUE, &res);
	test_sum(buf2_ptr + min_read, sector_size - min_read, sum, TRUE, &res);

	got_result(&res, "single sector read with lead");
}

static void test_single_sector_trail(u64_t base_pos, u8_t *buf_ptr, u8_t *buf2_ptr)
{
	result_t res;
	u32_t sum;

	fill_rand(buf2_ptr, sector_size);
	sum = get_sum(buf2_ptr, sector_size - min_read);

	simple_xfer(driver_minor, base_pos, buf2_ptr + sector_size - min_read,
		min_read, FALSE, min_read, &res);

	test_sum(buf2_ptr + sector_size - min_read, min_read, get_sum(buf_ptr,
		min_read), TRUE, &res);
	test_sum(buf2_ptr, sector_size - min_read, sum, TRUE, &res);

	got_result(&res, "single sector read with trail");
}

static void test_single_sector_lead_trail(u64_t base_pos, u8_t *buf_ptr, u8_t *buf2_ptr)
{
	result_t res;
	u32_t sum, sum2;

	fill_rand(buf2_ptr, sector_size);
	sum = get_sum(buf2_ptr, min_read);
	sum2 = get_sum(buf2_ptr + min_read * 2, sector_size - min_read * 2);

	simple_xfer(driver_minor, base_pos + min_read, buf2_ptr + min_read,
		min_read, FALSE, min_read, &res);

	test_sum(buf2_ptr + min_read, min_read, get_sum(buf_ptr + min_read,
		min_read), TRUE, &res);
	test_sum(buf2_ptr, min_read, sum, TRUE, &res);
	test_sum(buf2_ptr + min_read * 2, sector_size - min_read * 2, sum2,
		TRUE, &res);

	got_result(&res, "single sector read with lead and trail");
}

static void test_multisector_lead(u64_t base_pos, u8_t *buf_ptr, u8_t *buf2_ptr, size_t buf2_size)
{
	result_t res;
	u32_t sum;
	size_t size = min_read + sector_size * 2;

	fill_rand(buf2_ptr, buf2_size);
	sum = get_sum(buf2_ptr + size, buf2_size - size);

	simple_xfer(driver_minor, base_pos + sector_size - min_read, buf2_ptr,
		size, FALSE, size, &res);

	test_sum(buf2_ptr, size, get_sum(buf_ptr + sector_size - min_read,
		size), TRUE, &res);
	test_sum(buf2_ptr + size, buf2_size - size, sum, TRUE, &res);

	got_result(&res, "multisector read with lead");
}

static void test_multisector_trail(u64_t base_pos, u8_t *buf_ptr, u8_t *buf2_ptr, size_t buf2_size)
{
	result_t res;
	u32_t sum;
	size_t size = min_read + sector_size * 2;

	fill_rand(buf2_ptr, buf2_size);
	sum = get_sum(buf2_ptr + size, buf2_size - size);

	simple_xfer(driver_minor, base_pos, buf2_ptr, size, FALSE, size, &res);

	test_sum(buf2_ptr, size, get_sum(buf_ptr, size), TRUE, &res);
	test_sum(buf2_ptr + size, buf2_size - size, sum, TRUE, &res);

	got_result(&res, "multisector read with trail");
}

static void test_multisector_lead_trail(u64_t base_pos, u8_t *buf_ptr, u8_t *buf2_ptr, size_t buf2_size)
{
	result_t res;
	u32_t sum;

	fill_rand(buf2_ptr, buf2_size);
	sum = get_sum(buf2_ptr + sector_size, buf2_size - sector_size);

	simple_xfer(driver_minor, base_pos + min_read, buf2_ptr, sector_size,
		FALSE, sector_size, &res);

	test_sum(buf2_ptr, sector_size, get_sum(buf_ptr + min_read,
		sector_size), TRUE, &res);
	test_sum(buf2_ptr + sector_size, buf2_size - sector_size, sum, TRUE,
		&res);

	got_result(&res, "multisector read with lead and trail");
}

#define SECTORS_TO_TEST 3

static void unaligned_pos1(void)
{
	u8_t *buf_ptr, *buf2_ptr;
	size_t buf_size, buf2_size;
	u64_t base_pos;

	test_group("sector-unaligned positions, part one",
		min_read != sector_size);

	if (min_read == sector_size)
		return;

	assert(sector_size % min_read == 0);
	assert(min_read % element_size == 0);

	buf_size = buf2_size = sector_size * SECTORS_TO_TEST;
	base_pos = (u64_t)sector_size * SECTORS_TO_TEST;

	setup_test_buffers(buf_size, &buf_ptr, &buf2_ptr);

	establish_baseline(base_pos, buf_ptr, buf_size);

	test_single_sector_lead(base_pos, buf_ptr, buf2_ptr);
	test_single_sector_trail(base_pos, buf_ptr, buf2_ptr);
	test_single_sector_lead_trail(base_pos, buf_ptr, buf2_ptr);

	test_multisector_lead(base_pos, buf_ptr, buf2_ptr, buf2_size);
	test_multisector_trail(base_pos, buf_ptr, buf2_ptr, buf2_size);
	test_multisector_lead_trail(base_pos, buf_ptr, buf2_ptr, buf2_size);

	cleanup_buffers(buf_ptr, buf2_ptr, buf_size);
}

static void setup_baseline(u64_t base_pos, u8_t *buf_ptr, u32_t *sum, u32_t *sum2)
{
	result_t res;

	if (!may_write)
		return;

	*sum = fill_rand(buf_ptr, max_size);
	simple_xfer(driver_minor, base_pos, buf_ptr, max_size, TRUE, max_size, &res);
	got_result(&res, "large baseline write");

	*sum2 = fill_rand(buf_ptr + max_size, sector_size);
	simple_xfer(driver_minor, base_pos + max_size, buf_ptr + max_size, 
		sector_size, TRUE, sector_size, &res);
	got_result(&res, "small baseline write");
}

static void verify_baseline(u64_t base_pos, u8_t *buf_ptr, u32_t sum, u32_t sum2)
{
	result_t res;

	fill_rand(buf_ptr, max_size + sector_size);

	simple_xfer(driver_minor, base_pos, buf_ptr, max_size, FALSE, max_size, &res);
	if (may_write)
		test_sum(buf_ptr, max_size, sum, TRUE, &res);
	got_result(&res, "large baseline read");

	simple_xfer(driver_minor, base_pos + max_size, buf_ptr + max_size,
		sector_size, FALSE, sector_size, &res);
	if (may_write)
		test_sum(buf_ptr + max_size, sector_size, sum2, TRUE, &res);
	got_result(&res, "small baseline read");
}

static void test_minimal_vector(u64_t base_pos, u8_t *buf_ptr, u8_t *buf2_ptr)
{
	iovec_t iov[NR_IOREQS];
	u32_t rsum[NR_IOREQS];
	result_t res;
	int i;

	fill_rand(buf2_ptr, max_size + sector_size);

	for (i = 0; i < NR_IOREQS; i++) {
		iov[i].iov_addr = (vir_bytes) buf2_ptr + i * sector_size;
		iov[i].iov_size = min_read;
		rsum[i] = get_sum(buf2_ptr + i * sector_size + min_read,
			sector_size - min_read);
	}

	vir_xfer(driver_minor, base_pos + min_read, iov, NR_IOREQS, FALSE,
		min_read * NR_IOREQS, &res);

	for (i = 0; i < NR_IOREQS; i++) {
		test_sum(buf2_ptr + i * sector_size + min_read,
			sector_size - min_read, rsum[i], TRUE, &res);
		memmove(buf2_ptr + i * min_read, buf2_ptr + i * sector_size,
			min_read);
	}

	test_sum(buf2_ptr, min_read * NR_IOREQS, 
		get_sum(buf_ptr + min_read, min_read * NR_IOREQS), TRUE, &res);
	got_result(&res, "small fully unaligned filled vector");
}

static void test_single_large_element(u64_t base_pos, u8_t *buf_ptr, u8_t *buf2_ptr)
{
	result_t res;

	fill_rand(buf2_ptr, max_size + sector_size);
	simple_xfer(driver_minor, base_pos + min_read, buf2_ptr, max_size,
		FALSE, max_size, &res);
	test_sum(buf2_ptr, max_size, get_sum(buf_ptr + min_read, max_size),
		TRUE, &res);
	got_result(&res, "large fully unaligned single element");
}

static void test_maximal_vector(u64_t base_pos, u8_t *buf_ptr, u8_t *buf2_ptr)
{
	iovec_t iov[NR_IOREQS];
	result_t res;
	size_t max_block;
	int i;

	max_block = max_size / NR_IOREQS;
	max_block -= max_block % sector_size;

	fill_rand(buf2_ptr, max_size + sector_size);

	for (i = 0; i < NR_IOREQS; i++) {
		iov[i].iov_addr = (vir_bytes) buf2_ptr + i * max_block;
		iov[i].iov_size = max_block;
	}

	vir_xfer(driver_minor, base_pos + min_read, iov, NR_IOREQS, FALSE,
		max_block * NR_IOREQS, &res);
	test_sum(buf2_ptr, max_block * NR_IOREQS, 
		get_sum(buf_ptr + min_read, max_block * NR_IOREQS), TRUE, &res);
	got_result(&res, "large fully unaligned filled vector");
}

static void unaligned_pos2(void)
{
	u8_t *buf_ptr, *buf2_ptr;
	size_t buf_size;
	u32_t sum = 0L, sum2 = 0L;
	u64_t base_pos;

	test_group("sector-unaligned positions, part two",
		min_read != sector_size);

	if (min_read == sector_size)
		return;

	buf_size = max_size + sector_size;
	base_pos = (u64_t)sector_size * 3;

	buf_ptr = alloc_dma_memory(buf_size);
	buf2_ptr = alloc_dma_memory(buf_size);

	setup_baseline(base_pos, buf_ptr, &sum, &sum2);
	verify_baseline(base_pos, buf_ptr, sum, sum2);
	test_minimal_vector(base_pos, buf_ptr, buf2_ptr);
	test_single_large_element(base_pos, buf_ptr, buf2_ptr);
	test_maximal_vector(base_pos, buf_ptr, buf2_ptr);

	free_dma_memory(buf2_ptr, buf_size);
	free_dma_memory(buf_ptr, buf_size);
}

static void write_and_read_full_area(u64_t base_pos, u8_t *buf_ptr, size_t buf_size, u32_t *sum)
{
	result_t res;
	
	*sum = fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE, buf_size, &res);
	got_result(&res, "write to full area");
}

static void read_full_area(u64_t base_pos, u8_t *buf_ptr, size_t buf_size, u32_t sum, int verify_sum)
{
	result_t res;
	
	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);
	
	if (verify_sum)
		test_sum(buf_ptr, buf_size, sum, TRUE, &res);
	
	got_result(&res, "read from full area");
}

static void calculate_sector_checksums(u8_t *buf_ptr, u32_t *ssum, int sector_count)
{
	int i;
	for (i = 0; i < sector_count; i++)
		ssum[i] = get_sum(buf_ptr + sector_size * i, sector_size);
}

static void verify_sector_checksums(u8_t *buf_ptr, u32_t *ssum, int start_idx, int count)
{
	int j;
	result_t res;
	
	for (j = 0; j < count; j++)
		test_sum(buf_ptr + sector_size * j, sector_size, ssum[start_idx + j], TRUE, &res);
}

static void read_subarea(u64_t base_pos, int sector_offset, u8_t *buf_ptr, u32_t *ssum)
{
	result_t res;
	#define SUBAREA_SECTORS 3
	size_t subarea_size = sector_size * SUBAREA_SECTORS;
	
	fill_rand(buf_ptr, subarea_size);
	simple_xfer(driver_minor, base_pos + sector_size * sector_offset, buf_ptr, 
		subarea_size, FALSE, subarea_size, &res);
	
	verify_sector_checksums(buf_ptr, ssum, sector_offset, SUBAREA_SECTORS);
	got_result(&res, "read from subarea");
}

static void write_subarea(u64_t base_pos, int sector_offset, u8_t *buf_ptr, u32_t *ssum)
{
	result_t res;
	int j;
	#define SUBAREA_SECTORS 3
	size_t subarea_size = sector_size * SUBAREA_SECTORS;
	
	fill_rand(buf_ptr, subarea_size);
	simple_xfer(driver_minor, base_pos + sector_size * sector_offset, buf_ptr,
		subarea_size, TRUE, subarea_size, &res);
	
	for (j = 0; j < SUBAREA_SECTORS; j++)
		ssum[sector_offset + j] = get_sum(buf_ptr + sector_size * j, sector_size);
	
	got_result(&res, "write to subarea");
}

static void process_subareas(u64_t base_pos, u8_t *buf_ptr, u32_t *ssum)
{
	#define SUBAREA_COUNT 6
	int i;
	
	for (i = 0; i < SUBAREA_COUNT; i++) {
		read_subarea(base_pos, i, buf_ptr, ssum);
		
		if (may_write)
			write_subarea(base_pos, i, buf_ptr, ssum);
	}
}

static void final_readback(u64_t base_pos, u8_t *buf_ptr, size_t buf_size, u32_t *ssum)
{
	result_t res;
	#define TOTAL_SECTORS 8
	int i;
	
	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);
	
	for (i = 0; i < TOTAL_SECTORS; i++)
		test_sum(buf_ptr + sector_size * i, sector_size, ssum[i], TRUE, &res);
	
	got_result(&res, "readback from full area");
}

static void sweep_area(u64_t base_pos)
{
	#define TOTAL_SECTORS 8
	u8_t *buf_ptr;
	size_t buf_size;
	u32_t sum = 0L, ssum[TOTAL_SECTORS];
	
	buf_size = sector_size * TOTAL_SECTORS;
	buf_ptr = alloc_dma_memory(buf_size);
	
	if (may_write)
		write_and_read_full_area(base_pos, buf_ptr, buf_size, &sum);
	
	read_full_area(base_pos, buf_ptr, buf_size, sum, may_write);
	calculate_sector_checksums(buf_ptr, ssum, TOTAL_SECTORS);
	
	process_subareas(base_pos, buf_ptr, ssum);
	
	if (may_write)
		final_readback(base_pos, buf_ptr, buf_size, ssum);
	
	free_dma_memory(buf_ptr, buf_size);
}

static void prepare_integrity_buffer(u8_t **buf_ptr, size_t *buf_size)
{
	*buf_size = sector_size * 3;
	*buf_ptr = alloc_dma_memory(*buf_size);
}

static u32_t write_integrity_zone(u8_t *buf_ptr, size_t buf_size)
{
	u32_t sum = fill_rand(buf_ptr, buf_size);
	result_t res;
	
	simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
	got_result(&res, "write integrity zone");
	
	return sum;
}

static u32_t read_integrity_zone(u8_t *buf_ptr, size_t buf_size)
{
	result_t res;
	
	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, FALSE, buf_size, &res);
	got_result(&res, "read integrity zone");
	
	return get_sum(buf_ptr, buf_size);
}

static void verify_integrity_zone(u8_t *buf_ptr, size_t buf_size, u32_t expected_sum)
{
	result_t res;
	
	fill_rand(buf_ptr, buf_size);
	simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, FALSE, buf_size, &res);
	test_sum(buf_ptr, buf_size, expected_sum, TRUE, &res);
	got_result(&res, "check integrity zone");
}

static u32_t setup_integrity_check(u8_t *buf_ptr, size_t buf_size)
{
	result_t res;
	u32_t sum;
	
	if (may_write) {
		sum = write_integrity_zone(buf_ptr, buf_size);
		fill_rand(buf_ptr, buf_size);
		simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, FALSE, buf_size, &res);
		test_sum(buf_ptr, buf_size, sum, TRUE, &res);
		got_result(&res, "read integrity zone");
	} else {
		sum = read_integrity_zone(buf_ptr, buf_size);
	}
	
	return sum;
}

static void sweep_and_check(u64_t pos, int check_integ)
{
	u8_t *buf_ptr;
	size_t buf_size;
	u32_t sum = 0L;

	if (check_integ) {
		prepare_integrity_buffer(&buf_ptr, &buf_size);
		sum = setup_integrity_check(buf_ptr, buf_size);
	}

	sweep_area(pos);

	if (check_integ) {
		verify_integrity_zone(buf_ptr, buf_size, sum);
		free_dma_memory(buf_ptr, buf_size);
	}
}

static void basic_sweep(void)
{
	test_group("basic area sweep", TRUE);
	sweep_area((u64_t)sector_size);
}

static int is_partition_valid_for_high_disk_test(u64_t base_pos)
{
	return (part.base + part.size >= base_pos) && (base_pos >= part.base);
}

static u64_t calculate_base_position(void)
{
	u64_t base_pos = 0x100000000ULL | (sector_size * 4);
	base_pos -= base_pos % sector_size;
	return base_pos;
}

static void high_disk_pos(void)
{
	const int SECTOR_OFFSET = 8;
	u64_t base_pos = calculate_base_position();
	
	if (part.base + part.size < base_pos) {
		test_group("high disk positions", FALSE);
		return;
	}
	
	base_pos -= sector_size * SECTOR_OFFSET;
	
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
	#define POSITION_OFFSET_32BIT 0x100000000ULL
	#define SECTOR_OFFSET 4
	#define SECTOR_SWEEP_OFFSET 8
	
	u64_t base_pos;

	if (part.base == 0ULL) {
		return;
	}

	base_pos = POSITION_OFFSET_32BIT | (sector_size * SECTOR_OFFSET);
	base_pos -= base_pos % sector_size;

	if (part.size < base_pos) {
		test_group("high partition positions", FALSE);
		return;
	}

	test_group("high partition positions", TRUE);

	base_pos -= sector_size * SECTOR_SWEEP_OFFSET;

	sweep_and_check(base_pos, TRUE);
}

static int check_partition_exceeds_24bit(u64_t base_pos)
{
	return part.base + part.size >= base_pos;
}

static int check_partition_start_within_24bit(u64_t base_pos)
{
	return base_pos >= part.base;
}

static u64_t calculate_24bit_base_position(void)
{
	return (1ULL << 24) * sector_size;
}

static u64_t adjust_base_position_for_test(u64_t base_pos)
{
	return base_pos - (sector_size * 8);
}

static void high_lba_pos1(void)
{
	u64_t base_pos;

	base_pos = calculate_24bit_base_position();

	if (!check_partition_exceeds_24bit(base_pos)) {
		test_group("high LBA positions, part one", FALSE);
		return;
	}

	base_pos = adjust_base_position_for_test(base_pos);

	if (!check_partition_start_within_24bit(base_pos)) {
		test_group("high LBA positions, part one", FALSE);
		return;
	}

	test_group("high LBA positions, part one", TRUE);

	base_pos -= part.base;

	sweep_and_check(base_pos, part.base == 0ULL);
}

static void high_lba_pos2(void)
{
	#define LBA_28_BIT_LIMIT (1ULL << 28)
	#define SECTOR_OFFSET 8
	
	u64_t base_pos;
	int can_test;

	base_pos = LBA_28_BIT_LIMIT * sector_size;

	can_test = validate_partition_bounds(base_pos);
	
	if (!can_test) {
		test_group("high LBA positions, part two", FALSE);
		return;
	}

	test_group("high LBA positions, part two", TRUE);

	base_pos = calculate_sweep_position(base_pos);
	sweep_and_check(base_pos, part.base == 0ULL);
}

static int validate_partition_bounds(u64_t base_pos)
{
	if (part.base + part.size < base_pos) {
		return FALSE;
	}

	base_pos -= sector_size * SECTOR_OFFSET;

	if (base_pos < part.base) {
		return FALSE;
	}

	return TRUE;
}

static u64_t calculate_sweep_position(u64_t base_pos)
{
	base_pos -= sector_size * SECTOR_OFFSET;
	base_pos -= part.base;
	return base_pos;
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
	run_ioctl_tests();
	run_read_tests();
	run_write_tests();
	run_boundary_tests();
	close_primary();
}

static void run_ioctl_tests(void)
{
	misc_ioctl();
}

static void run_read_tests(void)
{
	bad_read1();
	bad_read2();
}

static void run_write_tests(void)
{
	bad_write();
}

static void run_boundary_tests(void)
{
	vector_and_large();
	part_limits();
	unaligned_size();
	unaligned_pos1();
	unaligned_pos2();
	high_pos();
}

static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
	parse_arguments();
	validate_configuration();
	initialize_random_seed();
	print_test_header();
	do_tests();
	print_test_summary();
	return (failed_tests) ? EINVAL : OK;
}

static void parse_arguments(void)
{
	if (env_argc > 1)
		optset_parse(optset_table, env_argv[1]);
}

static void validate_configuration(void)
{
	if (driver_label[0] == '\0')
		panic("no driver label given");

	if (ds_retrieve_label_endpt(driver_label, &driver_endpt))
		panic("unable to resolve driver label");

	if (driver_minor > 255)
		panic("invalid or no driver minor given");
}

static void initialize_random_seed(void)
{
	srand48(getticks());
}

static void print_test_header(void)
{
	output("BLOCKTEST: driver label '%s' (endpt %d), minor %d\n",
		driver_label, driver_endpt, driver_minor);
}

static void print_test_summary(void)
{
	output("BLOCKTEST: summary: %d out of %d tests failed "
		"across %d group%s; %d driver deaths\n",
		failed_tests, total_tests, failed_groups,
		failed_groups == 1 ? "" : "s", driver_deaths);
}

static void sef_local_startup(void)
{
	sef_setcb_init_fresh(sef_cb_init_fresh);
	sef_startup();
}

int main(int argc, char **argv)
{
	env_setargs(argc, argv);
	sef_local_startup();
	return 0;
}
