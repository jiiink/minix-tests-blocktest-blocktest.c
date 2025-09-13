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

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

static bool silent = false;

static void output(const char *fmt, ...) {
    if (!fmt || silent) {
        return;
    }
    
    va_list argp;
    va_start(argp, fmt);
    vprintf(fmt, argp);
    va_end(argp);
}

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdbool.h>

static void *alloc_dma_memory(size_t size, bool contig) {
    void *ptr = contig ? alloc_contig(size, 0, NULL) : mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (ptr == MAP_FAILED) {
        fprintf(stderr, "Error: unable to allocate %zu bytes of memory\n", size);
        exit(EXIT_FAILURE);
    }

    return ptr;
}

#include <stdbool.h>
#include <sys/mman.h>

static void free_dma_memory(void *ptr, size_t size, bool contig) {
    if (ptr == NULL) {
        return;
    }

    if (contig) {
        free_contig(ptr, size);
    } else {
        if (munmap(ptr, size) == -1) {
            // Handle the error according to application requirements
        }
    }
}

static int set_result(result_t *res, int type, ssize_t value)
{
    if (!res) {
        return -1; // Error handling for null pointer
    }

    res->type = type;
    res->value = value;

    return type;
}

static int accept_result(result_t *res, int type, ssize_t value) {
    if (!res) return FALSE;
    
    int isReset = (res->type == type && res->value == value);
    if (isReset) {
        set_result(res, RESULT_OK, 0);
    }

    return isReset;
}

static void got_result(result_t *res, const char *desc) {
    static int i = 0;
    total_tests++;
    
    if (res->type != RESULT_OK) {
        failed_tests++;
        if (!group_failure) {
            failed_groups++;
            group_failure = TRUE;
        }
    }

    const char *status = (res->type == RESULT_OK) ? "PASS" : "FAIL";
    output("#%02d: %-38s\t[%s]\n", ++i, desc, status);

    if (res->type != RESULT_OK) {
        const char *error_message = NULL;
        int int_value = 0;

        switch (res->type) {
            case RESULT_DEATH:
                error_message = "- driver died\n";
                break;
            case RESULT_COMMFAIL:
                error_message = "- communication failed; ipc_sendrec returned %d\n";
                int_value = res->value;
                break;
            case RESULT_BADTYPE:
            case RESULT_BADID:
            case RESULT_BADSTATUS:
            case RESULT_BADVALUE:
                error_message = "- bad or unexpected value %d\n";
                int_value = res->value;
                break;
            case RESULT_TRUNC:
                error_message = "- result size not as expected (%u bytes left)\n";
                int_value = res->value;
                break;
            case RESULT_CORRUPT:
                error_message = "- buffer has been modified erroneously\n";
                break;
            case RESULT_MISSING:
                error_message = "- buffer has been left untouched erroneously\n";
                break;
            case RESULT_OVERFLOW:
                error_message = "- area around target buffer modified\n";
                break;
            default:
                error_message = "- unknown error\n";
                break;
        }

        if (error_message) {
            if (int_value != 0)
                output(error_message, int_value);
            else
                output("%s", error_message);
        }
    }
}

#include <stdbool.h>
#include <stdio.h>

static bool group_failure = false;

static void test_group(const char *name, bool exec) {
    if (!name) {
        fprintf(stderr, "Invalid group name.\n");
        return;
    }

    printf("Test group: %s%s\n", name, exec ? "" : " (skipping)");
    group_failure = false;
}

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

static bool may_write = true; // Placeholder for the may_write variable
static int driver_endpt = 0; // Placeholder for the driver_endpt variable

static void reopen_device(dev_t minor) {
    message m;
    memset(&m, 0, sizeof(m));

    m.m_type = BDEV_OPEN;
    m.m_lbdev_lblockdriver_msg.minor = minor;
    m.m_lbdev_lblockdriver_msg.access = may_write ? (BDEV_R_BIT | BDEV_W_BIT) : BDEV_R_BIT;
    m.m_lbdev_lblockdriver_msg.id = 0;

    int result = ipc_sendrec(driver_endpt, &m);
    if (result != 0) {
        fprintf(stderr, "Error reopening device: %s\n", strerror(result));
    }
}

static int sendrec_driver(message *m_ptr, ssize_t exp, result_t *res) {
    message m_orig;
    endpoint_t last_endpt;
    int i, r;

    m_orig = *m_ptr;
    r = ipc_sendrec(driver_endpt, m_ptr);

    if (r == EDEADSRCDST) {
        output("WARNING: driver has died, attempting to proceed\n");
        driver_deaths++;

        last_endpt = driver_endpt;
        do {
            r = ds_retrieve_label_endpt(driver_label, &driver_endpt);
            if (r == OK && last_endpt != driver_endpt) break;
            micro_delay(100000);
        } while (1);

        for (i = 0; i < nr_opened; i++) {
            reopen_device(opened[i]);
        }

        return set_result(res, RESULT_DEATH, 0);
    }

    if (r != OK) {
        return set_result(res, RESULT_COMMFAIL, r);
    }

    if (m_ptr->m_type != BDEV_REPLY || 
        m_ptr->m_lblockdriver_lbdev_reply.id != m_orig.m_lbdev_lblockdriver_msg.id ||
        ((exp < 0 && m_ptr->m_lblockdriver_lbdev_reply.status >= 0) ||
        (exp >= 0 && m_ptr->m_lblockdriver_lbdev_reply.status < 0))) {
        return set_result(res, RESULT_BAD, 0);
    }

    return set_result(res, RESULT_OK, 0);
}

#include <assert.h>
#include <string.h>
#include <stdlib.h>

static void raw_xfer(dev_t minor, u64_t pos, iovec_s_t *iovec, int nr_req, int write, ssize_t exp, result_t *res) {
    cp_grant_id_t grant;
    message m;
    int r;

    assert(nr_req <= NR_IOREQS && (!write || may_write));

    grant = cpf_grant_direct(driver_endpt, (vir_bytes)iovec, sizeof(*iovec) * nr_req, CPF_READ);
    if (grant == GRANT_INVALID) {
        set_result(res, RESULT_ERROR, GRANT_INVALID);
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
        set_result(res, RESULT_ERROR, GRANT_REVOKE_FAILED);
        return;
    }

    if (r != RESULT_OK || m.m_lblockdriver_lbdev_reply.status != exp) {
        set_result(res, exp < 0 ? RESULT_BADSTATUS : RESULT_TRUNC, exp - m.m_lblockdriver_lbdev_reply.status);
    }
}

#include <assert.h>

static void vir_xfer(dev_t minor, u64_t pos, iovec_t *iovec, int nr_req, int write, ssize_t exp, result_t *res) {
    iovec_s_t iov_s[NR_IOREQS];

    assert(nr_req <= NR_IOREQS);

    for (int i = 0; i < nr_req; i++) {
        iov_s[i].iov_size = iovec[i].iov_size;
        iov_s[i].iov_grant = cpf_grant_direct(driver_endpt, (vir_bytes) iovec[i].iov_addr, iovec[i].iov_size, write ? CPF_READ : CPF_WRITE);
        if (iov_s[i].iov_grant == GRANT_INVALID) {
            res->status = -1;
            return;
        }
    }

    raw_xfer(minor, pos, iov_s, nr_req, write, exp, res);

    for (int i = 0; i < nr_req; i++) {
        iovec[i].iov_size = iov_s[i].iov_size;
        if (cpf_revoke(iov_s[i].iov_grant) == -1) {
            res->status = -1;
            return;
        }
    }

    res->status = 0;
}

static void simple_xfer(dev_t minor, u64_t pos, u8_t *buf, size_t size, int write, ssize_t exp, result_t *res) {
    if (res == NULL || buf == NULL) {
        return; // Early exit if pointers are NULL to ensure reliability
    }

    iovec_t iov = {
        .iov_addr = (vir_bytes)buf,
        .iov_size = size
    };

    vir_xfer(minor, pos, &iov, 1, write, exp, res);
}

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define GRANT_INVALID -1

typedef uint8_t u8_t;
typedef int cp_grant_id_t;
typedef uintptr_t vir_bytes;

extern int driver_endpt;
extern u8_t* alloc_dma_memory(size_t size);
extern cp_grant_id_t cpf_grant_direct(int endpoint, vir_bytes address, size_t size, int perms);
extern void panic(const char* message);

static void alloc_buf_and_grant(u8_t **ptr, cp_grant_id_t *grant, size_t size, int perms) {
    *ptr = alloc_dma_memory(size);
    if (*ptr == NULL) {
        panic("unable to allocate DMA memory");
    }

    *grant = cpf_grant_direct(driver_endpt, (vir_bytes)*ptr, size, perms);
    if (*grant == GRANT_INVALID) {
        panic("unable to allocate grant");
    }
}

#include <stddef.h>
#include <stdint.h>

static void free_buf_and_grant(uint8_t *ptr, cp_grant_id_t grant, size_t size) {
    if (ptr == NULL || size == 0) {
        return;
    }

    int revoke_status = cpf_revoke(grant);
    if (revoke_status != 0) {
        // Handle error if necessary (e.g., logging)
    }

    free_dma_memory(ptr, size);
}

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "your_header_file.h" // Add any necessary includes or declarations

#define BUF_SIZE 4096

static void handle_test_result(result_t *res, const char *description, ssize_t expected_size, ssize_t actual_size) {
    if (res->type == RESULT_OK && actual_size != expected_size) {
        res->type = RESULT_TRUNC;
        res->value = actual_size;
    }
    got_result(res, description);
}

static void initialize_message_and_iovec(message *mt, iovec_s_t *iovt, cp_grant_id_t grant, vir_bytes buf_size) {
    memset(mt, 0, sizeof(*mt));
    mt->m_type = BDEV_GATHER;
    mt->m_lbdev_lblockdriver_msg.minor = driver_minor;
    mt->m_lbdev_lblockdriver_msg.pos = 0LL;
    mt->m_lbdev_lblockdriver_msg.count = 1;
    mt->m_lbdev_lblockdriver_msg.grant = grant;
    mt->m_lbdev_lblockdriver_msg.id = lrand48();

    memset(iovt, 0, sizeof(*iovt));
    iovt->iov_grant = grant;
    iovt->iov_size = buf_size;
}

static void bad_read1(void) {
    message mt, m;
    iovec_s_t iov;
    cp_grant_id_t grant, grant2, grant3;
    u8_t *buf_ptr;
    vir_bytes buf_size = BUF_SIZE;
    result_t res;

    test_group("bad read requests, part one", true);

    alloc_buf_and_grant(&buf_ptr, &grant2, buf_size, CPF_WRITE);

    grant = cpf_grant_direct(driver_endpt, (vir_bytes)&iov, sizeof(iov), CPF_READ);
    if (grant == GRANT_INVALID) panic("unable to allocate grant");

    initialize_message_and_iovec(&mt, &iov, grant, buf_size);

    // Test normal request.
    m = mt;
    sendrec_driver(&m, OK, &res);
    handle_test_result(&res, "normal request", iov.iov_size, m.m_lblockdriver_lbdev_reply.status);

    // Test zero iovec elements.
    m = mt;
    m.m_lbdev_lblockdriver_msg.count = 0;
    sendrec_driver(&m, EINVAL, &res);
    got_result(&res, "zero iovec elements");

    // Test bad iovec grant.
    m = mt;
    m.m_lbdev_lblockdriver_msg.grant = GRANT_INVALID;
    sendrec_driver(&m, EINVAL, &res);
    got_result(&res, "bad iovec grant");

    // Test revoked iovec grant.
    grant3 = cpf_grant_direct(driver_endpt, (vir_bytes)&iov, sizeof(iov), CPF_READ);
    if (grant3 == GRANT_INVALID) panic("unable to allocate grant");

    cpf_revoke(grant3);
    m = mt;
    m.m_lbdev_lblockdriver_msg.grant = grant3;
    sendrec_driver(&m, EINVAL, &res);
    accept_result(&res, RESULT_BADSTATUS, EPERM);
    got_result(&res, "revoked iovec grant");

    // Test normal request (final check).
    m = mt;
    sendrec_driver(&m, OK, &res);
    handle_test_result(&res, "normal request", iov.iov_size, m.m_lblockdriver_lbdev_reply.status);

    // Clean up.
    free_buf_and_grant(buf_ptr, grant2, buf_size);
    cpf_revoke(grant);
}

#include <stddef.h>
#include <stdint.h>

static uint32_t get_sum(const uint8_t *ptr, size_t size) {
    uint32_t sum = 0;
    if (ptr == NULL) {
        return sum;
    }
    for (size_t i = 0; i < size; i++) {
        sum = sum ^ (sum << 5) ^ ptr[i];
    }
    return sum;
}

#include <stdlib.h>
#include <stdint.h>

static uint32_t fill_rand(uint8_t *ptr, size_t size) {
    if (ptr == NULL || size == 0) {
        return 0; // Return value indicating failure or empty checksum
    }

    for (size_t i = 0; i < size; i++) {
        ptr[i] = (uint8_t)(rand() % 256);
    }

    return get_sum(ptr, size);
}

static void test_sum(u8_t *ptr, size_t size, u32_t sum, int should_match, result_t *res) {
    if (res->type != RESULT_OK) {
        return;
    }

    u32_t calculated_sum = get_sum(ptr, size);

    if ((sum == calculated_sum) != should_match) {
        res->type = should_match ? RESULT_CORRUPT : RESULT_MISSING;
        res->value = 0;
    }
}

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "raw_transfer.h"

static void bad_read2(void) {
    u8_t *buf_ptr = NULL, *buf2_ptr = NULL, *buf3_ptr = NULL;
    u8_t c1, c2;
    size_t buf_size = BUF_SIZE;
    cp_grant_id_t buf_grant = GRANT_INVALID, buf2_grant = GRANT_INVALID, buf3_grant = GRANT_INVALID, grant = GRANT_INVALID;
    u32_t buf_sum, buf2_sum, buf3_sum;
    iovec_s_t iov[3], iovt[3];
    result_t res;

    test_group("bad read requests, part two", TRUE);

    if (!alloc_buf_and_grant(&buf_ptr, &buf_grant, buf_size, CPF_WRITE) ||
        !alloc_buf_and_grant(&buf2_ptr, &buf2_grant, buf_size, CPF_WRITE) ||
        !alloc_buf_and_grant(&buf3_ptr, &buf3_grant, buf_size, CPF_WRITE)) {
        goto cleanup;
    }

    iovt[0] = (iovec_s_t){buf_grant, buf_size};
    iovt[1] = (iovec_s_t){buf2_grant, buf_size};
    iovt[2] = (iovec_s_t){buf3_grant, buf_size};

    memcpy(iov, iovt, sizeof(iovt));
    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf_size);
    buf3_sum = fill_rand(buf3_ptr, buf_size);
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, buf_size * 3, &res);
    test_sum(buf_ptr, buf_size, buf_sum, FALSE, &res);
    test_sum(buf2_ptr, buf_size, buf2_sum, FALSE, &res);
    test_sum(buf3_ptr, buf_size, buf3_sum, FALSE, &res);
    got_result(&res, "normal vector request");

    memcpy(iov, iovt, sizeof(iovt));
    iov[1].iov_size = 0;
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
    test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, &res);
    got_result(&res, "zero size in iovec element");

    memcpy(iov, iovt, sizeof(iovt));
    iov[1].iov_size = (vir_bytes)LONG_MAX + 1;
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
    test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, &res);
    got_result(&res, "negative size in iovec element");

    memcpy(iov, iovt, sizeof(iovt));
    iov[0].iov_size = LONG_MAX / 2;
    iov[1].iov_size = LONG_MAX / 2 - 1;
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
    test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, &res);
    got_result(&res, "negative total size");

    memcpy(iov, iovt, sizeof(iovt));
    iov[0].iov_size = LONG_MAX - 1;
    iov[1].iov_size = LONG_MAX - 1;
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
    test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, &res);
    got_result(&res, "wrapping total size");

    memcpy(iov, iovt, sizeof(iovt));
    iov[1].iov_size--;
    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf_size);
    buf3_sum = fill_rand(buf3_ptr, buf_size);
    c1 = buf2_ptr[buf_size - 1];
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, BUF_SIZE * 3 - 1, &res);
    if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
        test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, &res);
        test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, &res);
    } else {
        test_sum(buf_ptr, buf_size, buf_sum, FALSE, &res);
        test_sum(buf2_ptr, buf_size, buf2_sum, FALSE, &res);
        test_sum(buf3_ptr, buf_size, buf3_sum, FALSE, &res);
        if (c1 != buf2_ptr[buf_size - 1]) set_result(&res, RESULT_CORRUPT, 0);
    }
    got_result(&res, "word-unaligned size in iovec element");

    memcpy(iov, iovt, sizeof(iovt));
    iov[1].iov_grant = GRANT_INVALID;
    fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf_size);
    buf3_sum = fill_rand(buf3_ptr, buf_size);
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, &res);
    got_result(&res, "invalid grant in iovec element");

    memcpy(iov, iovt, sizeof(iovt));
    grant = cpf_grant_direct(driver_endpt, (vir_bytes)buf2_ptr, buf_size, CPF_WRITE);
    if (grant == GRANT_INVALID) goto cleanup;
    cpf_revoke(grant);
    iov[1].iov_grant = grant;
    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf_size);
    buf3_sum = fill_rand(buf3_ptr, buf_size);
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    accept_result(&res, RESULT_BADSTATUS, EPERM);
    test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, &res);
    got_result(&res, "revoked grant in iovec element");

    memcpy(iov, iovt, sizeof(iovt));
    grant = cpf_grant_direct(driver_endpt, (vir_bytes)buf2_ptr, buf_size, CPF_READ);
    if (grant == GRANT_INVALID) goto cleanup;
    iov[1].iov_grant = grant;
    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf_size);
    buf3_sum = fill_rand(buf3_ptr, buf_size);
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, EINVAL, &res);
    accept_result(&res, RESULT_BADSTATUS, EPERM);
    test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, &res);
    test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, &res);
    got_result(&res, "read-only grant in iovec element");
    cpf_revoke(grant);

    memcpy(iov, iovt, sizeof(iovt));
    grant = cpf_grant_direct(driver_endpt, (vir_bytes)(buf2_ptr + 1), buf_size - 2, CPF_WRITE);
    if (grant == GRANT_INVALID) goto cleanup;
    iov[1].iov_grant = grant;
    iov[1].iov_size = buf_size - 2;
    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf_size);
    buf3_sum = fill_rand(buf3_ptr, buf_size);
    c1 = buf2_ptr[0];
    c2 = buf2_ptr[buf_size - 1];
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, BUF_SIZE * 3 - 2, &res);
    if (accept_result(&res, RESULT_BADSTATUS, EINVAL)) {
        test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, &res);
        test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, &res);
    } else {
        test_sum(buf_ptr, buf_size, buf_sum, FALSE, &res);
        test_sum(buf2_ptr, buf_size, buf2_sum, FALSE, &res);
        test_sum(buf3_ptr, buf_size, buf3_sum, FALSE, &res);
        if (c1 != buf2_ptr[0] || c2 != buf2_ptr[buf_size - 1]) {
            set_result(&res, RESULT_CORRUPT, 0);
        }
    }
    got_result(&res, "word-unaligned buffer in iovec element");
    cpf_revoke(grant);

    if (min_read > 1) {
        memcpy(iov, iovt, sizeof(iovt));
        buf_sum = fill_rand(buf_ptr, buf_size);
        buf2_sum = fill_rand(buf2_ptr, buf_size);
        buf3_sum = fill_rand(buf3_ptr, buf_size);
        raw_xfer(driver_minor, 1ULL, iov, 3, FALSE, EINVAL, &res);
        test_sum(buf_ptr, buf_size, buf_sum, TRUE, &res);
        test_sum(buf2_ptr, buf_size, buf2_sum, TRUE, &res);
        test_sum(buf3_ptr, buf_size, buf3_sum, TRUE, &res);
        got_result(&res, "word-unaligned position");
    }

    memcpy(iov, iovt, sizeof(iovt));
    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf_size);
    buf3_sum = fill_rand(buf3_ptr, buf_size);
    raw_xfer(driver_minor, 0ULL, iov, 3, FALSE, buf_size * 3, &res);
    test_sum(buf_ptr, buf_size, buf_sum, FALSE, &res);
    test_sum(buf2_ptr, buf_size, buf2_sum, FALSE, &res);
    test_sum(buf3_ptr, buf_size, buf3_sum, FALSE, &res);
    got_result(&res, "normal vector request");

cleanup:
    if (grant != GRANT_INVALID) cpf_revoke(grant);
    if (buf3_ptr) free_buf_and_grant(buf3_ptr, buf3_grant, buf_size);
    if (buf2_ptr) free_buf_and_grant(buf2_ptr, buf2_grant, buf_size);
    if (buf_ptr) free_buf_and_grant(buf_ptr, buf_grant, buf_size);
}

#include <errno.h>
#include <stdlib.h>
#include <string.h>

// Define structures and constants for clarity
typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;
typedef int cp_grant_id_t;
typedef struct { cp_grant_id_t iov_grant; size_t iov_size; } iovec_s_t;
typedef enum { TRUE = 1, FALSE = 0 } boolean;
#define BUF_SIZE 1024
#define CPF_READ 0
#define CPF_WRITE 1
#define GRANT_INVALID -1

// Function prototypes for external functions
void test_group(const char *desc, int condition);
cp_grant_id_t cpf_grant_direct(int endpoint, u64_t address, size_t size, int perm);
void cpf_revoke(cp_grant_id_t grant);
u32_t fill_rand(u8_t *ptr, size_t size);
void raw_xfer(int minor, u64_t pos, iovec_s_t *iov, int count, boolean is_write, int exp_res, void *res);
void test_sum(u8_t *ptr, size_t size, u32_t sum, boolean reset, void *res);
void got_result(void *res, const char *desc);
void accept_result(void *res, int exp_type, int exp_err);
void alloc_buf_and_grant(u8_t **ptr, cp_grant_id_t *grant, size_t size, int perm);
void free_buf_and_grant(u8_t *ptr, cp_grant_id_t grant, size_t size);
void panic(const char *msg);

static void bad_write(void) {
    u8_t *buf_ptr = NULL, *buf2_ptr = NULL, *buf3_ptr = NULL;
    size_t buf_size = BUF_SIZE, buf2_size = BUF_SIZE, buf3_size = BUF_SIZE, sector_unalign;
    cp_grant_id_t buf_grant, buf2_grant, buf3_grant, grant;
    u32_t buf_sum, buf2_sum, buf3_sum;
    iovec_s_t iov[3], iovt[3];
    int may_write = FALSE; // Placeholder value
    int driver_minor = 0; // Placeholder
    int driver_endpt = 0; // Placeholder
    int min_write = 0, sector_size = 1; // Placeholder values
    void *res; // Placeholder

    test_group("bad write requests", may_write);
    if (!may_write) return;

    alloc_buf_and_grant(&buf_ptr, &buf_grant, buf_size, CPF_READ);
    alloc_buf_and_grant(&buf2_ptr, &buf2_grant, buf2_size, CPF_READ);
    alloc_buf_and_grant(&buf3_ptr, &buf3_grant, buf3_size, CPF_READ);

    iovt[0].iov_grant = buf_grant;
    iovt[0].iov_size = buf_size;
    iovt[1].iov_grant = buf2_grant;
    iovt[1].iov_size = buf2_size;
    iovt[2].iov_grant = buf3_grant;
    iovt[2].iov_size = buf3_size;

    if (min_write == 0) min_write = sector_size;
    if (min_write > 1) {
        sector_unalign = (min_write > 2) ? 2 : 1;

        memcpy(iov, iovt, sizeof(iovt));
        buf_sum = fill_rand(buf_ptr, buf_size);
        buf2_sum = fill_rand(buf2_ptr, buf2_size);
        buf3_sum = fill_rand(buf3_ptr, buf3_size);
        raw_xfer(driver_minor, (u64_t)sector_unalign, iov, 3, TRUE, EINVAL, res);
        test_sum(buf_ptr, buf_size, buf_sum, TRUE, res);
        test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, res);
        test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, res);
        got_result(res, "sector-unaligned write position");

        memcpy(iov, iovt, sizeof(iovt));
        iov[1].iov_size -= sector_unalign;
        buf_sum = fill_rand(buf_ptr, buf_size);
        buf2_sum = fill_rand(buf2_ptr, buf2_size);
        buf3_sum = fill_rand(buf3_ptr, buf3_size);
        raw_xfer(driver_minor, 0ULL, iov, 3, TRUE, EINVAL, res);
        test_sum(buf_ptr, buf_size, buf_sum, TRUE, res);
        test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, res);
        test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, res);
        got_result(res, "sector-unaligned write size");
    }

    memcpy(iov, iovt, sizeof(iovt));
    grant = cpf_grant_direct(driver_endpt, (u64_t)buf2_ptr, buf2_size, CPF_WRITE);
    if (grant == GRANT_INVALID) panic("unable to allocate grant");

    iov[1].iov_grant = grant;
    buf_sum = fill_rand(buf_ptr, buf_size);
    buf2_sum = fill_rand(buf2_ptr, buf2_size);
    buf3_sum = fill_rand(buf3_ptr, buf3_size);
    raw_xfer(driver_minor, 0ULL, iov, 3, TRUE, EINVAL, res);
    accept_result(res, EINVAL, EINVAL);
    test_sum(buf_ptr, buf_size, buf_sum, TRUE, res);
    test_sum(buf2_ptr, buf2_size, buf2_sum, TRUE, res);
    test_sum(buf3_ptr, buf3_size, buf3_sum, TRUE, res);
    got_result(res, "write-only grant in iovec element");

    cpf_revoke(grant);

    free_buf_and_grant(buf3_ptr, buf3_grant, buf3_size);
    free_buf_and_grant(buf2_ptr, buf2_grant, buf2_size);
    free_buf_and_grant(buf_ptr, buf_grant, buf_size);
}

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define NR_IOREQS 8

typedef uint8_t u8_t;
typedef uint32_t u32_t;
typedef uint64_t u64_t;
typedef uint8_t result_t;
typedef uintptr_t vir_bytes;

#define TRUE 1
#define FALSE 0

typedef struct {
    vir_bytes iov_addr;
    size_t iov_size;
} iovec_t;

result_t alloc_dma_memory(size_t size);
void free_dma_memory(void* ptr, size_t size);
void fill_rand(u8_t* buf, size_t size);
void test_sum(const u8_t* buf, size_t size, u32_t check_sum, int flag, result_t* res);
u32_t get_sum(const u8_t* buf, size_t size);
void got_result(result_t* res, const char* operation);
void set_result(result_t* res, int type, int code);
void vir_xfer(int driver_minor, u64_t base_pos, iovec_t* iovec, int iovcnt, int write_flag, size_t size, result_t* res);

extern int may_write;
extern int driver_minor;
extern size_t sector_size;

static void vector_and_large_sub(size_t small_size) {
    size_t large_size, buf_size, buf2_size;
    u8_t* buf_ptr = NULL;
    u8_t* buf2_ptr = NULL;
    iovec_t iovec[NR_IOREQS];
    u64_t base_pos;
    result_t res;
    int i;

    base_pos = (u64_t)sector_size;
    large_size = small_size * NR_IOREQS;
    buf_size = large_size + sizeof(u32_t) * 2;
    buf2_size = large_size + sizeof(u32_t) * (NR_IOREQS + 1);

    buf_ptr = alloc_dma_memory(buf_size);
    buf2_ptr = alloc_dma_memory(buf2_size);

    if (buf_ptr == NULL || buf2_ptr == NULL) {
        free_dma_memory(buf_ptr, buf_size);
        free_dma_memory(buf2_ptr, buf2_size);
        return;
    }

    #define SPTR(n) (buf2_ptr + sizeof(u32_t) + (n) * (sizeof(u32_t) + small_size))
    #define LPTR(n) (buf_ptr + sizeof(u32_t) + small_size * (n))

    if (may_write) {
        fill_rand(buf_ptr, buf_size);

        iovec[0].iov_addr = (vir_bytes)(buf_ptr + sizeof(u32_t));
        iovec[0].iov_size = large_size;

        vir_xfer(driver_minor, base_pos, iovec, 1, TRUE, large_size, &res);
        got_result(&res, "large write");
    }

    for (i = 0; i < NR_IOREQS; i++) {
        *((u32_t *)SPTR(i) - 1) = 0xDEADBEEFL + i;
        iovec[i].iov_addr = (vir_bytes)SPTR(i);
        iovec[i].iov_size = small_size;
    }
    *((u32_t *)SPTR(NR_IOREQS) - 1) = 0xFEEDFACEL;

    vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, FALSE, large_size, &res);

    if (res.type == RESULT_OK) {
        for (i = 0; i < NR_IOREQS; i++) {
            if (*((u32_t *)SPTR(i) - 1) != 0xDEADBEEFL + i) {
                set_result(&res, RESULT_OVERFLOW, 0);
            }
        }
        if (*((u32_t *)SPTR(NR_IOREQS) - 1) != 0xFEEDFACEL) {
            set_result(&res, RESULT_OVERFLOW, 0);
        }
    }

    if (res.type == RESULT_OK && may_write) {
        for (i = 0; i < NR_IOREQS; i++) {
            test_sum(SPTR(i), small_size, get_sum(LPTR(i), small_size), TRUE, &res);
        }
    }

    got_result(&res, "vectored read");

    if (may_write) {
        fill_rand(buf2_ptr, buf2_size);

        for (i = 0; i < NR_IOREQS; i++) {
            iovec[i].iov_addr = (vir_bytes)SPTR(i);
            iovec[i].iov_size = small_size;
        }

        vir_xfer(driver_minor, base_pos, iovec, NR_IOREQS, TRUE, large_size, &res);
        got_result(&res, "vectored write");
    }

    *((u32_t *)buf_ptr) = 0xCAFEBABEL;
    *((u32_t *)(buf_ptr + sizeof(u32_t) + large_size)) = 0xDECAFBADL;

    iovec[0].iov_addr = (vir_bytes)(buf_ptr + sizeof(u32_t));
    iovec[0].iov_size = large_size;

    vir_xfer(driver_minor, base_pos, iovec, 1, FALSE, large_size, &res);

    if (res.type == RESULT_OK) {
        if (*((u32_t *)buf_ptr) != 0xCAFEBABEL) {
            set_result(&res, RESULT_OVERFLOW, 0);
        }
        if (*((u32_t *)(buf_ptr + sizeof(u32_t) + large_size)) != 0xDECAFBADL) {
            set_result(&res, RESULT_OVERFLOW, 0);
        }
    }

    if (res.type == RESULT_OK) {
        for (i = 0; i < NR_IOREQS; i++) {
            test_sum(SPTR(i), small_size, get_sum(LPTR(i), small_size), TRUE, &res);
        }
    }

    got_result(&res, "large read");

    free_dma_memory(buf2_ptr, buf2_size);
    free_dma_memory(buf_ptr, buf_size);

    #undef LPTR
    #undef SPTR
}

#include <stddef.h>

static size_t calculate_max_block(size_t max_size, size_t sector_size) {
    size_t max_block = max_size / NR_IOREQS;
    return max_block - (max_block % sector_size);
}

static void perform_vector_and_large_tests(size_t block_size) {
    test_group("vector and large, common block", TRUE);
    vector_and_large_sub(block_size);
}

static void vector_and_large(void) {
    size_t max_size_adjusted;
    size_t max_block;

    max_size_adjusted = (max_size > part.size - sector_size * 4) ? 
                        part.size - sector_size * 4 : max_size;
    
    max_block = calculate_max_block(max_size_adjusted, sector_size);

    perform_vector_and_large_tests(COMMON_BLOCK_SIZE);

    if (max_block != COMMON_BLOCK_SIZE) {
        test_group("vector and large, large block", TRUE);
        vector_and_large_sub(max_block);
    }
}

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define OK 0
#define NR_OPENED 10
#define BDEV_OPEN 1
#define BDEV_R_BIT 0x1
#define BDEV_W_BIT 0x2
typedef int dev_t;
typedef int result_t;

typedef struct {
    int m_type;
    struct {
        dev_t minor;
        int access;
        int id;
    } m_lbdev_lblockdriver_msg;
} message;

int may_write;
dev_t driver_minor;
dev_t opened[NR_OPENED];
int nr_opened;

void sendrec_driver(message *m, int expected_reply, result_t *res);
void got_result(result_t *res, const char *operation);

void open_device(dev_t minor) {
    message m;
    result_t res;
    memset(&m, 0, sizeof(m));

    m.m_type = BDEV_OPEN;
    m.m_lbdev_lblockdriver_msg.minor = minor;
    m.m_lbdev_lblockdriver_msg.access = may_write ? (BDEV_R_BIT | BDEV_W_BIT) : BDEV_R_BIT;
    m.m_lbdev_lblockdriver_msg.id = lrand48();

    sendrec_driver(&m, OK, &res);

    if (nr_opened < NR_OPENED) {
        opened[nr_opened++] = minor;
    }

    const char *operation = (minor == driver_minor) ? "opening the main partition" : "opening a subpartition";
    got_result(&res, operation);
}

#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void close_device(dev_t minor) {
    message m;
    result_t res;
    int i;
    int minor_index = -1;

    memset(&m, 0, sizeof(m));
    m.m_type = BDEV_CLOSE;
    m.m_lbdev_lblockdriver_msg.minor = minor;
    m.m_lbdev_lblockdriver_msg.id = lrand48();

    if (sendrec_driver(&m, OK, &res) != 0) {
        // Handle communication error appropriately
        return;
    }

    assert(nr_opened > 0);
    for (i = 0; i < nr_opened; i++) {
        if (opened[i] == minor) {
            minor_index = i;
            break;
        }
    }

    if (minor_index != -1) {
        opened[minor_index] = opened[--nr_opened];
    }

    got_result(&res, (minor == driver_minor) ? 
               "closing the main partition" : 
               "closing a subpartition");
}

#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int vir_ioctl(dev_t minor, unsigned long req, void *ptr, ssize_t exp, result_t *res) {
    cp_grant_id_t grant;
    message m;
    int r, perm = 0;

    assert(!_MINIX_IOCTL_BIG(req)); 

    if (_MINIX_IOCTL_IOR(req)) perm |= CPF_WRITE;
    if (_MINIX_IOCTL_IOW(req)) perm |= CPF_READ;

    grant = cpf_grant_direct(driver_endpt, (vir_bytes) ptr, _MINIX_IOCTL_SIZE(req), perm);
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
    u64_t threshold_size = (u64_t)max_size * 2;

    test_group("test miscellaneous ioctls", TRUE);

    vir_ioctl(driver_minor, DIOCGETP, &part, OK, &res);
    got_result(&res, "ioctl to get partition");

    if (res.type == RESULT_OK && part.size < threshold_size) {
        output("WARNING: small partition, some tests may fail\n");
    }

    openct = 0;
    vir_ioctl(driver_minor, DIOCOPENCT, &openct, OK, &res);

    if (res.type == RESULT_OK && openct != 1) {
        handle_badvalue(&res, openct);
    }
    got_result(&res, "ioctl to get open count");

    open_device(driver_minor);

    openct = 0;
    vir_ioctl(driver_minor, DIOCOPENCT, &openct, OK, &res);

    if (res.type == RESULT_OK && openct != 2) {
        handle_badvalue(&res, openct);
    }
    got_result(&res, "increased open count after opening");

    close_device(driver_minor);

    openct = 0;
    vir_ioctl(driver_minor, DIOCOPENCT, &openct, OK, &res);

    if (res.type == RESULT_OK && openct != 1) {
        handle_badvalue(&res, openct);
    }
    got_result(&res, "decreased open count after closing");
}

static void handle_badvalue(result_t *res, int value) {
    res->type = RESULT_BADVALUE;
    res->value = value;
}

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint8_t u8_t;
typedef uint32_t u32_t;
typedef uint64_t u64_t;
typedef struct result_t {
    // Implementation-specific details
} result_t;

static void test_group(const char* name, bool condition);
static u8_t* alloc_dma_memory(size_t size);
static void free_dma_memory(u8_t* ptr, size_t size);
static void fill_rand(u8_t* buffer, size_t size);
static u32_t get_sum(const u8_t* buffer, size_t size);
static void simple_xfer(dev_t minor, u64_t offset, u8_t* buffer, size_t nbytes, bool is_write, size_t max_transfer_size, result_t* result);
static void got_result(const result_t* result, const char* message);
static void test_sum(const u8_t* buffer, size_t size, u32_t expected_sum, bool condition, result_t* result);

static const size_t sector_size = 512; // Assuming a sector size, please adjust as needed

static void read_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size) {
    u8_t *buf_ptr;
    size_t buf_size;
    u32_t sum, sum2, sum3;
    result_t res;

    test_group("read around subpartition limits", true);

    buf_size = sector_size * 3;
    buf_ptr = alloc_dma_memory(buf_size);

    fill_rand(buf_ptr, buf_size);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr, sector_size, false, sector_size, &res);
    sum = get_sum(buf_ptr, sector_size);
    got_result(&res, "one sector read up to partition end");

    fill_rand(buf_ptr, buf_size);
    simple_xfer(sub0_minor, (u64_t)sub_size - buf_size, buf_ptr, buf_size, false, buf_size, &res);
    test_sum(buf_ptr + sector_size * 2, sector_size, sum, true, &res);
    sum2 = get_sum(buf_ptr + sector_size, sector_size * 2);
    got_result(&res, "multisector read up to partition end");

    fill_rand(buf_ptr, buf_size);
    sum3 = get_sum(buf_ptr + sector_size * 2, sector_size);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size * 2, buf_ptr, buf_size, false, sector_size * 2, &res);
    test_sum(buf_ptr, sector_size * 2, sum2, true, &res);
    test_sum(buf_ptr + sector_size * 2, sector_size, sum3, true, &res);
    got_result(&res, "read somewhat across partition end");

    fill_rand(buf_ptr, buf_size);
    sum2 = get_sum(buf_ptr + sector_size, sector_size * 2);
    simple_xfer(sub0_minor, (u64_t)sub_size - sector_size, buf_ptr, buf_size, false, sector_size, &res);
    test_sum(buf_ptr, sector_size, sum, true, &res);
    test_sum(buf_ptr + sector_size, sector_size * 2, sum2, true, &res);
    got_result(&res, "read mostly across partition end");

    sum = fill_rand(buf_ptr, buf_size);
    sum2 = get_sum(buf_ptr, sector_size);
    simple_xfer(sub0_minor, (u64_t)sub_size, buf_ptr, sector_size, false, 0, &res);
    test_sum(buf_ptr, sector_size, sum2, true, &res);
    got_result(&res, "one sector read at partition end");

    simple_xfer(sub0_minor, (u64_t)sub_size, buf_ptr, buf_size, false, 0, &res);
    test_sum(buf_ptr, buf_size, sum, true, &res);
    got_result(&res, "multisector read at partition end");

    simple_xfer(sub0_minor, (u64_t)sub_size + sector_size, buf_ptr, buf_size, false, 0, &res);
    test_sum(buf_ptr, sector_size, sum2, true, &res);
    got_result(&res, "single sector read beyond partition end");

    simple_xfer(sub0_minor, 0x1000000000000000ULL, buf_ptr, buf_size, false, 0, &res);
    test_sum(buf_ptr, buf_size, sum, true, &res);

    simple_xfer(sub1_minor, 0xffffffffffffffffULL - sector_size + 1, buf_ptr, sector_size, false, 0, &res);
    test_sum(buf_ptr, sector_size, sum2, true, &res);
    got_result(&res, "read with negative offset");

    free_dma_memory(buf_ptr, buf_size);
}

#include <stdint.h>
#include <stdlib.h>

static void write_limits(dev_t sub0_minor, dev_t sub1_minor, size_t sub_size) {
    uint8_t *buf_ptr = NULL;
    size_t buf_size = 0;
    uint32_t sum = 0, sub1_sum = 0;
    result_t res;

    if (!may_write) return;
    
    buf_size = sector_size * 3;
    buf_ptr = alloc_dma_memory(buf_size);
    if (!buf_ptr) goto cleanup;
    
    sub1_sum = fill_rand(buf_ptr, buf_size);
    simple_xfer(sub1_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
    got_result(&res, "write to second subpartition");

    sum = fill_rand(buf_ptr, sector_size);
    simple_xfer(sub0_minor, (uint64_t)sub_size - sector_size, buf_ptr, sector_size, TRUE, sector_size, &res);
    got_result(&res, "write up to partition end");

    fill_rand(buf_ptr, sector_size * 2);
    simple_xfer(sub0_minor, (uint64_t)sub_size - sector_size * 2, buf_ptr, sector_size * 2, FALSE, sector_size * 2, &res);
    test_sum(buf_ptr + sector_size, sector_size, sum, TRUE, &res);
    got_result(&res, "read up to partition end");

    fill_rand(buf_ptr, buf_size);
    uint32_t sum3 = get_sum(buf_ptr, sector_size);
    sum = get_sum(buf_ptr + sector_size, sector_size);

    simple_xfer(sub0_minor, (uint64_t)sub_size - sector_size * 2, buf_ptr, buf_size, TRUE, sector_size * 2, &res);
    got_result(&res, "write somewhat across partition end");

    fill_rand(buf_ptr, buf_size);
    uint32_t sum2 = get_sum(buf_ptr + sector_size, sector_size * 2);
    
    simple_xfer(sub0_minor, (uint64_t)sub_size - sector_size, buf_ptr, buf_size, FALSE, sector_size, &res);
    test_sum(buf_ptr, sector_size, sum, TRUE, &res);
    test_sum(buf_ptr + sector_size, sector_size * 2, sum2, TRUE, &res);
    got_result(&res, "read mostly across partition end");

    fill_rand(buf_ptr, buf_size);
    sum = get_sum(buf_ptr, sector_size);

    simple_xfer(sub0_minor, (uint64_t)sub_size - sector_size, buf_ptr, buf_size, TRUE, sector_size, &res);
    got_result(&res, "write mostly across partition end");

    fill_rand(buf_ptr, buf_size);
    sum2 = get_sum(buf_ptr + sector_size * 2, sector_size);

    simple_xfer(sub0_minor, (uint64_t)sub_size - sector_size * 2, buf_ptr, buf_size, FALSE, sector_size * 2, &res);
    test_sum(buf_ptr, sector_size, sum3, TRUE, &res);
    test_sum(buf_ptr + sector_size, sector_size, sum, TRUE, &res);
    test_sum(buf_ptr + sector_size * 2, sector_size, sum2, TRUE, &res);
    got_result(&res, "read somewhat across partition end");

    fill_rand(buf_ptr, sector_size);
    simple_xfer(sub0_minor, (uint64_t)sub_size, buf_ptr, sector_size, TRUE, 0, &res);
    got_result(&res, "write at partition end");

    simple_xfer(sub0_minor, (uint64_t)sub_size + sector_size, buf_ptr, sector_size, TRUE, 0, &res);
    got_result(&res, "write beyond partition end");

    fill_rand(buf_ptr, buf_size);
    simple_xfer(sub1_minor, 0ULL, buf_ptr, buf_size, FALSE, buf_size, &res);
    test_sum(buf_ptr, buf_size, sub1_sum, TRUE, &res);
    got_result(&res, "read from second subpartition");

    fill_rand(buf_ptr, sector_size);
    simple_xfer(sub1_minor, UINT64_MAX - sector_size + 1, buf_ptr, sector_size, TRUE, 0, &res);
    got_result(&res, "write with negative offset");

    simple_xfer(sub0_minor, (uint64_t)sub_size - sector_size, buf_ptr, sector_size, FALSE, sector_size, &res);
    test_sum(buf_ptr, sector_size, sum, TRUE, &res);
    got_result(&res, "read up to partition end");

cleanup:
    free_dma_memory(buf_ptr, buf_size);
}

static void vir_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs) {
    struct part_geom subpart, subpart2;
    size_t sub_size = sector_size * part_secs;
    result_t res;

    test_group("virtual subpartition limits", TRUE);

    if (!open_device(sub0_minor) || !open_device(sub1_minor)) {
        return;
    }

    subpart = part;
    subpart.size = (u64_t)sub_size;

    if (vir_ioctl(sub0_minor, DIOCSETP, &subpart, OK, &res) != OK || res.type != RESULT_OK) {
        got_result(&res, "ioctl to set first subpartition");
        goto cleanup;
    }

    if (vir_ioctl(sub0_minor, DIOCGETP, &subpart2, OK, &res) != OK ||
        res.type != RESULT_OK || subpart.base != subpart2.base || subpart.size != subpart2.size) {
        res.type = RESULT_BADVALUE;
        got_result(&res, "ioctl to get first subpartition");
        goto cleanup;
    }

    got_result(&res, "ioctl to get first subpartition");

    subpart.base += sub_size;

    if (vir_ioctl(sub1_minor, DIOCSETP, &subpart, OK, &res) != OK || res.type != RESULT_OK) {
        got_result(&res, "ioctl to set second subpartition");
        goto cleanup;
    }

    if (vir_ioctl(sub1_minor, DIOCGETP, &subpart2, OK, &res) != OK ||
        res.type != RESULT_OK || subpart.base != subpart2.base || subpart.size != subpart2.size) {
        res.type = RESULT_BADVALUE;
        got_result(&res, "ioctl to get second subpartition");
        goto cleanup;
    }
    
    got_result(&res, "ioctl to get second subpartition");

    read_limits(sub0_minor, sub1_minor, sub_size);
    write_limits(sub0_minor, sub1_minor, sub_size);

cleanup:
    close_device(sub1_minor);
    close_device(sub0_minor);
}

```c
static void real_limits(dev_t sub0_minor, dev_t sub1_minor, int part_secs)
{
    if (!may_write) return;

    test_group("real subpartition limits", may_write);

    size_t sub_size = sector_size * part_secs;
    size_t buf_size = sector_size;
    u8_t *buf_ptr = alloc_dma_memory(buf_size);

    memset(buf_ptr, 0, buf_size);

    result_t res;
    simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
    got_result(&res, "write of invalid partition table");

    close_device(driver_minor);
    open_device(driver_minor);

    check_subpartition(sub0_minor, &res);
    check_subpartition(sub1_minor, &res);

    close_device(sub1_minor);
    close_device(sub0_minor);

    write_valid_partition_table(buf_ptr, part_secs);

    simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, TRUE, buf_size, &res);
    got_result(&res, "write of valid partition table");

    close_device(driver_minor);
    open_device(driver_minor);

    verify_subpartition(sub0_minor, part.base + sector_size, (u64_t)part_secs * sector_size, &res);
    verify_subpartition(sub1_minor, part.base + (1 + part_secs) * sector_size, (u64_t)part_secs * sector_size, &res);

    read_limits(sub0_minor, sub1_minor, sub_size);
    write_limits(sub0_minor, sub1_minor, sub_size);

    close_device(sub0_minor);
    close_device(sub1_minor);

    free_dma_memory(buf_ptr, buf_size);
}

static void check_subpartition(dev_t sub_minor, result_t *res)
{
    struct part_geom subpart;
    open_device(sub_minor);
    vir_ioctl(sub_minor, DIOCGETP, &subpart, 0, res);
    if (res->type == RESULT_OK && subpart.size != 0)
    {
        res->type = RESULT_BADVALUE;
        res->value = ex64lo(subpart.size);
    }
    got_result(res, "ioctl to get subpartition");
}

static void write_valid_partition_table(u8_t *buf_ptr, int part_secs)
{
    memset(buf_ptr, 0, sector_size);
    struct part_entry *entry = (struct part_entry *)&buf_ptr[PART_TABLE_OFF];
    entry[0].sysind = MINIX_PART;
    entry[0].lowsec = part.base / sector_size + 1;
    entry[0].size = part_secs;
    entry[1].sysind = MINIX_PART;
    entry[1].lowsec = entry[0].lowsec + entry[0].size;
    entry[1].size = part_secs;
    buf_ptr[510] = 0x55;
    buf_ptr[511] = 0xAA;
}

static void verify_subpartition(dev_t sub_minor, u64_t expected_base, u64_t expected_size, result_t *res)
{
    struct part_geom subpart;
    open_device(sub_minor);
    vir_ioctl(sub_minor, DIOCGETP, &subpart, 0, res);
    if (res->type == RESULT_OK && 
        (subpart.base != expected_base || subpart.size != expected_size))
    {
        res->type = RESULT_BADVALUE;
        res->value = 0;
    }
    got_result(res, "ioctl to verify subpartition");
}
```

#include <stdio.h>

#define MINOR_d0p0s0 0
#define DEV_PER_DRIVE 1
#define NR_PARTITIONS 1
#define PART_SECS 9

static void output(const char *message) {
    printf("%s", message);
}

static void vir_limits(dev_t sub0_minor, dev_t sub1_minor, int sectors) {
    // Implementation code
}

static void real_limits(dev_t sub0_minor, dev_t sub1_minor, int sectors) {
    // Implementation code
}

static void part_limits(void)
{
    dev_t par, sub0_minor, sub1_minor;

    if (driver_minor >= MINOR_d0p0s0) {
        output("WARNING: operating on subpartition, skipping partition tests\n");
        return;
    }

    par = driver_minor % DEV_PER_DRIVE;
    sub0_minor = (par > 0) ? (MINOR_d0p0s0 + ((driver_minor / DEV_PER_DRIVE) * NR_PARTITIONS + par - 1) * NR_PARTITIONS) : (driver_minor + 1);
    sub1_minor = sub0_minor + 1;

    vir_limits(sub0_minor, sub1_minor, PART_SECS);
    real_limits(sub0_minor, sub1_minor, PART_SECS - 1);
}

#include <assert.h>
#include <string.h>

static void unaligned_size_io(uint64_t base_pos, uint8_t *buf_ptr, size_t buf_size,
    uint8_t *sec_ptr[2], int sectors, int pattern, uint32_t ssum[5]) {

    iovec_t iov[3], iovt[3];
    uint32_t rsum[3];
    result_t res;
    size_t total_size = sector_size * sectors;
    int i, nr_req;

    if ((sector_size / element_size == 2 && sectors == 1 && pattern == 2) || !may_write) {
        return;
    }

    base_pos += sector_size;

    fill_rand(sec_ptr[0], sector_size);
    rsum[0] = get_sum(sec_ptr[0] + element_size, sector_size - element_size);

    fill_rand(buf_ptr, buf_size);

    switch (pattern) {
    case 0:
        iovt[0].iov_addr = (vir_bytes)sec_ptr[0];
        iovt[0].iov_size = element_size;
        iovt[1].iov_addr = (vir_bytes)buf_ptr;
        iovt[1].iov_size = total_size - element_size;
        rsum[1] = get_sum(buf_ptr + iovt[1].iov_size, element_size);
        nr_req = 2;
        break;
    case 1:
        iovt[0].iov_addr = (vir_bytes)buf_ptr;
        iovt[0].iov_size = total_size - element_size;
        rsum[1] = get_sum(buf_ptr + iovt[0].iov_size, element_size);
        iovt[1].iov_addr = (vir_bytes)sec_ptr[0];
        iovt[1].iov_size = element_size;
        nr_req = 2;
        break;
    case 2:
        iovt[0].iov_addr = (vir_bytes)sec_ptr[0];
        iovt[0].iov_size = element_size;
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
        assert(0);
    }

    memcpy(iov, iovt, sizeof(iov));
    vir_xfer(driver_minor, base_pos, iov, nr_req, FALSE, total_size, &res);

    test_sum(sec_ptr[0] + element_size, sector_size - element_size, rsum[0], TRUE, &res);

    switch (pattern) {
    case 0:
        test_sum(buf_ptr + iovt[1].iov_size, element_size, rsum[1], TRUE, &res);
        memmove(buf_ptr + element_size, buf_ptr, iovt[1].iov_size);
        memcpy(buf_ptr, sec_ptr[0], element_size);
        break;
    case 1:
        test_sum(buf_ptr + iovt[0].iov_size, element_size, rsum[1], TRUE, &res);
        memcpy(buf_ptr + iovt[0].iov_size, sec_ptr[0], element_size);
        break;
    case 2:
        test_sum(buf_ptr + iovt[1].iov_size, element_size * 2, rsum[1], TRUE, &res);
        test_sum(sec_ptr[1] + element_size, sector_size - element_size, rsum[2], TRUE, &res);
        memmove(buf_ptr + element_size, buf_ptr, iovt[1].iov_size);
        memcpy(buf_ptr, sec_ptr[0], element_size);
        memcpy(buf_ptr + element_size + iovt[1].iov_size, sec_ptr[1], element_size);
        break;
    }

    for (i = 0; i < sectors; i++) {
        test_sum(buf_ptr + sector_size * i, sector_size, ssum[1 + i], TRUE, &res);
    }

    got_result(&res, "read with small elements");

    if (!may_write) {
        return;
    }

    for (i = 0; i < sectors; i++) {
        ssum[1 + i] = fill_rand(buf_ptr + sector_size * i, sector_size);
    }

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
    }

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

#include <stdbool.h>
#include <assert.h>

#define NUM_ITERATIONS 5
#define NUM_SUBTESTS 9

static void unaligned_size(void)
{
    u8_t *buf_ptr = NULL, *sec_ptr[2] = {NULL, NULL};
    size_t buf_size = sector_size * NUM_ITERATIONS;
    u32_t sum = 0, ssum[NUM_ITERATIONS] = {0};
    u64_t base_pos = (u64_t)sector_size * 2;
    result_t res;
    bool element_smaller_than_sector = (sector_size != element_size);

    test_group("sector-unaligned elements", element_smaller_than_sector);

    if (!element_smaller_than_sector)
        return;

    assert(sector_size % element_size == 0);

    buf_ptr = alloc_dma_memory(buf_size);
    sec_ptr[0] = alloc_dma_memory(sector_size);
    sec_ptr[1] = alloc_dma_memory(sector_size);

    if (!buf_ptr || !sec_ptr[0] || !sec_ptr[1])
        goto cleanup;

    if (may_write) {
        sum = fill_rand(buf_ptr, buf_size);

        for (int i = 0; i < NUM_ITERATIONS; i++)
            ssum[i] = get_sum(buf_ptr + sector_size * i, sector_size);

        simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, true, buf_size, &res);
        got_result(&res, "write several sectors");
    }

    fill_rand(buf_ptr, buf_size);

    simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, false, buf_size, &res);

    if (may_write) {
        test_sum(buf_ptr, buf_size, sum, true, &res);
    } else {
        for (int i = 0; i < NUM_ITERATIONS; i++)
            ssum[i] = get_sum(buf_ptr + sector_size * i, sector_size);
    }

    got_result(&res, "read several sectors");

    for (int i = 0; i < NUM_SUBTESTS; i++) {
        unaligned_size_io(base_pos, buf_ptr, buf_size, sec_ptr, i / 3 + 1, i % 3, ssum);
    }

    if (may_write) {
        fill_rand(buf_ptr, buf_size);

        simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, false, buf_size, &res);

        test_sum(buf_ptr, sector_size, ssum[0], true, &res);
        test_sum(buf_ptr + sector_size * 4, sector_size, ssum[4], true, &res);

        got_result(&res, "check first and last sectors");
    }

cleanup:
    free_dma_memory((void *)sec_ptr[1], sector_size);
    free_dma_memory((void *)sec_ptr[0], sector_size);
    free_dma_memory((void *)buf_ptr, buf_size);
}

static void unaligned_pos1(void)
{
    u8_t *buf_ptr = NULL, *buf2_ptr = NULL;
    size_t buf_size, buf2_size, size;
    u32_t sum, sum2;
    u64_t base_pos;
    result_t res;

    test_group("sector-unaligned positions, part one", min_read != sector_size);

    if (min_read == sector_size || sector_size % min_read != 0 || min_read % element_size != 0) {
        return;
    }

    buf_size = buf2_size = sector_size * 3;
    base_pos = (u64_t)sector_size * 3;

    buf_ptr = alloc_dma_memory(buf_size);
    buf2_ptr = alloc_dma_memory(buf2_size);

    if (!buf_ptr || !buf2_ptr) {
        free_dma_memory(buf_ptr, buf_size);
        free_dma_memory(buf2_ptr, buf2_size);
        return;
    }

    if (may_write) {
        sum = fill_rand(buf_ptr, buf_size);
        simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE, buf_size, &res);
        got_result(&res, "write several sectors");
    }

    fill_rand(buf_ptr, buf_size);
    simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);

    if (may_write) {
        test_sum(buf_ptr, buf_size, sum, TRUE, &res);
    }
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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#define NR_IOREQS 10

typedef struct {
    void *iov_addr;
    size_t iov_size;
} iovec_t;

typedef struct {
    // Define fields based on the actual structure
} result_t;

extern uint32_t fill_rand(void *buf, size_t size);
extern uint32_t get_sum(void *buf, size_t size);
extern void simple_xfer(int driver_minor, uint64_t pos, void *buf, size_t size, int write, size_t req_size, result_t *res);
extern void vir_xfer(int driver_minor, uint64_t pos, iovec_t *iov, int count, int write, size_t req_size, result_t *res);
extern uint8_t *alloc_dma_memory(size_t size);
extern void free_dma_memory(uint8_t *buf, size_t size);
extern void got_result(result_t *res, const char *msg);
extern int test_group(const char *description, int condition);
extern void test_sum(void *buf, size_t size, uint32_t sum, int may_write, result_t *res);

// Assume globals for these variables
extern int driver_minor;
extern size_t max_size;
extern size_t sector_size;
extern size_t min_read;
extern int may_write;

static void unaligned_pos2(void) {
    if (!test_group("sector-unaligned positions, part two", min_read != sector_size) || min_read == sector_size) {
        return;
    }

    size_t buf_size = max_size + sector_size;
    uint8_t *buf_ptr = alloc_dma_memory(buf_size);
    assert(buf_ptr != NULL);
    uint8_t *buf2_ptr = alloc_dma_memory(buf_size);
    assert(buf2_ptr != NULL);

    uint64_t base_pos = (uint64_t)sector_size * 3;
    uint32_t sum = 0, sum2 = 0, rsum[NR_IOREQS] = {0};
    iovec_t iov[NR_IOREQS];
    result_t res;

    if (may_write) {
        sum = fill_rand(buf_ptr, max_size);
        simple_xfer(driver_minor, base_pos, buf_ptr, max_size, 1, max_size, &res);
        got_result(&res, "large baseline write");

        sum2 = fill_rand(buf_ptr + max_size, sector_size);
        simple_xfer(driver_minor, base_pos + max_size, buf_ptr + max_size, sector_size, 1, sector_size, &res);
        got_result(&res, "small baseline write");
    }

    fill_rand(buf_ptr, buf_size);
    simple_xfer(driver_minor, base_pos, buf_ptr, max_size, 0, max_size, &res);

    if (may_write) {
        test_sum(buf_ptr, max_size, sum, 1, &res);
    }
    got_result(&res, "large baseline read");

    simple_xfer(driver_minor, base_pos + max_size, buf_ptr + max_size, sector_size, 0, sector_size, &res);
    if (may_write) {
        test_sum(buf_ptr + max_size, sector_size, sum2, 1, &res);
    }
    got_result(&res, "small baseline read");

    fill_rand(buf2_ptr, buf_size);
    for (int i = 0; i < NR_IOREQS; i++) {
        iov[i].iov_addr = buf2_ptr + i * sector_size;
        iov[i].iov_size = min_read;
        rsum[i] = get_sum(buf2_ptr + i * sector_size + min_read, sector_size - min_read);
    }

    vir_xfer(driver_minor, base_pos + min_read, iov, NR_IOREQS, 0, min_read * NR_IOREQS, &res);
    for (int i = 0; i < NR_IOREQS; i++) {
        test_sum(buf2_ptr + i * sector_size + min_read, sector_size - min_read, rsum[i], 1, &res);
        memmove(buf2_ptr + i * min_read, buf2_ptr + i * sector_size, min_read);
    }

    test_sum(buf2_ptr, min_read * NR_IOREQS, get_sum(buf_ptr + min_read, min_read * NR_IOREQS), 1, &res);
    got_result(&res, "small fully unaligned filled vector");

    fill_rand(buf2_ptr, buf_size);
    simple_xfer(driver_minor, base_pos + min_read, buf2_ptr, max_size, 0, max_size, &res);
    test_sum(buf2_ptr, max_size, get_sum(buf_ptr + min_read, max_size), 1, &res);
    got_result(&res, "large fully unaligned single element");

    size_t max_block = (max_size / NR_IOREQS) - ((max_size / NR_IOREQS) % sector_size);
    fill_rand(buf2_ptr, buf_size);

    for (int i = 0; i < NR_IOREQS; i++) {
        iov[i].iov_addr = buf2_ptr + i * max_block;
        iov[i].iov_size = max_block;
    }

    vir_xfer(driver_minor, base_pos + min_read, iov, NR_IOREQS, 0, max_block * NR_IOREQS, &res);
    test_sum(buf2_ptr, max_block * NR_IOREQS, get_sum(buf_ptr + min_read, max_block * NR_IOREQS), 1, &res);
    got_result(&res, "large fully unaligned filled vector");

    free_dma_memory(buf2_ptr, buf_size);
    free_dma_memory(buf_ptr, buf_size);
}

```c
static void sweep_area(u64_t base_pos) {
    u8_t *buf_ptr;
    size_t buf_size = sector_size * 8;
    u32_t sum = 0;
    u32_t ssum[8];
    result_t res;

    buf_ptr = alloc_dma_memory(buf_size);
    if (buf_ptr == NULL) return;

    if (may_write) {
        sum = fill_rand(buf_ptr, buf_size);
        simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, TRUE, buf_size, &res);
        got_result(&res, "write to full area");
    }

    fill_rand(buf_ptr, buf_size);
    simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);

    if (may_write) test_sum(buf_ptr, buf_size, sum, TRUE, &res);

    for (int i = 0; i < 8; i++) {
        ssum[i] = get_sum(buf_ptr + sector_size * i, sector_size);
    }

    got_result(&res, "read from full area");

    for (int i = 0; i < 6; i++) {
        size_t offset = sector_size * i;
        fill_rand(buf_ptr, sector_size * 3);
        
        simple_xfer(driver_minor, base_pos + offset, buf_ptr, sector_size * 3, FALSE, sector_size * 3, &res);

        for (int j = 0; j < 3; j++) {
            test_sum(buf_ptr + sector_size * j, sector_size, ssum[i + j], TRUE, &res);
        }

        got_result(&res, "read from subarea");

        if (!may_write) continue;

        fill_rand(buf_ptr, sector_size * 3);
        simple_xfer(driver_minor, base_pos + offset, buf_ptr, sector_size * 3, TRUE, sector_size * 3, &res);
        
        for (int j = 0; j < 3; j++) {
            ssum[i + j] = get_sum(buf_ptr + sector_size * j, sector_size);
        }

        got_result(&res, "write to subarea");
    }

    if (may_write) {
        fill_rand(buf_ptr, buf_size);
        simple_xfer(driver_minor, base_pos, buf_ptr, buf_size, FALSE, buf_size, &res);

        for (int i = 0; i < 8; i++) {
            test_sum(buf_ptr + sector_size * i, sector_size, ssum[i], TRUE, &res);
        }

        got_result(&res, "readback from full area");
    }

    free_dma_memory(buf_ptr, buf_size);
}
```

#include <stdbool.h>

static void sweep_and_check(u64_t pos, int check_integ)
{
    const size_t buf_size = sector_size * 3;
    result_t res;
    u32_t sum = 0L;
    u8_t *buf_ptr = NULL;

    if (check_integ) {
        buf_ptr = alloc_dma_memory(buf_size);

        if (buf_ptr == NULL) {
            report_error("Memory allocation failed");
            return;
        }

        if (may_write) {
            sum = fill_rand(buf_ptr, buf_size);
            simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, true, buf_size, &res);
            got_result(&res, "write integrity zone");
        }

        fill_rand(buf_ptr, buf_size);
        simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, false, buf_size, &res);
        got_result(&res, "read integrity zone");

        if (may_write) {
            test_sum(buf_ptr, buf_size, sum, true, &res);
        } else {
            sum = get_sum(buf_ptr, buf_size);
        }
    }

    sweep_area(pos);

    if (check_integ) {
        fill_rand(buf_ptr, buf_size);
        simple_xfer(driver_minor, 0ULL, buf_ptr, buf_size, false, buf_size, &res);
        test_sum(buf_ptr, buf_size, sum, true, &res);
        got_result(&res, "check integrity zone");
        free_dma_memory(buf_ptr, buf_size);
    }
}

void basic_sweep(void) {
    if (!test_group("basic area sweep", true)) {
        // Handle test_group failure if necessary
        return;
    }
    
    if (!sweep_area((u64_t)sector_size)) {
        // Handle sweep_area failure if necessary
        return;
    }
}

#include <stdint.h>
#include <stdbool.h>

static void high_disk_pos(void) {
    const uint64_t PART_SIZE_THRESHOLD = 0x100000000ULL;
    const uint64_t NEEDED_SECTORS = 4;
    const uint64_t MIN_PARTITION_SECTORS = 2 * NEEDED_SECTORS;
    uint64_t base_pos = PART_SIZE_THRESHOLD;

    base_pos -= base_pos % sector_size;

    if (part.base + part.size < base_pos || base_pos < part.base + sector_size * MIN_PARTITION_SECTORS) {
        test_group("high disk positions", false);
        return;
    }

    test_group("high disk positions", true);
    
    base_pos -= sector_size * NEEDED_SECTORS * 2;

    sweep_and_check(base_pos - part.base, part.base == 0ULL);
}

#include <stdbool.h>
#include <stdint.h>

static void high_part_pos(void) {
    uint64_t base_pos;

    if (part.base == 0ULL) {
        return;
    }

    base_pos = ((0x100000000ULL + (sector_size * 4)) / sector_size) * sector_size;

    bool valid_partition_size = (part.size >= base_pos);
    test_group("high partition positions", valid_partition_size);

    if (valid_partition_size) {
        base_pos -= sector_size * 8;
        sweep_and_check(base_pos, true);
    }
}

#include <stdbool.h>

static void high_lba_pos1(void) {
    const u64_t base_pos_24bit = (1ULL << 24) * sector_size;
    u64_t base_pos_adjusted = base_pos_24bit - (sector_size * 8);

    bool is_partition_valid = (part.base + part.size >= base_pos_24bit) && (base_pos_adjusted >= part.base);
    test_group("high LBA positions, part one", is_partition_valid);

    if (is_partition_valid) {
        sweep_and_check(base_pos_adjusted - part.base, part.base == 0ULL);
    }
}

#include <stdbool.h>

static void high_lba_pos2(void) {
    u64_t base_pos = (1ULL << 28) * sector_size;

    if (part.base + part.size < base_pos || part.base > base_pos - sector_size * 8) {
        test_group("high LBA positions, part two", false);
        return;
    }

    test_group("high LBA positions, part two", true);
    sweep_and_check(base_pos - part.base, part.base == 0ULL);
}

void high_pos(void) {
    basic_sweep();

    high_disk_pos();

    high_part_pos();

    high_lba_pos1();

    high_lba_pos2();
}

#include <stdbool.h>
#include <stdio.h>

static void open_device(int minor);

static void handle_device_open_result(bool success) {
    if (!success) {
        fprintf(stderr, "Failed to open device\n");
        // Additional error handling as needed
    }
}

static void open_primary(void) {
    bool success = true; // Assume success for demonstration
    handle_device_open_result(success);

    if (success) {
        open_device(driver_minor);
    }
}

static void close_primary(void)
{
    test_group("device close", TRUE);

    if (close_device(driver_minor) != 0) {
        // Handle error appropriately
        perror("Failed to close device");
        return;
    }

    if (nr_opened != 0) {
        // Handle unexpected open file descriptor state
        fprintf(stderr, "Warning: nr_opened is not zero. Current value: %d\n", nr_opened);
    }
}

static void do_tests(void) {
    if (!open_primary()) {
        // Handle error if the primary cannot be opened
        return;
    }

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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "optset.h"
#include "env.h"
#include "ds.h"
#include "driver.h"
#include "timestamps.h"

static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info)) 
{
    if (env_argc > 1) 
    {
        if (optset_parse(optset_table, env_argv[1]) != 0) 
        {
            fprintf(stderr, "Error parsing option set.\n");
            return EINVAL;
        }
    }

    if (driver_label[0] == '\0') 
    {
        fprintf(stderr, "No driver label given.\n");
        return EINVAL;
    }

    if (ds_retrieve_label_endpt(driver_label, &driver_endpt) != 0) 
    {
        fprintf(stderr, "Unable to resolve driver label.\n");
        return EINVAL;
    }

    if (driver_minor > 255) 
    {
        fprintf(stderr, "Invalid or no driver minor given.\n");
        return EINVAL;
    }

    srand48(getticks());

    printf("BLOCKTEST: driver label '%s' (endpt %d), minor %d\n",
           driver_label, driver_endpt, driver_minor);

    do_tests();

    printf("BLOCKTEST: summary: %d out of %d tests failed "
           "across %d group%s; %d driver deaths\n",
           failed_tests, total_tests, failed_groups,
           (failed_groups == 1) ? "" : "s", driver_deaths);

    return (failed_tests > 0) ? EINVAL : OK;
}

static void sef_local_startup(void)
{
	if (sef_setcb_init_fresh(sef_cb_init_fresh) != OK) {
		/* Handle error appropriately: log, exit, etc. */
		exit(EXIT_FAILURE);
	}

	if (sef_startup() != OK) {
		/* Handle error appropriately: log, exit, etc. */
		exit(EXIT_FAILURE);
	}
}

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 1 || argv == NULL) {
        fprintf(stderr, "Invalid arguments\n");
        return EXIT_FAILURE;
    }

    if (env_setargs(argc, argv) != 0) {
        fprintf(stderr, "Failed to set environment arguments\n");
        return EXIT_FAILURE;
    }

    if (sef_local_startup() != 0) {
        fprintf(stderr, "Startup initialization failed\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
