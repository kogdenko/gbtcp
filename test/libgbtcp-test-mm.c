// SPDX-License-Identifier: LGPL-2.1-only

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <kernel/gbtcp.h>
#include <kernel/mm.h>
#include <kernel/sys.h>

#define TEST_HEAP_SIZE (16 * GT_PAGE_SIZE)

static char test_path[PATH_MAX - 8];
static char test_tmp_path[PATH_MAX];

static int
setup(void **state)
{
	unlink(test_path);
	unlink(test_tmp_path);
	return 0;
}

static int
teardown(void **state)
{
	unlink(test_path);
	unlink(test_tmp_path);
	return 0;
}

static void
test_heap_create_basic(void **state)
{
	struct gt_mheap heap;
	struct gt_mheap_hdr *hdr;
	struct stat st;

	assert_int_equal(gt_mheap_create(&heap, test_path, TEST_HEAP_SIZE,
					 sizeof(struct gt_mheap_hdr), 1),
			 0);

	hdr = heap.mhp_hdr;
	assert_non_null(hdr);
	assert_true(heap.mhp_fd >= 0);

	// Header identity is persisted for attach()
	assert_int_equal((uintptr_t)hdr->mhh_base_addr, (uintptr_t)hdr);
	assert_int_equal(hdr->mhh_size, TEST_HEAP_SIZE);

	// Page memory starts on a page boundary after the header
	assert_int_equal((uintptr_t)hdr->mhh_mem % GT_PAGE_SIZE, 0);
	assert_true(hdr->mhh_mem > (u8 *)hdr);

	// All pages are free; page count matches the room after the header
	assert_true(hdr->mhh_n_pages > 0);
	assert_int_equal(hdr->mhh_free_pages, hdr->mhh_n_pages);
	assert_int_equal(hdr->mhh_n_pages,
			 ((uintptr_t)hdr->mhh_base_addr + TEST_HEAP_SIZE -
			  (uintptr_t)hdr->mhh_mem) /
				 GT_PAGE_SIZE);
	assert_int_equal(hdr->mhh_n_caches, 1);

	// Backing file is renamed into place and has the full size
	assert_int_equal(stat(test_path, &st), 0);
	assert_int_equal(st.st_size, TEST_HEAP_SIZE);
	assert_int_equal(access(test_tmp_path, F_OK), -1);

	// The mapping is writable end to end
	memset(hdr->mhh_mem, 0xa5, (size_t)hdr->mhh_n_pages * GT_PAGE_SIZE);

	gt_mheap_detach(&heap);
	assert_null(heap.mhp_hdr);
	assert_int_equal(heap.mhp_fd, -1);
}

static void
test_heap_create_bad_path(void **state)
{
	struct gt_mheap heap;

	assert_true(gt_mheap_create(&heap, "/nonexistent-dir/heap",
				    TEST_HEAP_SIZE, sizeof(struct gt_mheap_hdr),
				    1) < 0);
	assert_null(heap.mhp_hdr);
	assert_int_equal(heap.mhp_fd, -1);
}

static void *
mock_mmap(void *addr, size_t size, int prot, int flags, int fd, off_t offset)
{
	check_expected(size);
	errno = mock_type(int);
	return MAP_FAILED;
}

static void
test_heap_create_mmap_fail(void **state)
{
	struct gt_mheap heap;
	sys_mmap_f orig;

	orig = sys_mmap_fn;
	sys_mmap_fn = mock_mmap;
	expect_value(mock_mmap, size, TEST_HEAP_SIZE);
	will_return(mock_mmap, ENOMEM);

	assert_int_equal(gt_mheap_create(&heap, test_path, TEST_HEAP_SIZE,
					 sizeof(struct gt_mheap_hdr), 1),
			 -ENOMEM);
	sys_mmap_fn = orig;

	assert_null(heap.mhp_hdr);
	assert_int_equal(heap.mhp_fd, -1);

	// The temporary file must not leak and the final path must not appear
	assert_int_equal(access(test_tmp_path, F_OK), -1);
	assert_int_equal(access(test_path, F_OK), -1);
}

int
main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_heap_create_basic, setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_heap_create_bad_path,
						setup, teardown),
		cmocka_unit_test_setup_teardown(test_heap_create_mmap_fail,
						setup, teardown),
	};

	gt_init();

	snprintf(test_path, sizeof(test_path), "/tmp/gbtcp-test-mm.%d.heap",
		 (int)getpid());
	snprintf(test_tmp_path, sizeof(test_tmp_path), "%s.tmp", test_path);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
