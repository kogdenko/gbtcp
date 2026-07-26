// SPDX-License-Identifier: LGPL-2.1-only

#include <execinfo.h>

#include <gbtcp/kernel/backtrace.h>
#include <gbtcp/kernel/list.h>
#include <gbtcp/kernel/worker.h>

#if GT_HAVE_BFD
#include <bfd.h>

struct gt_bfd {
	struct gt_dlist link;
	u8 filetype;
	bfd *abfd;
	asymbol **syms;
};

struct gt_bfd_debug_info {
	const char *func;
	const char *src_filename;
	const char *bfd_filename;
	u32 line;
};

static void gt_sig_printf(int fd, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

void
gt_bfd_init(void)
{
	gt_dlist_init(&gt_current_process.pc_bfd_head);

	bfd_init();
}

void
gt_bfd_deinit(void)
{
	struct gt_bfd *bfd;

	while (!gt_dlist_is_empty(&gt_current_process.pc_bfd_head)) {
		bfd = GT_DLIST_FIRST(&gt_current_process.pc_bfd_head,
				     struct gt_bfd, link);
		gt_bfd_close(bfd);
	}
}

// bfd_get_filename()

static void
gt_bfd_free(struct gt_bfd *bfd)
{
	if (bfd->abfd != NULL) {
		bfd_close(bfd->abfd);
	}
	sys_free(bfd->syms);
	sys_free(bfd);
}

int
gt_bfd_open(struct gt_bfd **pbfd, const char *path, u8 filetype)
{
	long rc;
	struct gt_bfd *bfd;

	bfd = sys_malloc(sizeof(*bfd));
	if (bfd == NULL) {
		return -ENOMEM;
	}

	bfd->syms = NULL;
	bfd->filetype = filetype;
	bfd->abfd = bfd_openr(path, NULL);
	if (bfd->abfd == NULL) {
		gt_bfd_free(bfd);
		return -EINVAL;
	}

	if (!bfd_check_format(bfd->abfd, bfd_object)) {
		gt_bfd_free(bfd);
		return -EINVAL;
	}

	rc = bfd_get_symtab_upper_bound(bfd->abfd);
	if (rc <= 0) {
		gt_bfd_free(bfd);
		return -EINVAL;
	}

	bfd->syms = (asymbol **)sys_malloc(rc);
	if (bfd->syms == NULL) {
		gt_bfd_free(bfd);
		return -ENOMEM;
	}

	rc = bfd_canonicalize_symtab(bfd->abfd, bfd->syms);
	if (rc <= 0) {
		gt_bfd_free(bfd);
		return -EINVAL;
	}

	GT_DLIST_INSERT_TAIL(&gt_current_process.pc_bfd_head, bfd, link);
	if (pbfd != NULL) {
		*pbfd = bfd;
	}

	return 0;
}

int
gt_bfd_close(struct gt_bfd *bfd)
{
	GT_DLIST_REMOVE(bfd, link);
	gt_bfd_free(bfd);
	return 0;
}

static struct gt_bfd *
gt_bfd_find(const char *path)
{
	struct gt_bfd *bfd;

	GT_DLIST_FOREACH(bfd, &gt_current_process.pc_bfd_head, link) {
		if (!strcmp(bfd_get_filename(bfd->abfd), path)) {
			return bfd;
		}
	}

	return NULL;
}

static u8
gt_bfd_get_debug_info(void *addr, struct gt_bfd_debug_info *info)
{
	uintptr_t off;
	Dl_info dlinfo;
	asection *section;
	struct gt_bfd *bfd;

	if (dladdr(addr, &dlinfo) == 0) {
		return 0;
	}

	bfd = gt_bfd_find(dlinfo.dli_fname);
	if (bfd == NULL) {
		return 0;
	}

	info->bfd_filename = bfd_get_filename(bfd->abfd);

	section = bfd_get_section_by_name(bfd->abfd, ".text");
	if (section == NULL) {
		return 0;
	}

	off = (uintptr_t)addr - section->vma;
	if (bfd->filetype == GT_BFD_SHARED_LIBRARY) {
		off -= (uintptr_t)dlinfo.dli_fbase;
	}

	if (bfd_find_nearest_line(bfd->abfd, section, bfd->syms, off,
				  &info->src_filename, &info->func,
				  &info->line)) {
		if (info->src_filename != NULL && info->func != NULL) {
			info->src_filename = gt_basename(info->src_filename);
			info->bfd_filename = gt_basename(info->bfd_filename);
			return 1;
		}
	}

	return 0;
}

static void
gt_sig_printf(int fd, const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	sys_write_f write_fn;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	write_fn = sys_write_fn;
	if (write_fn == NULL) {
		write_fn = write;
	}
	(*write_fn)(fd, buf, strlen(buf));
}

void
gt_print_backtrace(int fd)
{
	int i, size;
	void *addrs[128];
	char **symbols;
	struct gt_bfd_debug_info info;

	gt_sig_printf(fd, "Process %d received signal\n", (int)getpid());

	size = backtrace(addrs, GT_ARRAY_SIZE(addrs));
	symbols = backtrace_symbols(addrs, size);
	if (symbols == NULL) {
		return;
	}

	for (i = 0; i < size; ++i) {
		if (gt_bfd_get_debug_info(addrs[i], &info)) {
			gt_sig_printf(fd, "#%-2d %p %s`%s at %s:%u\n", i,
				      addrs[i], info.bfd_filename, info.func,
				      info.src_filename, info.line);
		} else {
			gt_sig_printf(fd, "#%-2d %s\n", i, symbols[i]);
		}
	}

	free(symbols);
}
#else // GT_HAVE_BFD
void
gt_bfd_init(void)
{
}

void
gt_bfd_deinit(void)
{
}

int
gt_bfd_open(struct gt_bfd **pbfd, const char *path, u8 filetype)
{
	return 0;
}

int
gt_bfd_close(struct gt_bfd *bfd)
{
	return 0;
}

void
gt_print_backtrace(int fd)
{
	int size;
	void *buf[128];

	size = backtrace(buf, GT_ARRAY_SIZE(buf));
	backtrace_symbols_fd(buf, size, fd);
}
#endif
