#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <err.h>
#include <ctype.h>
#include <limits.h>
#include <gbtcp/gbtcp.h>

static int aflag;
static int nflag;
static int iflag;
static int qflag;
static int Hflag;
static int Lflag = INT_MAX;

static int sysctl_r(char *, int,  char *, const char *, int);

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define outf(...) if (1) printf(__VA_ARGS__)

static char *
ltrim(const char *s, const char *what)
{
	char *p;

	for (p = (char *)s; *p != '\0'; ++p) {
		if (strchr(what, *p) == NULL) {
			break;
		}
	}
	return p;
}

static char *
trim(const char *s, const char *what)
{
	char *p;
	int i, len;

	p = ltrim(s, what);
	len = strlen(p);
	for (i = len - 1; i >= 0; --i) {
		if (strchr(what, p[i]) == NULL) {
			break;
		}
	}
	p[i + 1] = '\0';
	return p;
}

static char *
strzcpy(char *dest, const char *src, size_t n)
{
	size_t i;

	for (i = 0; i < n - 1; ++i) {
		if (src[i] == '\0') {
			break;
		}
		dest[i] = src[i];
	}
	dest[i] = '\0';
	return dest;
}

static void
print_human_num(unsigned long long ull)
{
	int i;
	double d;
	char *kmgt[] = { "", "K", "M", "G", "T" };

	if (ull <= 1000) {
		outf("%llu", ull);
	} else {
		d = ull;
		for (i = 0; d > 1000; ++i) {
			if (i == ARRAY_SIZE(kmgt) - 1) {
				break;
			}
			d /= 1000;
		}
		outf("%.3f%s", d, kmgt[i]);
	}
}

static void
print_sysctl(const char *path, char *old)
{
	int i, zero;
	unsigned long long ull;
	char *s, *endptr;

	if (nflag) {
		zero = 1;
		for (i = 0; old[i] != '\0'; ++i) {
			if (isalnum(old[i]) && old[i] != '0') {
				zero = 0;
				break;
			}
		}
		if (zero) {
			return;
		}
	}
	while (*path == '.') {
		path++;
	}
	outf("%s=", path);
	if (!Hflag) {
		outf("%s\n", old);
		return;
	}
	s = old;
	while (*s != '\0') {
		ull = strtoull(s, &endptr, 10);
		if (*endptr == ',') {
			print_human_num(ull);
			outf(",");
			s = endptr + 1;
		} else if (*endptr == '\0') {
			print_human_num(ull);
			break;
		} else {
			// Skip not number until ','
			endptr = strchr(s, ',');
			if (endptr == NULL) {
				outf("%s", s);
				break;
			} else {
				outf("%.*s,", (int)(endptr - s), s);
				s = endptr + 1;
			}
		}
	}
	outf("\n");
}

static int
sysctl_list_r(char *path, int path_len, char *buf, int depth)
{
	int i, rc, len;

	// path: A.B.list
	for (i = 0; i < Lflag; ++i) {
		// buf: ,C
		assert(buf[0] == ',');
		if (buf[1] == '\0') {
			return -EPROTO;
		}
		len = snprintf(path + path_len, PATH_MAX - path_len, ".%s+", buf + 1);
		len += path_len;
		// path: A.B.list.C+
		if (len >= PATH_MAX) {
			path[PATH_MAX - 1] = '\0';
			return -ENAMETOOLONG;
		}
		path[len - 1] = '\0';
		// path: A.B.list.C
		rc = sysctl_r(path, len - 1, buf, NULL, depth + 1);
		if (rc < 0 && rc != -ENOENT) {
			return rc;
		}
		path[len - 1] = '+';
		path[len] = '\0';
		// path: A.B.list.C+
		rc = gt_sysctl(path, buf, NULL);
		if (rc == -1) {
			rc = -gt_errno;
			return rc;
		}
		if (buf[0] == '\0') {
			break;
		} else if (buf[0] != ',') {
			return -EPROTO;
		}
	}
	return 0;
}

static int
sysctl_r(char *path, int path_len, char *buf, const char *new, int depth)
{
	int rc;

	rc = gt_sysctl(path, buf, new);
	if (rc == -1) {
		rc = -gt_errno;
		return rc;
	}
	if (buf[0] == ',') {
		if (path_len && path[path_len - 1] == '+') {
			// path A.B.C.DDDD+
			// Remove .DDDD+
			path_len--;
			while (path_len > 0 && path[path_len] != '.') {
				path_len--;
			}
		}
		rc = sysctl_list_r(path, path_len, buf, depth + 1);
		return rc;
	} else {
		print_sysctl(path, buf);
	}
	return 0;
}

static int
sysctl_raw(const char *arg, int line_num)
{
	int rc;
	char *path, *new, *eql;
	char line[32];
	char arg_buf[GT_SYSCTL_BUFSIZ];
	char buf[GT_SYSCTL_BUFSIZ];

	strzcpy(arg_buf, arg, sizeof(arg_buf));
	// Separate variable name and value
	eql = strchr(arg_buf, '=');
	if (eql == NULL) {
		new = NULL;
	} else {
		*eql = '\0';
		new = trim(eql + 1, " \r\n\t");
	}
	path = trim(arg_buf, " .\r\n\t");
	rc = sysctl_r(path, strlen(path), buf, new, 0);
	if (rc < 0) {
		if (rc == -ENOENT) {
			if (iflag) {
				return 0;
			} else if (qflag) {
				return rc;
			}
		}
		if (line_num) {
			snprintf(line, sizeof(line), " at line %d", line_num);
		} else {
			line[0] = '\0';
		}
		warnx("'%s'%s: %s", path, line, strerror(-rc));
	}
	return rc;
}

static int
read_file(const char *path)
{	
	char buf[BUFSIZ];
	int rc, line_num;
	char *s, *x;
	FILE *file;

	line_num = 0;
	file = fopen(path, "r");
	if (file == NULL) {
		rc = -gt_errno;
		assert(rc < 0);
		warnx("fopen('%s') failed (%s)", path, strerror(gt_errno));
		return rc;
	}
	while ((s = fgets(buf, sizeof(buf), file)) != NULL) {
		line_num++;
		x = strchr(s, '#');
		if (x != NULL) {
			*x = '\0';
		}
		sysctl_raw(s, line_num);
	}
	fclose(file);
	return 0;
}

static void
usage()
{
	outf(
	"Usage: sysctl [options] [variable[=name] ...]\n"
	"\n"
	"\t-h             Print this help\n"
	"\t-f path        Apply file\n"
	"\t-a             Display all variables\n"
	"\t-i             Ignore unknown variables\n"
	"\t-Q             Be quiet\n");
}

int
main(int argc, char **argv)
{
	int i, rc, opt;
	const char *path;

	gt_init();
	path = NULL;
	while ((opt = getopt(argc, argv, "hf:aniQHL:")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return 0;
		case 'f':
			path = optarg;
			break;
		case 'a':
			aflag = 1;
			break;
		case 'n':
			nflag= 1;
			break;
		case 'i':
			iflag = 1;
			break;
		case 'q':
			qflag = 1;
			break;
		case 'H':
			Hflag = 1;
			break;
		case 'L':
			Lflag = strtoul(optarg, NULL, 10);
			break;
		}
	}
	if (path != NULL) {
		rc = read_file(path);
		if (rc < 0) {
			return EXIT_FAILURE;
		}
	}
	if (optind == argc && aflag == 0) {
		if (path == NULL) {
			usage();
			return EXIT_FAILURE;
		} else {
			return EXIT_SUCCESS;
		}
	}
	for (i = optind; i < argc; ++i) {
		sysctl_raw(argv[i], 0);
	}
	if (aflag && optind == argc) {
		sysctl_raw("", 0);
	}
	return EXIT_SUCCESS;
}
