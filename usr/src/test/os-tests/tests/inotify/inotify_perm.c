/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Verify that an inotify watch can only be added through a file descriptor
 * that is open for reading, that adding a watch on a FIFO does not wait for
 * a writer, and that reads and writes on a FIFO in a watched directory do not
 * generate events. The framework is created as root and the checks are then
 * run as an unprivileged user in a child process.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ccompile.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

static char ip_base[PATH_MAX];
static char ip_hidden[PATH_MAX];
static char ip_open[PATH_MAX];
static char ip_file[PATH_MAX];
static char ip_exec[PATH_MAX];
static char ip_fifo[PATH_MAX];

static bool ip_failed;

static void __PRINTFLIKE(1)
ip_fail(const char *fmt, ...)
{
	va_list ap;

	ip_failed = true;
	(void) fprintf(stderr, "TEST FAILED: ");
	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	(void) fprintf(stderr, "\n");
}

static void
ip_pass(const char *desc)
{
	(void) printf("TEST PASSED: %s\n", desc);
}

static int
ip_open_fd(const char *path, int oflag)
{
	int fd;

	if ((fd = open(path, oflag)) < 0) {
		ip_fail("open %s (0x%x) failed: %s", path, oflag,
		    strerror(errno));
	}

	return (fd);
}

static void
ip_add_watch_eacces(int ifd, const char *path, int oflag, const char *desc)
{
	inotify_addwatch_t ioc;
	int fd;

	if ((fd = ip_open_fd(path, oflag)) < 0)
		return;

	(void) memset(&ioc, 0, sizeof (ioc));
	ioc.inaw_fd = fd;
	ioc.inaw_mask = IN_ALL_EVENTS;

	if (ioctl(ifd, INOTIFYIOC_ADD_WATCH, &ioc) >= 0)
		ip_fail("%s: watch added unexpectedly", desc);
	else if (errno != EACCES)
		ip_fail("%s: expected EACCES, got %s", desc, strerror(errno));
	else
		ip_pass(desc);

	(void) close(fd);
}

static void
ip_add_child(int ifd, int fd, const char *name, int expected,
    const char *desc)
{
	inotify_addchild_t ioc;
	int ret;

	(void) memset(&ioc, 0, sizeof (ioc));
	ioc.inac_fd = fd;
	ioc.inac_name = (char *)name;

	ret = ioctl(ifd, INOTIFYIOC_ADD_CHILD, &ioc);
	if (expected == 0 && ret != 0) {
		ip_fail("%s: failed: %s", desc, strerror(errno));
	} else if (expected != 0 && ret == 0) {
		ip_fail("%s: child added unexpectedly", desc);
	} else if (expected != 0 && errno != expected) {
		ip_fail("%s: expected %s, got %s", desc, strerror(expected),
		    strerror(errno));
	} else {
		ip_pass(desc);
	}
}

static void
ip_ioctl_tests(void)
{
	inotify_addwatch_t ioc;
	int ifd, rfd, sfd;

	if ((ifd = inotify_init()) < 0) {
		ip_fail("inotify_init failed: %s", strerror(errno));
		return;
	}

	ip_add_watch_eacces(ifd, ip_hidden, O_SEARCH,
	    "O_SEARCH descriptor for an unreadable directory");
	ip_add_watch_eacces(ifd, ip_open, O_SEARCH,
	    "O_SEARCH descriptor for a readable directory");
	ip_add_watch_eacces(ifd, ip_exec, O_EXEC,
	    "O_EXEC descriptor for an execute-only file");

	if ((rfd = ip_open_fd(ip_open, O_RDONLY)) < 0)
		goto out;
	if ((sfd = ip_open_fd(ip_open, O_SEARCH)) < 0) {
		(void) close(rfd);
		goto out;
	}

	(void) memset(&ioc, 0, sizeof (ioc));
	ioc.inaw_fd = rfd;
	ioc.inaw_mask = IN_ALL_EVENTS;

	if (ioctl(ifd, INOTIFYIOC_ADD_WATCH, &ioc) < 0) {
		ip_fail("O_RDONLY descriptor for a readable directory: %s",
		    strerror(errno));
	} else {
		ip_pass("O_RDONLY descriptor for a readable directory");
		ip_add_child(ifd, sfd, "file", EACCES,
		    "child added through an O_SEARCH descriptor");
		ip_add_child(ifd, rfd, "file", 0,
		    "child added through an O_RDONLY descriptor");
	}

	(void) close(sfd);
	(void) close(rfd);
out:
	(void) close(ifd);
}

static void
ip_libc_tests(void)
{
	char buf[sizeof (struct inotify_event) + NAME_MAX + 1]
	    __aligned(__alignof__(struct inotify_event));
	bool found = false;
	ssize_t len;
	int ifd, fd;

	if ((ifd = inotify_init1(IN_NONBLOCK)) < 0) {
		ip_fail("inotify_init1 failed: %s", strerror(errno));
		return;
	}

	if (inotify_add_watch(ifd, ip_hidden, IN_ALL_EVENTS) >= 0) {
		ip_fail("inotify_add_watch on an unreadable directory "
		    "succeeded unexpectedly");
	} else if (errno != EACCES) {
		ip_fail("inotify_add_watch on an unreadable directory: "
		    "expected EACCES, got %s", strerror(errno));
	} else {
		ip_pass("inotify_add_watch on an unreadable directory");
	}

	if (inotify_add_watch(ifd, ip_open, IN_MODIFY) < 0) {
		ip_fail("inotify_add_watch on a readable directory: %s",
		    strerror(errno));
		goto out;
	}

	if ((fd = ip_open_fd(ip_file, O_WRONLY)) < 0)
		goto out;
	if (write(fd, "x", 1) != 1)
		ip_fail("write to %s failed: %s", ip_file, strerror(errno));
	(void) close(fd);

	while ((len = read(ifd, buf, sizeof (buf))) > 0) {
		for (char *p = buf; p < buf + len; ) {
			const struct inotify_event *ev = (void *)p;

			if ((ev->mask & IN_MODIFY) != 0 && ev->len > 0 &&
			    strcmp(ev->name, "file") == 0) {
				found = true;
			}
			p += sizeof (*ev) + ev->len;
		}
	}

	if (found)
		ip_pass("IN_MODIFY reported for a file in a watched directory");
	else
		ip_fail("no IN_MODIFY event for %s", ip_file);

out:
	(void) close(ifd);
}

static void
ip_fifo_watch_test(void)
{
	int ifd;

	if ((ifd = inotify_init()) < 0) {
		ip_fail("inotify_init failed: %s", strerror(errno));
		return;
	}

	/*
	 * The FIFO has no writer. If adding the watch blocks, the alarm
	 * terminates this process and the parent reports the failure.
	 */
	(void) alarm(10);
	if (inotify_add_watch(ifd, ip_fifo, IN_ALL_EVENTS) < 0)
		ip_fail("inotify_add_watch on a FIFO: %s", strerror(errno));
	else
		ip_pass("inotify_add_watch on a FIFO without a writer");
	(void) alarm(0);

	(void) close(ifd);
}

static void
ip_fifo_tests(void)
{
	char buf[sizeof (struct inotify_event) + NAME_MAX + 1]
	    __aligned(__alignof__(struct inotify_event));
	uint32_t seen = 0;
	ssize_t len;
	int ifd, rfd, wfd;

	if ((ifd = inotify_init1(IN_NONBLOCK)) < 0) {
		ip_fail("inotify_init1 failed: %s", strerror(errno));
		return;
	}

	if (inotify_add_watch(ifd, ip_open, IN_ALL_EVENTS) < 0) {
		ip_fail("inotify_add_watch on a readable directory: %s",
		    strerror(errno));
		goto out;
	}

	if ((rfd = ip_open_fd(ip_fifo, O_RDONLY | O_NONBLOCK)) < 0)
		goto out;
	if ((wfd = ip_open_fd(ip_fifo, O_WRONLY)) < 0) {
		(void) close(rfd);
		goto out;
	}

	if (write(wfd, "x", 1) != 1)
		ip_fail("write to %s failed: %s", ip_fifo, strerror(errno));
	if (read(rfd, buf, 1) != 1)
		ip_fail("read from %s failed: %s", ip_fifo, strerror(errno));
	(void) close(wfd);
	(void) close(rfd);

	while ((len = read(ifd, buf, sizeof (buf))) > 0) {
		for (char *p = buf; p < buf + len; ) {
			const struct inotify_event *ev = (void *)p;

			if (ev->len > 0 && strcmp(ev->name, "fifo") == 0)
				seen |= ev->mask;
			p += sizeof (*ev) + ev->len;
		}
	}

	if ((seen & IN_OPEN) == 0)
		ip_fail("no IN_OPEN event for %s", ip_fifo);
	else
		ip_pass("IN_OPEN reported for a FIFO in a watched directory");

	if ((seen & (IN_ACCESS | IN_MODIFY)) != 0) {
		ip_fail("I/O events reported for %s (mask 0x%x)", ip_fifo,
		    seen);
	} else {
		ip_pass("no I/O events for a FIFO in a watched directory");
	}

out:
	(void) close(ifd);
}

static void
ip_mkfile(const char *path, mode_t mode)
{
	int fd;

	if ((fd = open(path, O_CREAT | O_EXCL | O_WRONLY, mode)) < 0)
		err(EXIT_FAILURE, "failed to create %s", path);
	if (fchmod(fd, mode) != 0)
		err(EXIT_FAILURE, "failed to chmod %s", path);
	(void) close(fd);
}

static void
ip_path(char *buf, const char *name)
{
	int len;

	len = snprintf(buf, PATH_MAX, "%s/%s", ip_base, name);
	if (len < 0 || len >= PATH_MAX)
		errx(EXIT_FAILURE, "path for %s is too long", name);
}

static void
ip_cleanup(void)
{
	char hfile[PATH_MAX];

	ip_path(hfile, "hidden/secret");
	(void) unlink(hfile);
	(void) unlink(ip_file);
	(void) unlink(ip_exec);
	(void) unlink(ip_fifo);
	(void) rmdir(ip_hidden);
	(void) rmdir(ip_open);
	(void) rmdir(ip_base);
}

int
main(void)
{
	char hfile[PATH_MAX];
	pid_t pid;
	int status;

	if (getuid() != 0)
		errx(EXIT_FAILURE, "this test must be run as root");

	(void) strlcpy(ip_base, "/tmp/inotify_perm.XXXXXX", sizeof (ip_base));
	if (mkdtemp(ip_base) == NULL)
		err(EXIT_FAILURE, "failed to create temporary directory");
	if (chmod(ip_base, 0755) != 0)
		err(EXIT_FAILURE, "failed to chmod %s", ip_base);

	ip_path(ip_hidden, "hidden");
	ip_path(ip_open, "open");
	ip_path(ip_file, "open/file");
	ip_path(ip_exec, "exec");
	ip_path(ip_fifo, "open/fifo");
	ip_path(hfile, "hidden/secret");

	if (mkdir(ip_hidden, 0711) != 0 || chmod(ip_hidden, 0711) != 0)
		err(EXIT_FAILURE, "failed to create %s", ip_hidden);
	if (mkdir(ip_open, 0755) != 0 || chmod(ip_open, 0755) != 0)
		err(EXIT_FAILURE, "failed to create %s", ip_open);
	ip_mkfile(hfile, 0600);
	ip_mkfile(ip_file, 0666);
	ip_mkfile(ip_exec, 0111);
	if (mkfifo(ip_fifo, 0666) != 0 || chmod(ip_fifo, 0666) != 0)
		err(EXIT_FAILURE, "failed to create %s", ip_fifo);

	if ((pid = fork()) < 0)
		err(EXIT_FAILURE, "fork failed");

	if (pid == 0) {
		if (setgid(GID_NOBODY) != 0 || setuid(UID_NOBODY) != 0)
			err(EXIT_FAILURE, "failed to drop to the nobody user");

		ip_ioctl_tests();
		ip_libc_tests();
		ip_fifo_watch_test();
		ip_fifo_tests();
		(void) fflush(stdout);
		_exit(ip_failed ? EXIT_FAILURE : EXIT_SUCCESS);
	}

	if (waitpid(pid, &status, 0) != pid)
		err(EXIT_FAILURE, "waitpid failed");

	ip_cleanup();

	if (WIFSIGNALED(status)) {
		(void) fprintf(stderr,
		    "TEST FAILED: child terminated by signal %d\n",
		    WTERMSIG(status));
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
		(void) fprintf(stderr, "One or more tests failed\n");
		return (EXIT_FAILURE);
	}

	(void) printf("All tests passed\n");
	return (EXIT_SUCCESS);
}
