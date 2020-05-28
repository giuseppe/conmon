#define _GNU_SOURCE

#include "ctrl.h"
#include "utils.h"
#include "globals.h"
#include "config.h"
#include "ctr_logging.h"
#include "conn_sock.h"
#include "cmsg.h"
#include "cli.h" // opt_bundle_path

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>

#include <seccomp.h>
#include <linux/seccomp.h>
#include <linux/netlink.h>

static struct seccomp_notif_sizes sizes;
static struct seccomp_notif *req;
static struct seccomp_notif_resp *resp;

static void resize_winsz(int height, int width);
static gboolean read_from_ctrl_buffer(int fd, gboolean (*line_process_func)(char *));
static gboolean process_terminal_ctrl_line(char *line);
static gboolean process_winsz_ctrl_line(char *line);
static void setup_fifo(int *fifo_r, int *fifo_w, char *filename, char *error_var_name);

static int seccomp(unsigned int op, unsigned int flags, void *args)
{
	errno = 0;
	return syscall(__NR_seccomp, op, flags, args);
}

static int handle_req(struct seccomp_notif *req,
		      struct seccomp_notif_resp *resp, int listener)
{
	(void) req;
	(void) resp;
	(void) listener;

	static uint64_t audit_pid = 0;
	static uint64_t audit_fd = 0;
	
	resp->id = req->id;
	resp->error = 0;
	resp->val = 0;
	resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

	if (req->data.nr == __NR_socket) {
		resp->error = -ENOTSUP;
		resp->flags = 0;
		audit_pid = req->pid;
		audit_pid = req->pid;
	}

	if (req->data.nr == __NR_close &&
	    audit_pid == req->pid &&
	    audit_fd == req->data.args[0]) {
		audit_pid = 0;
		audit_fd = 0;
	}

	return 0;
}

gboolean seccomp_accept_cb(int fd, G_GNUC_UNUSED GIOCondition condition, G_GNUC_UNUSED gpointer user_data)
{
	ninfof("about to accept from seccomp_socket_fd: %d", fd);
	int connfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
	if (connfd < 0) {
		nwarn("Failed to accept console-socket connection");
		return G_SOURCE_CONTINUE;
	}

	struct file_t console = recvfd(connfd);
	close(connfd);
	if (req == NULL) {
		if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
			pexitf("seccomp");
		}
		req = malloc(sizes.seccomp_notif);
		if (!req)
			pexitf("malloc");

		resp = malloc(sizes.seccomp_notif_resp);
		if (!resp)
			pexitf("malloc");
		memset(resp, 0, sizes.seccomp_notif_resp);
	}
	g_unix_fd_add(console.fd, G_IO_IN|G_IO_HUP, seccomp_cb, NULL);
	return G_SOURCE_CONTINUE;
}

gboolean seccomp_cb(int fd, GIOCondition condition, G_GNUC_UNUSED gpointer user_data)
{
	(void) fd;
	if (condition & G_IO_IN) {
		memset(req, 0, sizes.seccomp_notif);
		if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, req)) {
			return G_SOURCE_CONTINUE;
		}

		if (handle_req(req, resp, fd) < 0) {
			return G_SOURCE_CONTINUE;
		}			

		if (ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 &&
		    errno != ENOENT) {
			return G_SOURCE_CONTINUE;
		}

	}
	return G_SOURCE_CONTINUE;
}

gboolean terminal_accept_cb(int fd, G_GNUC_UNUSED GIOCondition condition, G_GNUC_UNUSED gpointer user_data)
{

	ninfof("about to accept from console_socket_fd: %d", fd);
	int connfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
	if (connfd < 0) {
		nwarn("Failed to accept console-socket connection");
		return G_SOURCE_CONTINUE;
	}

	/* Not accepting anything else. */
	const char *csname = user_data;
	unlink(csname);
	close(fd);

	/* We exit if this fails. */
	ninfof("about to recvfd from connfd: %d", connfd);
	struct file_t console = recvfd(connfd);

	ninfof("console = {.name = '%s'; .fd = %d}", console.name, console.fd);
	free(console.name);

	/* We change the terminal settings to match kube settings */
	struct termios tset;
	if (tcgetattr(console.fd, &tset) == -1) {
		nwarn("Failed to get console terminal settings");
		goto exit;
	}

	tset.c_oflag |= ONLCR;

	if (tcsetattr(console.fd, TCSANOW, &tset) == -1)
		nwarn("Failed to set console terminal settings");

exit:
	/* We only have a single fd for both pipes, so we just treat it as
	 * stdout. stderr is ignored. */
	masterfd_stdin = console.fd;
	masterfd_stdout = console.fd;

	/* Now that we have a fd to the tty, make sure we handle any pending data
	 * that was already buffered. */
	schedule_master_stdin_write();

	/* now that we've set masterfd_stdout, we can register the ctrl_winsz_cb
	 * if we didn't set it here, we'd risk attempting to run ioctl on
	 * a negative fd, and fail to resize the window */
	g_unix_fd_add(winsz_fd_r, G_IO_IN, ctrl_winsz_cb, NULL);

	/* Clean up everything */
	close(connfd);

	/* Since we've gotten our console from the runtime, we no longer need to
	   be listening on this callback. */
	return G_SOURCE_REMOVE;
}

/*
 * ctrl_winsz_cb is a callback after a window resize event is sent along the winsz fd.
 */
gboolean ctrl_winsz_cb(int fd, G_GNUC_UNUSED GIOCondition condition, G_GNUC_UNUSED gpointer user_data)
{
	return read_from_ctrl_buffer(fd, process_winsz_ctrl_line);
}

/*
 * process_winsz_ctrl_line processes a line passed to the winsz fd
 * after the terminal_ctrl fd receives a winsz event.
 * It reads a height and length, and resizes the pty with it.
 */
static gboolean process_winsz_ctrl_line(char *line)
{
	int height, width, ret = -1;
	ret = sscanf(line, "%d %d\n", &height, &width);
	ninfof("Height: %d, Width: %d", height, width);
	if (ret != 2) {
		nwarn("Failed to sscanf message");
		return FALSE;
	}
	resize_winsz(height, width);
	return TRUE;
}

/*
 * ctrl_cb is a callback for handling events directly from the caller
 */
gboolean ctrl_cb(int fd, G_GNUC_UNUSED GIOCondition condition, G_GNUC_UNUSED gpointer user_data)
{
	return read_from_ctrl_buffer(fd, process_terminal_ctrl_line);
}

/*
 * process_terminal_ctrl_line takes a line from the
 * caller program (received through the terminal ctrl fd)
 * and either writes to the winsz fd (to handle terminal resize events)
 * or reopens log files.
 */
static gboolean process_terminal_ctrl_line(char *line)
{
	/* while the height and width won't be used in this function,
	 * we want to remove them from the buffer anyway
	 */
	int ctl_msg_type, height, width, ret = -1;
	ret = sscanf(line, "%d %d %d\n", &ctl_msg_type, &height, &width);
	if (ret != 3) {
		nwarn("Failed to sscanf message");
		return FALSE;
	}

	ninfof("Message type: %d", ctl_msg_type);
	switch (ctl_msg_type) {
	case WIN_RESIZE_EVENT: {
		_cleanup_free_ char *hw_str = g_strdup_printf("%d %d\n", height, width);
		if (write(winsz_fd_w, hw_str, strlen(hw_str)) < 0) {
			nwarn("Failed to write to window resizing fd. A resize event may have been dropped");
			return FALSE;
		}
		break;
	}
	case REOPEN_LOGS_EVENT:
		reopen_log_files();
		break;
	default:
		ninfof("Unknown message type: %d", ctl_msg_type);
		break;
	}
	return TRUE;
}

/*
 * read_from_ctrl_buffer reads a line (of no more than CTLBUFSZ) from an fd,
 * and calls line_process_func. It is a generic way to handle input on an fd
 * line_process_func should return TRUE if it succeeds, and FALSE if it fails
 * to process the line.
 */
static gboolean read_from_ctrl_buffer(int fd, gboolean (*line_process_func)(char *))
{
#define CTLBUFSZ 200
	static char ctlbuf[CTLBUFSZ];
	static int readsz = CTLBUFSZ - 1;
	static char *readptr = ctlbuf;
	ssize_t num_read = read(fd, readptr, readsz);
	if (num_read <= 0) {
		nwarnf("Failed to read from fd %d", fd);
		return G_SOURCE_CONTINUE;
	}

	readptr[num_read] = '\0';
	ninfof("Got ctl message: %s on fd %d", ctlbuf, fd);

	char *beg = ctlbuf;
	char *newline = strchrnul(beg, '\n');
	/* Process each message which ends with a line */
	while (*newline != '\0') {
		if (!line_process_func(ctlbuf))
			return G_SOURCE_CONTINUE;

		beg = newline + 1;
		newline = strchrnul(beg, '\n');
	}
	if (num_read == (CTLBUFSZ - 1) && beg == ctlbuf) {
		/*
		 * We did not find a newline in the entire buffer.
		 * This shouldn't happen as our buffer is larger than
		 * the message that we expect to receive.
		 */
		nwarn("Could not find newline in entire buffer");
	} else if (*beg == '\0') {
		/* We exhausted all messages that were complete */
		readptr = ctlbuf;
		readsz = CTLBUFSZ - 1;
	} else {
		/*
		 * We copy remaining data to beginning of buffer
		 * and advance readptr after that.
		 */
		int cp_rem = 0;
		do {
			ctlbuf[cp_rem++] = *beg++;
		} while (*beg != '\0');
		readptr = ctlbuf + cp_rem;
		readsz = CTLBUFSZ - 1 - cp_rem;
	}

	return G_SOURCE_CONTINUE;
}

/*
 * resize_winsz resizes the pty window size.
 */
static void resize_winsz(int height, int width)
{
	struct winsize ws;
	ws.ws_row = height;
	ws.ws_col = width;

	int ret = ioctl(masterfd_stdout, TIOCSWINSZ, &ws);
	if (ret == -1)
		pwarn("Failed to set process pty terminal size");
}


void setup_console_fifo()
{
	setup_fifo(&winsz_fd_r, &winsz_fd_w, "winsz", "window resize control fifo");
	ninfof("winsz read side: %d, winsz write side: %d", winsz_fd_r, winsz_fd_r);
}

int setup_terminal_control_fifo()
{
	/*
	 * Open a dummy writer to prevent getting flood of POLLHUPs when
	 * last writer closes.
	 */
	int dummyfd = -1;
	setup_fifo(&terminal_ctrl_fd, &dummyfd, "ctl", "terminal control fifo");
	ninfof("terminal_ctrl_fd: %d", terminal_ctrl_fd);
	g_unix_fd_add(terminal_ctrl_fd, G_IO_IN, ctrl_cb, NULL);

	return dummyfd;
}

static void setup_fifo(int *fifo_r, int *fifo_w, char *filename, char *error_var_name)
{
	_cleanup_free_ char *fifo_path = g_build_filename(opt_bundle_path, filename, NULL);

	if (!fifo_r || !fifo_w)
		pexitf("setup fifo was passed a NULL pointer");

	if (mkfifo(fifo_path, 0666) == -1)
		pexitf("Failed to mkfifo at %s", fifo_path);

	if ((*fifo_r = open(fifo_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)) == -1)
		pexitf("Failed to open %s read half", error_var_name);

	if ((*fifo_w = open(fifo_path, O_WRONLY | O_CLOEXEC)) == -1)
		pexitf("Failed to open %s write half", error_var_name);
}
