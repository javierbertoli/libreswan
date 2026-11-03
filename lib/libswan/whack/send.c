/*
 * Libreswan whack functions to communicate with pluto (whack.c)
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2011 Mattias Walström <lazzer@vmlinux.org>
 * Copyright (C) 2012-2017 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <unistd.h>		/* for write() */
#include <errno.h>
#include <stdlib.h>		/* for exit() */
#include <sys/un.h>		/* struct sockaddr_un;! */
#include <fcntl.h>		/* for open() */
#include <signal.h>		/* for sigaction() */
#include <termios.h>		/* for tcsetattr() */

#include "whack.h"
#include "lsw_socket.h"
#include "lswlog.h"

static int whack_get_value(char *buf, size_t bufsize)
{
	int len;
	int try;

	fflush(stdout);

	try = 3;
	len = 0;
	while (try > 0 && len == 0) {
		fprintf(stderr, "Enter username:   ");

		memset(buf, 0, bufsize);

		if (fgets(buf, bufsize, stdin) != buf) {
			if (errno == 0) {
				fprintf(stderr,
					"Cannot read username from standard in\n");
				exit(RC_WHACK_PROBLEM);
			} else {
				perror("fgets value");
				exit(RC_WHACK_PROBLEM);
			}
		}

		/* send the value to pluto, including \0, but fgets adds \n */
		len = strlen(buf);
		if (len == 0)
			fprintf(stderr, "answer was empty, retry\n");

		try--;
	}

	if (len ==  0)
		exit(RC_WHACK_PROBLEM);

	return len;
}

/*
 * Get password from user.  Truncate it to fit in buf.
 *
 * getpass(3) is obsolete and, with glibc, disables ISIG so that
 * Ctrl-C can't interrupt the prompt.  Instead turn off echo by hand,
 * leaving Ctrl-C working; restore the terminal before dying.  Ctrl-Z
 * is disabled while prompting (stopping whack would leave pluto
 * blocked waiting for the answer).
 */

static int secret_tty_fd = -1;
static struct termios secret_tty_saved;

static void secret_tty_restore_and_die(int sig)
{
	if (secret_tty_fd >= 0) {
		tcsetattr(secret_tty_fd, TCSAFLUSH, &secret_tty_saved);
		if (write(secret_tty_fd, "\n", 1) < 0) {
			/* ignore */
		}
	}
	/* SA_RESETHAND|SA_NODEFER: default action, delivered now */
	raise(sig);
}

static const int secret_signals[] = { SIGINT, SIGQUIT, SIGTERM, SIGHUP, };

static size_t whack_get_secret(const char *prompt, char *buf, size_t bufsize)
{
	fflush(stdout);
	passert(bufsize > 0);	/* room for terminal NUL */

	/* like getpass(3), prefer the terminal; else stdin/stderr */
	int tty = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
	int in = (tty >= 0 ? tty : STDIN_FILENO);
	int out = (tty >= 0 ? tty : STDERR_FILENO);

	if (write(out, prompt, strlen(prompt)) < 0) {
		/* ignore */
	}

	struct termios saved;
	bool noecho = (tcgetattr(in, &saved) == 0);
	struct sigaction old_sa[elemsof(secret_signals)];

	if (noecho) {
		secret_tty_saved = saved;
		secret_tty_fd = in;
		struct sigaction sa = {
			.sa_handler = secret_tty_restore_and_die,
			.sa_flags = SA_RESETHAND | SA_NODEFER,
		};
		sigemptyset(&sa.sa_mask);
		for (unsigned i = 0; i < elemsof(secret_signals); i++) {
			sigaction(secret_signals[i], NULL, &old_sa[i]);
			/* leave ignored signals, e.g., nohup, ignored */
			if (old_sa[i].sa_handler != SIG_IGN) {
				sigaction(secret_signals[i], &sa, NULL);
			}
		}
		struct termios t = saved;
		t.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSUSP
		t.c_cc[VSUSP] = _POSIX_VDISABLE;
#endif
		tcsetattr(in, TCSAFLUSH, &t);
	}

	size_t len = 0;
	for (;;) {
		char c;
		ssize_t r = read(in, &c, 1);
		if (r < 0 && errno == EINTR) {
			continue;
		}
		if (r < 0) {
			int e = errno;
			if (noecho) {
				tcsetattr(in, TCSAFLUSH, &saved);
			}
			errno = e;
			perror("read secret");
			exit(RC_WHACK_PROBLEM);
		}
		if (r == 0 || c == '\n') {
			break;
		}
		if (len < bufsize - 1) {
			buf[len++] = c;
		}
	}
	buf[len] = '\0';	/* force NUL termination */

	if (noecho) {
		tcsetattr(in, TCSAFLUSH, &saved);
		secret_tty_fd = -1;
		for (unsigned i = 0; i < elemsof(secret_signals); i++) {
			sigaction(secret_signals[i], &old_sa[i], NULL);
		}
		if (write(out, "\n", 1) < 0) {
			/* ignore */
		}
	}

	if (tty >= 0) {
		close(tty);
	}

	return len + 1;		/* includes NUL */
}

static void whack_send_reply(int sock, const char *buf, ssize_t len, struct logger *logger)
{
	/* send the secret to pluto */
	if (write(sock, buf, len) != len) {
		/* not fatal() which should be internal to pluto() */
		llog_errno(ERROR_STREAM, logger, errno, "write() failed: ");
		exit(RC_WHACK_PROBLEM);
	}
}

static int whack_read_reply(int sock,
			    char xauthusername[MAX_XAUTH_USERNAME_LEN],
			    char xauthpass[XAUTH_MAX_PASS_LENGTH],
			    char xauthotp[XAUTH_MAX_PASS_LENGTH],
			    int usernamelen,
			    int xauthpasslen,
			    int xauthotplen,
			    struct logger *logger,
			    enum whack_noise noise)
{
	char buf[4097]; /* arbitrary limit on log line length */
	char *be = buf;
	int exit_status = 0;

	for (;; ) {
		char *ls = buf;
		ssize_t rl = read(sock, be, (buf + sizeof(buf) - 1) - be);

		if (rl < 0) {
			llog_errno(ERROR_STREAM, logger, errno, "read() failed: ");
			exit(RC_WHACK_PROBLEM);
		}

		if (rl == 0) {
			if (be != buf) {
				llog(ERROR_STREAM, logger,
				     "last line from pluto too long or unterminated");
			}
			break;
		}

		be += rl;
		*be = '\0';

		for (;; ) {

			char *le = strchr(ls, '\n');
			if (le == NULL) {
				/* move last, partial line to start of buffer */
				memmove(buf, ls, be - ls);
				be -= ls - buf;
				break;
			}

			le++;	/* include NL in line */

			/*
			 * figure out prefix number and how it should
			 * affect our exit status and printing
			 */
			char *lpe = NULL; /* line-prefix-end */
			unsigned long s = strtoul(ls, &lpe, 10);
			if (lpe == ls || *lpe != ' ') {
				/* includes embedded NL, see above */
				llog(ERROR_STREAM, logger,
				     "log line missing NNN prefix: %*s", (int)(le - ls), ls);
				exit(RC_WHACK_PROBLEM);
			}

			ls = lpe + 1; /* skip NNN_ */

			/*
			 * Normally the message is either:
			 *
			 *   000 optional-text\n
			 *   NNN \n
			 *
			 * where, with the latter, the newline should
			 * be suppressed.
			 *
			 * However, when there's an internal error,
			 * the message:
			 *
			 *   NNN error-message\n
			 */
			if ((s == 0 && noise >= NOISY_WHACK) ||
			    (s != 0 && (le - ls) > 1/*more-than-just-nl*/)) {
				if (write(STDOUT_FILENO, ls, le - ls) == -1) {
					int e = errno;
					llog_errno(RC_LOG, logger, e, "write() failed, and ignored");
				}
			}

			/*
			 * figure out prefix number and how it should affect
			 * our exit status
			 */

			switch (s) {

			case RC_ENTERSECRET:
				if (xauthpass == NULL) {
					llog(ERROR_STREAM, logger,
					     "unexpected request for xauth password");
					exit(RC_WHACK_PROBLEM);
				}
				if (xauthpasslen == 0) {
					xauthpasslen =
						whack_get_secret("Enter passphrase: ",
								 xauthpass,
								 XAUTH_MAX_PASS_LENGTH);
				}
				if (xauthpasslen > XAUTH_MAX_PASS_LENGTH) {
					/*
					 * for input >= 128,
					 * xauthpasslen would be 129
					 */
					xauthpasslen =
						XAUTH_MAX_PASS_LENGTH;
					llog(ERROR_STREAM, logger,
					     "xauth password cannot be >= %d chars",
					     XAUTH_MAX_PASS_LENGTH);
				}
				whack_send_reply(sock, xauthpass, xauthpasslen, logger);
				break;

			case RC_ENTEROTP:
			{
				if (xauthotp == NULL) {
					llog(ERROR_STREAM, logger,
					     "unexpected request for xauth OTP");
					exit(RC_WHACK_PROBLEM);
				}
				/*
				 * A one-time password is never the
				 * --xauthpass password.  Use
				 * --xauthotp once, then prompt; it
				 * is never cached.
				 */
				if (xauthotplen > 0) {
					whack_send_reply(sock, xauthotp, xauthotplen, logger);
					memset(xauthotp, 0, XAUTH_MAX_PASS_LENGTH);
					xauthotplen = 0;
					break;
				}
				char otp[XAUTH_MAX_PASS_LENGTH];
				size_t otplen = whack_get_secret("Enter OTP: ",
								 otp, sizeof(otp));
				whack_send_reply(sock, otp, otplen, logger);
				memset(otp, 0, sizeof(otp));
				break;
			}

			case RC_USERPROMPT:
				if (xauthusername == NULL) {
					llog(ERROR_STREAM, logger,
					     "unexpected request for xauth username");
					exit(RC_WHACK_PROBLEM);
				}
				if (usernamelen == 0) {
					usernamelen = whack_get_value(xauthusername,
								      MAX_XAUTH_USERNAME_LEN);
				}
				if (usernamelen > MAX_XAUTH_USERNAME_LEN) {
					/*
					 * for input >= 128,
					 * useramelen would be 129
					 */
					usernamelen = MAX_XAUTH_USERNAME_LEN;
					llog(ERROR_STREAM, logger,
					     "username cannot be >= %d chars",
					     MAX_XAUTH_USERNAME_LEN);
				}
				whack_send_reply(sock, xauthusername, usernamelen, logger);

				break;

			default:
				/*
				 * Only RC_ codes between
				 * RC_EXIT_FLOOR (RC_DUPNAME) and
				 * RC_EXIT_ROOF are errors.
				 *
				 * The exit status is sticky so that
				 * incidental logs don't clear or
				 * change it.
				 */
				if (exit_status == 0 && s >= RC_EXIT_FLOOR && s < RC_EXIT_ROOF) {
					exit_status = s;
				}
				break;
			}

			ls = le;
		}
	}
	return exit_status;
}

int whack_send_msg(struct whack_message *msg, const char *ctlsocket,
		   char xauthusername[MAX_XAUTH_USERNAME_LEN],
		   char xauthpass[XAUTH_MAX_PASS_LENGTH],
		   char xauthotp[XAUTH_MAX_PASS_LENGTH],
		   int usernamelen, int xauthpasslen, int xauthotplen,
		   struct logger *logger,
		   enum whack_noise noise)
{
	struct sockaddr_un ctl_addr = {
		.sun_family = AF_UNIX,
		.sun_path  = DEFAULT_CTL_SOCKET,
#ifdef USE_SOCKADDR_LEN
		.sun_len = sizeof(struct sockaddr_un),
#endif
	};

	/* copy socket location */

	fill_and_terminate(ctl_addr.sun_path, ctlsocket, sizeof(ctl_addr.sun_path));

	/*  Pack strings */

	struct whackpacker wp = {
		.msg = msg,
		.str_next = (unsigned char *)msg->string,
		.str_roof = (unsigned char *)&msg->string[sizeof(msg->string)],
	};

	err_t ugh = pack_whack_msg(&wp, logger);

	if (ugh != NULL) {
		llog(ERROR_STREAM, logger, "send_wack_msg(): can't pack strings: %s", ugh);
		return -1;
	}

	ssize_t len = wp.str_next - (unsigned char *)msg;

	/* Connect to pluto ctl */

	if (access(ctl_addr.sun_path, R_OK | W_OK) < 0) {
		int e = errno;

		switch (e) {
		case EACCES:
			llog_errno(ERROR_STREAM, logger, e,
				   "no right to communicate with pluto (access(\"%s\")): ",
				   ctl_addr.sun_path);
			break;
		case ENOENT:
			llog_errno(ERROR_STREAM, logger, e,
				   "Pluto is not running (no \"%s\"): ",
				   ctl_addr.sun_path);
			break;
		default:
			llog_errno(ERROR_STREAM, logger, e, "access(\"%s\") failed: ",
				   ctl_addr.sun_path);
			break;
		}
		exit(RC_WHACK_PROBLEM);
	}

	int sock = cloexec_socket(PLUTO_CTL_DOMAIN, PLUTO_CTL_TYPE, 0);
	if (sock < 0) {
		llog_errno(ERROR_STREAM, logger, errno, "socket() failed: ");
		exit(RC_WHACK_PROBLEM);
	}

	if (connect(sock, (struct sockaddr *)&ctl_addr,
		    offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0) {
		llog_errno(ERROR_STREAM, logger, errno, "connect(pluto_ctl) failed: ");
		close(sock);
		exit(RC_WHACK_PROBLEM);
	}

	/* Send message */
#if 0
	const ssize_t min = 856;
	if (len < min) {
		llog(ERROR_STREAM, logger, "bumping up buffer from %td to %td",
		     len, min);
		len = min;	/* this just writes pat of the string
				 * buffer */
	}
#endif


	if (write(sock, msg, len) != len) {
		llog_errno(ERROR_STREAM, logger, errno, "write(pluto_ctl) failed: ");
		close(sock);
		exit(RC_WHACK_PROBLEM);
	}

	/* read reply (possibly send further messages) */
	int ret = whack_read_reply(sock, xauthusername, xauthpass, xauthotp,
				   usernamelen, xauthpasslen, xauthotplen,
				   logger, noise);
	close(sock);

	return ret;
}
