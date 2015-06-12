	/*
* nsca_handler - A tool for managing data to be sent using NSCA
* Copyright (C) 2014 Pierre Schweitzer <pierre@reactos.org>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "nsca_handler.h"

#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <syslog.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
/* BUG: http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=473595 */
#ifndef S_SPLINT_S
#include <unistd.h>
#endif
#include <poll.h>
#include <errno.h>

#define unreferenced_parameter(p) (void)p
#define soft_assert(e) if (!(e)) internal_assert(__FILE__, __LINE__, #e, 0)
#define hard_assert(e) if (!(e)) internal_assert(__FILE__, __LINE__, #e, 1)

#define NSCA_SEND_CMD "/usr/sbin/send_nsca -H TO_BE_COMPLETED -c /etc/send_nsca.cfg"
#define NSCA_OUTPUT_DIR "/var/lib/icinga/nsca_spool/"
#define MAX_FILE_LENGTH (sizeof(NSCA_OUTPUT_DIR) + NAME_MAX + 1)
#define MAX_SIZE 0x2000 /* This is somehow matching MAX_EXTERNAL_COMMAND_LENGTH */

static void internal_assert(const char * file, unsigned int line, const char * assert_text,
                            char critical) {
    syslog((critical ? LOG_CRIT : LOG_NOTICE),
           "Assertion '%s' failed at line %d in file %s", assert_text, line, file);

    if (critical) {
        syslog(LOG_INFO, "Deamon shutting down.");
        exit(EXIT_FAILURE);
    }
}

static void signal_handler(int signal) {
    unreferenced_parameter(signal);
    syslog(LOG_INFO, "Deamon shutting down.");
    exit(EXIT_SUCCESS);
}

static void handle_file(const char * file_path) {
    FILE * data;
    char buffer[MAX_SIZE];
    size_t len;

    /* Open file */
    data = fopen(file_path, "r");
    if (data == NULL)
    {
        /* Delete the file, the system might be in bad shape */
        unlink(file_path);
        return;
    }

    /* Attempt to lock the file so that no other worker will interfere */
    if (flock(fileno(data), LOCK_EX | LOCK_NB) != 0)
    {
        int saved_errno = errno;

        /* Another work may have locked it, give up! */
        (void)fclose(data);

        if (saved_errno != EWOULDBLOCK)
        {
            /* It's likely not locked by another worker, delete the file */
            unlink(file_path);
        }

        return;
    }

    if (fgets(buffer, MAX_SIZE, data) != buffer)
    {
        /* Delete the file, the system might be in bad shape */
        (void)fclose(data);
        unlink(file_path);
        return;
    }

    /* Close file - this releases exclusive lock */
    soft_assert(fclose(data) == 0);
    /* And unlink */
    soft_assert(unlink(file_path) == 0);

    len = strlen(buffer);
    soft_assert(len != 0);

    /* Now, send the data to NSCA */
    data = popen(NSCA_SEND_CMD, "w");
    if (data == NULL)
    {
        /* Not that cool... We ate data. Shall we recreate the file? */
        return;
    }

    soft_assert(fwrite(buffer, sizeof(char), len, data) == len);

    /* We don't care about NSCA properly sending data */
    (void)pclose(data);
}

static void handle_current_files(void) {
    DIR * nsca_dir_s;

    /* Open the output directory */
    nsca_dir_s = opendir(NSCA_OUTPUT_DIR);
    if (nsca_dir_s == NULL) {
        return;
    }

    /* And browse any single file in it */
    for (;;) {
        pid_t worker;
        struct dirent * dir_entry;

        /* Get a file */
        dir_entry = readdir(nsca_dir_s);
        if (dir_entry == NULL) {
            break;
        }

        /* Fork, we don't care about the rest at that point */
        worker = fork();
        /* Let's assume, for now, that we were just lacking resources
         * at a point, and try to keep on the work...
         */
        soft_assert(worker != -1);

        if (worker == 0)
        {
            char complete_name[MAX_FILE_LENGTH];

            /* Build complete path */
            strncpy(complete_name, NSCA_OUTPUT_DIR, MAX_FILE_LENGTH);
            strncat(complete_name, dir_entry->d_name, MAX_FILE_LENGTH - sizeof(NSCA_OUTPUT_DIR));
            complete_name[MAX_FILE_LENGTH - 1] = '\0';

            /* And handle file */
            handle_file(complete_name);

            exit(EXIT_SUCCESS);
        }

        /* Get to the next file */
    }

    /* That's all! */
    (void)closedir(nsca_dir_s);

    return;
}

int main(int argc, char ** argv) {
    pid_t deamon, initial_work;
    int inotify_fd, nsca_dir_fd;
    struct sigaction sig_handling;

    unreferenced_parameter(argc);
    unreferenced_parameter(argv);

    memset(&sig_handling, 0, sizeof(struct sigaction));
    sig_handling.sa_handler = signal_handler;

    /* Install signals handler */
    if (sigaction(SIGTERM, &sig_handling, NULL) < 0) {
        fprintf(stderr, "Failed to install signal handler\n");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGINT, &sig_handling, NULL) < 0) {
        fprintf(stderr, "Failed to install signal handler\n");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGQUIT, &sig_handling, NULL) < 0) {
        fprintf(stderr, "Failed to install signal handler\n");
        exit(EXIT_FAILURE);
    }

    /* Prevent zombies */
    sig_handling.sa_handler = NULL;
    sig_handling.sa_flags = SA_NOCLDWAIT;
    if (sigaction(SIGCHLD, &sig_handling, NULL) < 0) {
        fprintf(stderr, "Failed to install signal handler\n");
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "Daemon starting up");
    setlogmask(LOG_MASK(LOG_INFO) | LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_NOTICE));
    openlog("nsca_handler", LOG_CONS, LOG_USER);

    /* Start deamon */
    deamon = fork();
    if (deamon < 0) {
        exit(EXIT_FAILURE);
    }

    if (deamon > 0) {
        exit(EXIT_SUCCESS);
    }

    /* Quit session */
    (void)umask(0);
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }

    /* Go back to root */
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    /* Get rid of useless descriptors */
    (void)close(STDIN_FILENO);
    (void)close(STDOUT_FILENO);
    (void)close(STDERR_FILENO);

    /* Fork again to handle files that would already exist */
    initial_work = fork();
    /* In case we cannot fork(), that's not that a major issue
     * It just means that we cannot handle initial files
     * Let's try to focus on the new ones, that's mandatory
     */
    soft_assert(initial_work != -1);

    if (initial_work == 0)
    {
        handle_current_files();
        exit(EXIT_SUCCESS);
    }

    /* Initialize inotify to watch the NSCA output directory */
    inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd < 0) {
        exit(EXIT_FAILURE);
    }

    /* We'll watch files created in the directory */
    nsca_dir_fd = inotify_add_watch(inotify_fd, NSCA_OUTPUT_DIR, IN_CREATE);
    if (nsca_dir_fd < 0) {
        (void)close(inotify_fd);
        exit(EXIT_FAILURE);
    }

    for (;;) {
        pid_t worker;
        int timeout = -1, event;
        struct pollfd fds[1];
        char buffer[sizeof(struct inotify_event) + NAME_MAX + 1];

        fds[0].fd = inotify_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        event = poll(fds, 1, timeout);
        if (event < 0) {
            /* Did one of our children died? Then keep going */
            if (errno == EINTR) {
                continue;
            }

            break;
        } else if (event == 0) {
            /* Shouldn't happen */
            continue;
        }

        /* We have an event, a file was created */
        soft_assert(read(inotify_fd, buffer, sizeof(buffer)) >= (ssize_t)sizeof(struct inotify_event));

        /* Fork, we don't care about the rest at that point */
        worker = fork();
        /* Let's assume, for now, that we were just lacking resources
         * at a point, and try to keep on the work...
         */
        soft_assert(worker != -1);

        if (worker == 0)
        {
            /* Browse everything */
            handle_current_files();

            exit(EXIT_SUCCESS);
        }

        /* Get to the next file */
    }

    (void)close(nsca_dir_fd);
    (void)close(inotify_fd);
    exit(EXIT_SUCCESS);
}
