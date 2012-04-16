/*****
*
* Copyright (C) 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoannv@gmail.com>
*
* This file is part of the Requiem-Logeater program.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "ev.h"

#include <librequiem/requiem.h>
#include <librequiem/requiem-log.h>
#include <librequiem/requiem-timer.h>
#include <librequiem/daemonize.h>

#include "config.h"

#include "regex.h"
#include "requiem-logeater.h"
#include "common.h"

#include "logeater-options.h"
#include "udp-server.h"
#include "file-server.h"
#include "log-entry.h"
#include "log-plugins.h"
#include "logeater-alert.h"

#ifndef MAX
 #define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

struct regex_data {
        logeater_log_source_t *log_source;
        logeater_log_entry_t *log_entry;
};


void _logeater_handle_signal_if_needed(void);


static struct timeval start;
extern logeater_config_t config;
static char **global_argv;
static requiem_option_t *logeater_root_optlist;
static volatile sig_atomic_t got_signal = 0;
static ev_async ev_interrupt;



static void print_stats(const char *prefix, struct timeval *end)
{
        double tdiv;

        tdiv = (end->tv_sec + (double) end->tv_usec / 1000000) - (start.tv_sec + (double) start.tv_usec / 1000000);

        requiem_log(REQUIEM_LOG_WARN, "%s%lu line processed in %.2f seconds (%.2f EPS), %lu alert emited.\n",
                    prefix, config.line_processed, tdiv, config.line_processed / tdiv, config.alert_count);
}


static RETSIGTYPE sig_handler(int signum)
{
        got_signal = signum;
        ev_async_send(EV_DEFAULT_ &ev_interrupt);
}


static void server_close(void)
{
        size_t i;

        for ( i = 0; i < config.udp_nserver; i++ )
                udp_server_close(config.udp_server[i]);
}


#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
static void handle_sigquit(void)
{
        struct timeval end;

        gettimeofday(&end, NULL);
        print_stats("statistics signal received: ", &end);
}



static const char *get_restart_string(void)
{
        int ret;
        size_t i;
        requiem_string_t *buf;

        ret = requiem_string_new(&buf);
        if ( ret < 0 )
                return global_argv[0];

        for ( i = 0; global_argv[i] != NULL; i++ ) {
                if ( ! requiem_string_is_empty(buf) )
                        requiem_string_cat(buf, " ");

                requiem_string_cat(buf, global_argv[i]);
        }

        return requiem_string_get_string(buf);
}


static void handle_sighup(void)
{
        int ret;

        /*
         * Here we go !
         */
        ret = execvp(global_argv[0], global_argv);
        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "error restarting '%s': %s\n", global_argv[0], requiem_strerror(ret));
                return;
        }
}
#endif



void _logeater_handle_signal_if_needed(void)
{
        int signo;

        if ( ! got_signal )
                return;

        signo = got_signal;
        got_signal = 0;

#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        if ( signo == SIGQUIT || signo == SIGUSR1 ) {
                handle_sigquit();
                return;
        }
#endif

        server_close();

        if ( config.logeater_client )
                requiem_client_destroy(config.logeater_client, REQUIEM_CLIENT_EXIT_STATUS_FAILURE);

        requiem_deinit();

#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        if ( signo == SIGHUP ) {
                requiem_log(REQUIEM_LOG_WARN, "signal %d received, restarting (%s).\n", signo, get_restart_string());
                handle_sighup();
        }
#endif

        requiem_log(REQUIEM_LOG_WARN, "signal %d received, terminating requiem-logeater.\n", signo);
        exit(2);
}


static void libev_timer_cb(struct ev_timer *w, int revents)
{
        requiem_timer_wake_up();
}


static void libev_udp_cb(struct ev_io *w, int revents)
{
        udp_server_process_event(w->data);
}


static void libev_interrupt_cb(EV_P_ ev_async *w, int revents)
{
        _logeater_handle_signal_if_needed();
}


static void regex_match_cb(void *plugin, void *data)
{
        struct regex_data *rdata = data;
        log_plugin_run(plugin, rdata->log_source, rdata->log_entry);
}



/**
 * logeater_dispatch_log:
 * @list: List of regex.
 * @str: The log.
 * @from: Where does this log come from.
 *
 * This function is to be called by module reading log devices.
 * It will take appropriate action.
 */
void logeater_dispatch_log(logeater_log_source_t *ls, const char *str, size_t size)
{
        int ret;
        char *out;
        struct regex_data rdata;
        logeater_log_entry_t *log_entry;

        ret = logeater_log_source_preprocess_input(ls, str, size, &out, &size);
        if ( ret < 0 )
                return;

        requiem_log_debug(3, "[LOG] %s\n", out);

        log_entry = logeater_log_entry_new();
        if ( ! log_entry )
                return;

        logeater_log_entry_set_log(log_entry, ls, out, size);

        rdata.log_source = ls;
        rdata.log_entry = log_entry;

        regex_exec(logeater_log_source_get_regex_list(ls), &regex_match_cb, &rdata,
                   logeater_log_entry_get_message(log_entry), logeater_log_entry_get_message_len(log_entry));

        logeater_log_entry_destroy(log_entry);
        config.line_processed++;
}


static void wait_for_event(void)
{
        size_t i;
        int udp_event_fd;
        ev_io events[config.udp_nserver];

        ev_async_init(&ev_interrupt, libev_interrupt_cb);
        ev_async_start(&ev_interrupt);

        for ( i = 0; i < config.udp_nserver; i++ ) {
                udp_event_fd = udp_server_get_event_fd(config.udp_server[i]);

                ev_io_init(&events[i], libev_udp_cb, udp_event_fd, EV_READ);
                events[i].data = config.udp_server[i];

                ev_io_start(&events[i]);
        }

        ev_loop(0);
}



int main(int argc, char **argv)
{
        int ret;
        ev_timer evt;
        struct timeval end;
        struct sigaction action;

        /*
         * Initialize libev.
         */
        ev_default_loop(EVFLAG_AUTO);

        /*
         * make sure we ignore sighup until acceptable.
         */
#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        action.sa_flags = 0;
        action.sa_handler = SIG_IGN;
        sigemptyset(&action.sa_mask);
        sigaction(SIGHUP, &action, NULL);
#endif

        memset(&start, 0, sizeof(start));
        memset(&end, 0, sizeof(end));

        requiem_init(&argc, argv);
        global_argv = argv;

        REQUIEM_PLUGIN_SET_PRELOADED_SYMBOLS();

        ret = requiem_option_new_root(&logeater_root_optlist);
        if ( ret < 0 )
                return ret;

        ret = log_plugins_init(LOG_PLUGIN_DIR, logeater_root_optlist);
        if (ret < 0)
                return ret;

        requiem_log_debug(1, "Initialized %d logs plugins.\n", ret);

        ret = logeater_options_init(logeater_root_optlist, argc, argv);
        if ( ret < 0 )
                exit(1);

        /*
         * setup signal handling
         */
        action.sa_flags = 0;
        sigemptyset(&action.sa_mask);
        action.sa_handler = sig_handler;

#ifdef SA_INTERRUPT
        action.sa_flags |= SA_INTERRUPT;
#endif

        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGABRT, &action, NULL);
#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        sigaction(SIGUSR1, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
#endif

        ret = file_server_start_monitoring();
        if ( ret < 0 && ! config.udp_nserver ) {
                requiem_log(REQUIEM_LOG_WARN, "No file or UDP server available for monitoring: terminating.\n");
                return -1;
        }

        if ( config.daemon_mode ) {
                requiem_daemonize(config.pidfile);
                if ( config.pidfile )
                        free(config.pidfile);

                ev_default_fork();
        }

        ev_timer_init(&evt, libev_timer_cb, 1, 1);
        ev_timer_start(&evt);

        /*
         * Whether we are using batch-mode or file notification, we need
         * to process the currently un-processed entry.
         */
        gettimeofday(&start, NULL);

        do {
                ret = file_server_read_once();
                requiem_timer_wake_up();
        } while ( ret > 0 );

        /*
         * if either FAM or UDP server is enabled, we use polling to know
         * if there are data available for reading. if batch_mode is set,
         * then we revert to reading every data at once.
         */
        if ( ! config.batch_mode )
                wait_for_event();
        else {
                gettimeofday(&end, NULL);

                /*
                 * only call requiem_client_destroy in case we are running in batch
                 * mode, causing an heartbeat to be sent to notice of a normal exit.
                 */
                if ( ! config.dry_run )
                        requiem_client_destroy(config.logeater_client, REQUIEM_CLIENT_EXIT_STATUS_SUCCESS);

                print_stats("", &end);
        }

        requiem_deinit();
        return 0;
}
