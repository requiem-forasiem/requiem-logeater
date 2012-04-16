/*****
*
* Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _Logeater_PCONFIG_H
#define _Logeater_PCONFIG_H

#include <librequiem/requiem-inttypes.h>
#include "regex.h"
#include "udp-server.h"

int logeater_options_init(requiem_option_t *logeater_optlist, int argc, char **argv);

typedef struct {
        char *pidfile;
        char *logfile_prefix_regex;
        char *logfile_ts_format;
        const char *system_charset;
        char *charset;
        int charset_ref;

        requiem_client_t *logeater_client;

        requiem_bool_t batch_mode;
        requiem_bool_t dry_run;
        requiem_bool_t ignore_metadata;
        requiem_bool_t no_resolve;
        requiem_bool_t daemon_mode;

        size_t udp_nserver;
        udp_server_t **udp_server;

        requiem_io_t *text_output_fd;
        unsigned long alert_count;
        unsigned long line_processed;

        int warning_limit;
        uid_t wanted_uid;
        gid_t wanted_gid;
} logeater_config_t;

#endif /* _Logeater_PCONFIG_H */
