/*****
*
* Copyright (C) 1998, 1999, 2000, 2001, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <locale.h>
#include <langinfo.h>
#include <glob.h>

#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
# include <grp.h>
# include <pwd.h>
#endif

#include <librequiem/requiem.h>
#include <librequiem/requiem-log.h>
#include <librequiem/daemonize.h>

#include "requiem-logeater.h"
#include "logeater-options.h"
#include "log-source.h"
#include "log-entry.h"
#include "logeater-alert.h"
#include "file-server.h"
#include "udp-server.h"
#include "logeater-charset.h"

#define DEFAULT_UDP_SERVER_PORT 514


logeater_config_t config;
static const char *config_file = REQUIEM_Logeater_CONF;


#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
static int drop_privilege(void)
{
        int ret;

        if ( config.wanted_gid != getgid() ) {
                ret = setgid(config.wanted_gid);
                if ( ret < 0 ) {
                        requiem_log(REQUIEM_LOG_ERR, "change to GID %d failed: %s.\n",
                                    (int) config.wanted_gid, strerror(errno));
                        return ret;
                }

                ret = setgroups(1, &config.wanted_gid);
                if ( ret < 0 ) {
                        requiem_log(REQUIEM_LOG_ERR, "removal of ancillary groups failed: %s.\n", strerror(errno));
                        return ret;
                }
        }


        if ( config.wanted_uid != getuid() ) {
                ret = setuid(config.wanted_uid);
                if ( ret < 0 ) {
                        requiem_log(REQUIEM_LOG_ERR, "change to UID %d failed: %s.\n",
                                    (int) config.wanted_uid, strerror(errno));
                        return ret;
                }
        }

        return 0;
}
#endif


static int set_conf_file(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        config_file = strdup(optarg);
        return 0;
}


static int print_version(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        printf("requiem-logeater-%s\n", VERSION);
        exit(0);
}



static int print_help(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        requiem_option_print(NULL, REQUIEM_OPTION_TYPE_CLI, 25, stderr);
        return requiem_error(REQUIEM_ERROR_EOF);
}



static int set_batch_mode(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        config.batch_mode = TRUE;
        return 0;
}



static char *const2char(const char *val)
{
        union {
                const char *ro;
                char *rw;
        } uval;

        uval.ro = val;

        return uval.rw;
}


static int set_metadata_flags(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        unsigned int i;
        file_server_metadata_flags_t flags = 0;
        char *name, *value = const2char(arg);
        struct {
                const char *name;
                file_server_metadata_flags_t flags;
        } tbl[] = {
                { "nowrite", FILE_SERVER_METADATA_FLAGS_NO_WRITE },
                { "last", FILE_SERVER_METADATA_FLAGS_LAST        },
                { "head", FILE_SERVER_METADATA_FLAGS_HEAD        },
                { "tail", FILE_SERVER_METADATA_FLAGS_TAIL        }
        };

        while ( (name = strsep(&value, " ,")) ) {

                for ( i = 0; i < sizeof(tbl) / sizeof(*tbl); i++ ) {
                        if ( ! strstr(name, tbl[i].name) )
                                continue;

                        if ( tbl[i].flags != FILE_SERVER_METADATA_FLAGS_NO_WRITE &&
                             flags & (~FILE_SERVER_METADATA_FLAGS_NO_WRITE) ) {
                                requiem_log(REQUIEM_LOG_ERR, "attribute '%s' is incompatible with previously specified attribute.\n", tbl[i].name);
                                return -1;
                        }

                        flags |= tbl[i].flags;
                }
        }

        file_server_set_metadata_flags(flags);
        return 0;
}


static int set_no_resolve(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        config.no_resolve = TRUE;
        return 0;
}


static int set_rotation_time_offset(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        char *endptr;
        unsigned long int off;

        off = strtoul(optarg, &endptr, 10);
        if ( *endptr != '\0' ) {
                requiem_string_sprintf(err, "Invalid max rotation time offset specified: %s", optarg);
                return -1;
        }

        file_server_set_max_rotation_time_offset(off);
        return 0;
}



static int get_rotation_time_offset(requiem_option_t *opt, requiem_string_t *out, void *context)
{
        return requiem_string_sprintf(out, "%jd", (intmax_t) file_server_get_max_rotation_time_offset());
}


static int set_rotation_size_offset(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        char *eptr = NULL;
        unsigned long long int value;

        value = strtoull(arg, &eptr, 10);
        if ( value == ULLONG_MAX || eptr == arg ) {
                requiem_log(REQUIEM_LOG_ERR, "Invalid buffer size specified: '%s'.\n", arg);
                return -1;
        }

        if ( *eptr == 'K' || *eptr == 'k' )
                value = value * 1024;

        else if ( *eptr == 'M' || *eptr == 'm' )
                value = value * 1024 * 1024;

        else if ( *eptr == 'G' || *eptr == 'g' )
                value = value * 1024 * 1024 * 1024;

        else if ( eptr != arg ) {
                requiem_string_sprintf(err, "Invalid max rotation size offset specified: %s.", arg);
                return -1;
        }

        file_server_set_max_rotation_size_offset((off_t) value);
        return 0;
}



static int get_rotation_size_offset(requiem_option_t *opt, requiem_string_t *out, void *context)
{
        return requiem_string_sprintf(out, "%jd", (intmax_t) file_server_get_max_rotation_size_offset());
}


static int set_quiet_mode(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        requiem_log_set_flags(requiem_log_get_flags() | REQUIEM_LOG_FLAGS_QUIET);
        return 0;
}


static int set_debug_mode(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        int level = (optarg) ? atoi(optarg) : REQUIEM_LOG_DEBUG;
        requiem_log_set_debug_level(level);
        return 0;
}


static int set_daemon_mode(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        requiem_log_set_flags(requiem_log_get_flags()|REQUIEM_LOG_FLAGS_QUIET|REQUIEM_LOG_FLAGS_SYSLOG);

        config.daemon_mode = TRUE;
        return 0;
}


static int set_pidfile(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        config.pidfile = strdup(arg);
        if ( ! config.pidfile )
                return requiem_error_from_errno(errno);

        return 0;
}

static int set_logfile_prefix_regex(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        return logeater_log_format_set_prefix_regex(context, arg);
}



static int set_logfile_ts_format(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        return logeater_log_format_set_ts_fmt(context, arg);
}



static int set_dry_run(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        config.dry_run = TRUE;

        return 0;
}



static int set_text_output(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        int ret;
        FILE *fd;

        ret = requiem_io_new(&(config.text_output_fd));
        if ( ret < 0 )
                return ret;

        if ( ! arg || strcmp(arg, "-") == 0 ) {
                requiem_io_set_file_io(config.text_output_fd, stdout);
                return 0;
        }

        fd = fopen(arg, "w");
        if ( ! fd ) {
                requiem_log(REQUIEM_LOG_ERR, "could not open %s for writing.\n", arg);
                requiem_io_destroy(config.text_output_fd);
                return -1;
        }

        requiem_io_set_file_io(config.text_output_fd, fd);

        return 0;
}


static int glob_errfunc_cb(const char *epath, int eerrno)
{
        requiem_log(REQUIEM_LOG_WARN, "error with '%s': %s.\n", epath, strerror(eerrno));
        return 0;
}


static requiem_bool_t isglob(const char *pattern)
{
        unsigned int i;
        const char *ptr;
        char chlist[] = { '*', '?', '[', '~' };

        for ( i = 0; i < sizeof(chlist) / sizeof(*chlist); i++ ) {
                ptr = strchr(pattern, chlist[i]);
                if ( ! ptr )
                        continue;

                if ( ptr == pattern || *(ptr - 1) != '\\' )
                        return TRUE;
        }

        return FALSE;
}


static const char *guess_charset(const char *filename)
{
        size_t fret;
        FILE *fd;
        int ret, confidence;
        char buf[1024*1024];
        const char *charset = NULL;

        fd = fopen(filename, "r");
        if ( ! fd )
                return NULL;

        fret = fread(buf, 1, sizeof(buf), fd);
        fclose(fd);

        ret = logeater_charset_detect(buf, fret, &charset, &confidence);
        if ( ret >= 0 && confidence >= 80 ) {
                requiem_log(REQUIEM_LOG_DEBUG, "%s: using detected '%s' charset with %d%% confidence.\n", filename, charset, confidence);
        } else {
                requiem_log(REQUIEM_LOG_DEBUG, "%s: using system '%s' over detected '%s' charset with %d%% confidence.\n", filename, config.system_charset, charset, confidence);
                charset = config.system_charset;
        }

        return charset;
}

static int add_file(void *context, const char *filename)
{
        int ret;
        const char *charset;
        logeater_log_source_t *ls;

        if ( ! config.charset ) {
                charset = guess_charset(filename);
        } else {
                config.charset_ref++;
                charset = config.charset;
                requiem_log(REQUIEM_LOG_DEBUG, "%s: using charset '%s' specified by user configuration.\n", filename, charset);
        }

        ret = logeater_log_source_new(&ls, context, filename, charset);
        if ( ret < 0 )
                return -1;

        else if ( ret == 1 )
                return 0;

        return file_server_monitor_file(ls);
}


static int get_file_from_pattern(void *context, const char *pattern)
{
        int ret;
        size_t i;
        glob_t gl;

        ret = glob(pattern, GLOB_TILDE, glob_errfunc_cb, &gl);
        if ( ret != 0 ) {
                if ( ret == GLOB_NOMATCH )
                        requiem_log(REQUIEM_LOG_WARN, "%s: not found, no monitoring will occur.\n", pattern);
                else
                        requiem_log(REQUIEM_LOG_ERR, "%s glob failed: %s.\n", pattern, strerror(errno));

                return ret;
        }

        for ( i = 0; i < gl.gl_pathc; i++ ) {
                ret = add_file(context, gl.gl_pathv[i]);
                if ( ret < 0 )
                        break;
        }

        globfree(&gl);

        return ret;
}


static int set_charset(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        if ( config.charset )
                free(config.charset);

        config.charset_ref = 0;

        config.charset = strdup(arg);
        if ( ! config.charset )
                return -1;

        return 0;
}


static int set_file(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        int ret;

        config.charset_ref++;

        if ( strcmp(arg, "-") == 0 )
                return add_file(context, arg);

        else if ( ! isglob(arg) )
                return add_file(context, arg);

        else {
                ret = get_file_from_pattern(context, arg);
                if ( ret < 0 )
                        return 0; /* ignore error */
        }

        return 0;
}



static int add_server(logeater_log_source_t *ls, const char *addr, unsigned int port)
{
        config.udp_nserver++;

        config.udp_server = realloc(config.udp_server, sizeof(*config.udp_server) * config.udp_nserver);
        if ( ! config.udp_server )
                return -1;

        config.udp_server[config.udp_nserver - 1] = udp_server_new(ls, addr, port);
        if ( ! config.udp_server[config.udp_nserver - 1] )
                return -1;

        return 0;
}



static int set_udp_server(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        int ret;
        logeater_log_source_t *ls;
        unsigned int port = 0;
        char *addr, source[512];

        if ( arg && *arg ) {
                ret = requiem_parse_address(arg, &addr, &port);
                if ( ret < 0 )
                        return ret;

                port = port ? port : DEFAULT_UDP_SERVER_PORT;
        } else {
                addr = strdup("0.0.0.0");
                port = DEFAULT_UDP_SERVER_PORT;
        }

        snprintf(source, sizeof(source), "%s:%u/udp", addr, port);

        ret = logeater_log_source_new(&ls, context, source, config.charset ? config.charset : NULL);
        if ( ret < 0 || ret == 1 ) {
                free(addr);
                return ret;
        }

        ret = add_server(ls, addr, port);
        free(addr);

        if ( ret < 0 )
                return -1;

        requiem_log(REQUIEM_LOG_INFO, "Listening for syslog message on %s.\n", source);

        return 0;
}



static int set_warning_limit(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        char *endptr;

        config.warning_limit = strtol(arg, &endptr, 10);
        if ( *endptr != '\0' || config.warning_limit < -1 ) {
                requiem_string_sprintf(err, "Invalid warning limit: %s", arg);
                return -1;
        }

        return 0;
}


static int set_format(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        logeater_log_format_t *format;
        requiem_option_context_t *octx;

        if ( config.charset ) {
                if ( config.charset_ref == 0 ) {
                        requiem_log(REQUIEM_LOG_ERR, "'charset=%s' is defined after any 'file' definition.\n", config.charset);
                        return -1;
                }

                free(config.charset);
                config.charset = NULL;
                config.charset_ref = 0;
        }

        format = logeater_log_format_new(arg);
        if ( ! format )
                return -1;

        return requiem_option_new_context(opt, &octx, arg, format);
}


static int set_idmef_alter_force(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        return logeater_log_format_set_idmef(context, arg, TRUE);
}


static int set_idmef_alter(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        return logeater_log_format_set_idmef(context, arg, FALSE);
}



#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
static int set_user(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        uid_t uid;
        const char *p;
        struct passwd *pw;

        for ( p = optarg; isdigit((int) *p); p++ );

        if ( *p == 0 )
                uid = atoi(optarg);
        else {
                pw = getpwnam(optarg);
                if ( ! pw ) {
                        requiem_log(REQUIEM_LOG_ERR, "could not lookup user '%s'.\n", optarg);
                        return -1;
                }

                uid = pw->pw_uid;
        }

        config.wanted_uid = uid;

        return 0;
}


static int set_group(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        gid_t gid;
        const char *p;
        struct group *grp;

        for ( p = optarg; isdigit((int) *p); p++ );

        if ( *p == 0 )
                gid = atoi(optarg);
        else {
                grp = getgrnam(optarg);
                if ( ! grp ) {
                        requiem_log(REQUIEM_LOG_ERR, "could not lookup group '%s'.\n", optarg);
                        return -1;
                }

                gid = grp->gr_gid;
        }

        config.wanted_gid = gid;

        return 0;
}
#endif


int logeater_options_init(requiem_option_t *ropt, int argc, char **argv)
{
        int ret;
        requiem_option_t *opt;
        requiem_string_t *err;
        int all_hook = REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG|REQUIEM_OPTION_TYPE_WIDE;

        memset(&config, 0, sizeof(config));
        config.warning_limit = -1;

        setlocale(LC_CTYPE, "");
        config.system_charset = nl_langinfo(CODESET);

#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        config.wanted_uid = getuid();
        config.wanted_gid = getgid();
#endif

        requiem_option_add(ropt, &opt, REQUIEM_OPTION_TYPE_CLI, 'h', "help",
                           "Print this help", REQUIEM_OPTION_ARGUMENT_NONE, print_help, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

        requiem_option_add(ropt, &opt, REQUIEM_OPTION_TYPE_CLI, 'v', "version",
                           "Print version number", REQUIEM_OPTION_ARGUMENT_NONE,
                           print_version, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        requiem_option_add(ropt, NULL, REQUIEM_OPTION_TYPE_CFG|REQUIEM_OPTION_TYPE_CLI, 0, "user",
                           "Set the user ID used by requiem-logeater", REQUIEM_OPTION_ARGUMENT_REQUIRED, set_user, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

        requiem_option_add(ropt, &opt, REQUIEM_OPTION_TYPE_CFG|REQUIEM_OPTION_TYPE_CLI, 0, "group",
                           "Set the group ID used by requiem-logeater", REQUIEM_OPTION_ARGUMENT_REQUIRED, set_group, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);
#endif

        requiem_option_add(ropt, &opt, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 'q', "quiet",
                           "Quiet mode", REQUIEM_OPTION_ARGUMENT_NONE, set_quiet_mode, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

        requiem_option_add(ropt, &opt, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 'D', "debug-level",
                           "Debug mode", REQUIEM_OPTION_ARGUMENT_OPTIONAL, set_debug_mode, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

        requiem_option_add(ropt, &opt, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 'd', "daemon",
                           "Run in daemon mode", REQUIEM_OPTION_ARGUMENT_NONE,
                           set_daemon_mode, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_FIRST);

        requiem_option_add(ropt, &opt, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 'P', "pidfile",
                           "Write Requiem Logeater PID to specified file",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_pidfile, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

        requiem_option_add(ropt, NULL, REQUIEM_OPTION_TYPE_CLI, 0, "text-output",
                           "Dump alert to stdout, or to the specified file", REQUIEM_OPTION_ARGUMENT_OPTIONAL,
                           set_text_output, NULL);

        requiem_option_add(ropt, NULL, REQUIEM_OPTION_TYPE_CLI, 0, "dry-run",
                           "No alert emission / Requiem connection", REQUIEM_OPTION_ARGUMENT_NONE,
                           set_dry_run, NULL);

        requiem_option_add(ropt, &opt, REQUIEM_OPTION_TYPE_CLI, 'c', "config",
                           "Configuration file to use", REQUIEM_OPTION_ARGUMENT_REQUIRED,
                           set_conf_file, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

        requiem_option_add(ropt, NULL, all_hook, 0, "max-rotation-time-offset",
                           "Specifies the maximum time difference, in seconds, between the time " \
                           "of logfiles rotation. If this amount is reached, a high "   \
                           "severity alert will be emited", REQUIEM_OPTION_ARGUMENT_REQUIRED,
                           set_rotation_time_offset, get_rotation_time_offset);

        requiem_option_add(ropt, NULL, all_hook, 0, "max-rotation-size-offset",
                           "Specifies the maximum size difference between two logfile "
                           "rotation. If this difference is reached, a high severity alert "
                           "will be emited", REQUIEM_OPTION_ARGUMENT_REQUIRED, set_rotation_size_offset,
                           get_rotation_size_offset);

        requiem_option_add(ropt, &opt, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 0, "warning-limit",
                           "Limit the number of parse warnings reported from sources (0 suppress, "
                           "-1 unlimited, or user defined number)", REQUIEM_OPTION_ARGUMENT_REQUIRED,
                           set_warning_limit, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

        requiem_option_add(ropt, NULL, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 'b', "batch-mode",
                           "Tell Logeater to run in batch mode", REQUIEM_OPTION_ARGUMENT_NONE,
                           set_batch_mode, NULL);

        requiem_option_add(ropt, NULL, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 0, "metadata",
                           "Specify whether log analyzis should begin from 'head', 'tail', or 'last' known file position. "
                           "You can also use the 'nowrite' attribute so that existing file metadata are not overwritten. "
                           "The default value is 'last'", REQUIEM_OPTION_ARGUMENT_REQUIRED,
                           set_metadata_flags, NULL);

        requiem_option_add(ropt, NULL, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 0, "no-resolve",
                           "Do not attempt to resolve target address (useful for profiling)",
                           REQUIEM_OPTION_ARGUMENT_NONE, set_no_resolve, NULL);

        requiem_option_add(ropt, &opt, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG,
                           0, "format", NULL, REQUIEM_OPTION_ARGUMENT_REQUIRED, set_format, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_LAST);

        requiem_option_add(opt, NULL, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG,
                           't', "time-format", "Specify the input timestamp format", REQUIEM_OPTION_ARGUMENT_REQUIRED,
                           set_logfile_ts_format, NULL);

        requiem_option_add(opt, NULL, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG,
                           'p', "prefix-regex", "Specify the input prefix format", REQUIEM_OPTION_ARGUMENT_REQUIRED,
                           set_logfile_prefix_regex, NULL);

        requiem_option_add(opt, NULL, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG,
                           'f', "file", "Specify a file to monitor (use \"-\" for standard input)",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_file, NULL);

        requiem_option_add(opt, NULL, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 's', "udp-server",
                           "address:port pair to listen to syslog to UDP messages (default port 514)",
                           REQUIEM_OPTION_ARGUMENT_OPTIONAL, set_udp_server, NULL);

        requiem_option_add(opt, NULL, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG,
                           'c', "charset", "Specify the charset used by the input file",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_charset, NULL);

        requiem_option_add(opt, NULL, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG,
                           0, "idmef-alter", "Assign specific IDMEF path/value to matching log entry",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_idmef_alter, NULL);

        requiem_option_add(opt, NULL, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG,
                           0, "idmef-alter-force", "Assign specific IDMEF path/value to matching log entry, even if path is already used",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_idmef_alter_force, NULL);

        ret = requiem_option_read(ropt, &config_file, &argc, argv, &err, NULL);

        if ( config.charset )
                free(config.charset);

        if ( ret < 0 ) {
                if ( requiem_error_get_code(ret) == REQUIEM_ERROR_EOF )
                        return -1;

                if ( err )
                        requiem_log(REQUIEM_LOG_WARN, "%s.\n", requiem_string_get_string(err));
                else
                        requiem_perror(ret, "error processing options");

                return -1;
        }

        while ( ret < argc )
                requiem_log(REQUIEM_LOG_WARN, "Unhandled command line argument: '%s'.\n", argv[ret++]);

        if ( config.batch_mode && config.udp_nserver ) {
                requiem_log(REQUIEM_LOG_WARN, "UDP server and batch modes can't be used together.\n");
                return -1;
        }

        if ( config.ignore_metadata && ! config.batch_mode ) {
                requiem_log(REQUIEM_LOG_WARN, "--ignore-metadata is only supported in batch mode.\n");
                return -1;
        }


#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        ret = drop_privilege();
        if ( ret < 0 )
                return -1;
#endif

        if ( config.dry_run )
                return 0;

        ret = requiem_client_new(&config.logeater_client, "requiem-logeater");
        if ( ret < 0 ) {
                requiem_perror(ret, "error creating requiem-client");
                return -1;
        }

        requiem_client_set_config_filename(config.logeater_client, config_file);

        ret = logeater_alert_init(config.logeater_client);
        if ( ret < 0 )
                return -1;

        ret = requiem_client_start(config.logeater_client);
        if ( ret < 0 ) {
                requiem_perror(ret, "error starting requiem-client");
                return -1;
        }

        return 0;
}
