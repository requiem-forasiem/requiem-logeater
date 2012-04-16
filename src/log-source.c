/*****
*
* Copyright (C) 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * glibc2 won't define strptime()
 * unless _XOPEN_SOURCE is defined.
 */
#include <time.h>
#include <pcre.h>

#include <librequiem/requiem-log.h>

#include "requiem-logeater.h"
#include "log-source.h"
#include "logeater-options.h"
#include "logeater-charset.h"


/*
 * default log fmt.
 */
#define SYSLOG_TS_FMT "%b %d %H:%M:%S"
#define SYSLOG_PREFIX_REGEX "^(?P<timestamp>.{15}) (?P<hostname>\\S+) (?:((?P<process>\\S+)(\\[(?P<pid>[0-9]+)\\])?)?: )?"



typedef struct {
        requiem_list_t list;
        requiem_bool_t force;
        idmef_path_t *path;
        idmef_value_t *value;
} logeater_format_idmef_t;


struct logeater_log_format {
        int refcount;
        char *name;
        char *ts_fmt;
        pcre *prefix_regex;
        pcre_extra *prefix_regex_extra;

        requiem_list_t idmef_list;
};


struct logeater_log_format_container {
        REQUIEM_LINKED_OBJECT;
        logeater_log_format_t *format;
};


struct logeater_log_source {
        requiem_list_t list;

        char *name;
        logeater_charset_t *charset;

        regex_list_t *rlist;

        int warning_limit;
        int warning_count;

        requiem_list_t format_list;
};



extern logeater_config_t config;
static REQUIEM_LIST(source_list);



/*
 * Log format stuff
 */
static void logeater_log_format_destroy(logeater_log_format_t *format)
{
        if ( --format->refcount != 0 )
                return;

        if ( format->ts_fmt )
                free(format->ts_fmt);

        if ( format->prefix_regex)
                free(format->prefix_regex);

        if ( format->prefix_regex_extra)
                free(format->prefix_regex_extra);
}


static logeater_log_format_t *logeater_log_format_ref(logeater_log_format_t *lf)
{
        lf->refcount++;
        return lf;
}


static inline int _fallback_preprocess_input(const char *in, size_t inlen, char **out, size_t *outlen)
{
        if ( inlen + 1 < inlen )
                return -1;

        *out = malloc(inlen + 1);
        if ( ! *out )
                return -1;

        *outlen = inlen;
        memcpy(*out, in, inlen + 1);

        return 0;
}


int logeater_log_source_preprocess_input(logeater_log_source_t *source, const char *in, size_t inlen, char **out, size_t *outlen)
{
        int ret = -1;

        if ( source->charset )
                ret = logeater_charset_convert(source->charset, in, inlen, out, outlen);

        if ( ret < 0 )
                ret = _fallback_preprocess_input(in, inlen, out, outlen);

        return ret;
}


logeater_log_format_t *logeater_log_format_new(const char *name)
{
        logeater_log_format_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                requiem_log(REQUIEM_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->name = strdup(name);
        if ( ! new->name ) {
                free(new);
                return NULL;
        }

        if ( logeater_log_format_set_ts_fmt(new, SYSLOG_TS_FMT) < 0 ) {
                requiem_log(REQUIEM_LOG_WARN, "failed to set log timestamp format.\n");
                free(new->name);
                free(new);
                return NULL;
        }

        if ( logeater_log_format_set_prefix_regex(new, SYSLOG_PREFIX_REGEX) < 0 ) {
                requiem_log(REQUIEM_LOG_WARN, "failed to set log message prefix.\n");
                free(new->name);
                free(new);
                return NULL;
        }

        requiem_list_init(&new->idmef_list);
        return new;
}



const char *logeater_log_format_get_name(logeater_log_format_t *lf)
{
        return lf->name;
}



int logeater_log_format_set_prefix_regex(logeater_log_format_t *ls, const char *regex)
{
        int erroffset;
        const char *errptr;

        if ( ls->prefix_regex )
                free(ls->prefix_regex);

        ls->prefix_regex = pcre_compile(regex, 0, &errptr, &erroffset, NULL);
        if ( ! ls->prefix_regex ) {
                requiem_log(REQUIEM_LOG_WARN, "Unable to compile regex: %s : %s.\n", regex, errptr);
                return -1;
        }

        ls->prefix_regex_extra = pcre_study(ls->prefix_regex, 0, &errptr);
        if ( ! ls->prefix_regex_extra && errptr ) {
                requiem_log(REQUIEM_LOG_WARN, "Unable to study regex: %s : %s.\n", regex, errptr);
                return -1;
        }

        return 0;
}




int logeater_log_format_set_ts_fmt(logeater_log_format_t *ls, const char *fmt)
{
        if ( ls->ts_fmt )
                free(ls->ts_fmt);

        ls->ts_fmt = strdup(fmt);
        if ( ! ls->ts_fmt ) {
                requiem_log(REQUIEM_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        return 0;
}





int logeater_log_format_set_idmef(logeater_log_format_t *format, const char *idmef_s, requiem_bool_t force)
{
        int ret;
        size_t len;
        char *idmef, tmp;
        logeater_format_idmef_t *entry;

        len = strcspn(idmef_s, " =");
        if ( len == 0 )
                return -1;

        idmef = strdup(idmef_s);
        if ( ! idmef )
                return -1;

        entry = malloc(sizeof(*entry));
        if ( ! entry ) {
                free(idmef);
                return -1;
        }

        entry->force = force;

        tmp = idmef[len];
        idmef[len] = 0;

        ret = idmef_path_new_fast(&entry->path, idmef);
        if ( ret < 0 ) {
                free(idmef);
                free(entry);
                return ret;
        }

        idmef[len] = tmp;

        ret = idmef_value_new_from_path(&entry->value, entry->path, idmef + len + strspn(idmef + len, " ="));
        if ( ret < 0 ) {
                free(idmef);
                idmef_path_destroy(entry->path);
                free(entry);
                return ret;
        }

        free(idmef);
        requiem_list_add_tail(&format->idmef_list, &entry->list);

        return 0;
}



void logeater_log_format_apply_idmef(const logeater_log_format_t *format, idmef_message_t *idmef)
{
        int ret;
        requiem_list_t *tmp;
        idmef_value_t *value;
        logeater_format_idmef_t *entry;

        requiem_list_for_each(&format->idmef_list, tmp) {
                entry = requiem_list_entry(tmp, logeater_format_idmef_t, list);

                if ( ! entry->force ) {
                        ret = idmef_path_get(entry->path, idmef, &value);
                        if ( ret > 0 ) {
                                idmef_value_destroy(value);
                                continue;
                        }
                }

                idmef_path_set(entry->path, idmef, entry->value);
        }
}


const char *logeater_log_format_get_ts_fmt(const logeater_log_format_t *source)
{
        return source->ts_fmt;
}



const pcre *logeater_log_format_get_prefix_regex(const logeater_log_format_t *source)
{
        return source->prefix_regex;
}


const pcre_extra *logeater_log_format_get_prefix_regex_extra(const logeater_log_format_t *source)
{
        return source->prefix_regex_extra;
}


logeater_log_format_t *logeater_log_format_container_get_format(logeater_log_format_container_t *fc)
{
        return fc->format;
}



/*
 * Log source
 */
static logeater_log_source_t *search_source(const char *name)
{
        requiem_list_t *tmp;
        logeater_log_source_t *ls;

        requiem_list_for_each(&source_list, tmp) {
                ls = requiem_linked_object_get_object(tmp);

                if ( strcmp(logeater_log_source_get_name(ls), name) == 0 )
                        return ls;
        }

        return NULL;
}


static int source_set_format(logeater_log_source_t *ls, logeater_log_format_t *format)
{
        logeater_log_format_container_t *fc;

        fc = malloc(sizeof(*fc));
        if ( ! fc )
                return -1;

        fc->format = logeater_log_format_ref(format);
        requiem_linked_object_add(&ls->format_list, (requiem_linked_object_t *)fc);

        return 0;
}



regex_list_t *logeater_log_source_get_regex_list(logeater_log_source_t *ls)
{
        return ls->rlist;
}



int logeater_log_source_set_name(logeater_log_source_t *ls, const char *name)
{
        if ( ls->name )
                free(ls->name);

        ls->name = strdup(name);
        if ( ! ls->name ) {
                requiem_log(REQUIEM_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        return 0;
}


static requiem_bool_t is_charset(const char *charset, const char *wanted)
{
        char tmp[32];
        size_t ok = 0, i;
        const char *separator = "-_ ";
        requiem_bool_t is_separator;

        while ( *charset && ok != (sizeof(tmp) - 1) ) {
                is_separator = FALSE;

                for ( i = 0; separator[i]; i++ ) {
                        if ( *charset == separator[i] ) {
                                is_separator = TRUE;
                                break;
                        }
                }

                if ( ! is_separator )
                        tmp[ok++] = *charset;

                charset++;
        }

        tmp[ok] = 0;
        return strcasecmp(tmp, wanted) == 0;
}


int logeater_log_source_new(logeater_log_source_t **ls, logeater_log_format_t *format, const char *name, const char *charset)
{
        int ret = -1;

        *ls = search_source(name);
        if ( *ls ) {
                ret = source_set_format(*ls, format);
                if ( ret < 0 )
                        return -1;

                return 1;
        }

        *ls = calloc(1, sizeof(**ls));
        if ( ! *ls ) {
                requiem_log(REQUIEM_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        (*ls)->name = strdup(name);
        if ( ! (*ls)->name) {
                requiem_log(REQUIEM_LOG_ERR, "memory exhausted.\n");
                free(*ls);
                return -1;
        }

        (*ls)->rlist = regex_init(name);
        if ( ! (*ls)->rlist ) {
                free((*ls)->name);
                free(*ls);
                return -1;
        }

        (*ls)->warning_limit = config.warning_limit;
        requiem_list_init(&(*ls)->format_list);

        ret = source_set_format(*ls, format);
        if ( ret < 0 )
                return ret;

        if ( charset && ! is_charset(charset, "UTF8") ) {
                ret = logeater_charset_open(&(*ls)->charset, charset);
                if ( ret < 0 )
                        return ret;
        }

        requiem_list_add_tail(&source_list, &(*ls)->list);
        return 0;
}



const char *logeater_log_source_get_name(const logeater_log_source_t *ls)
{
        return ls->name;
}



void logeater_log_source_destroy(logeater_log_source_t *source)
{
        requiem_list_t *tmp, *bkp;
        logeater_log_format_container_t *fc;

        requiem_list_for_each_safe(&source->format_list, tmp, bkp) {
                fc = requiem_linked_object_get_object(tmp);
                requiem_linked_object_del((requiem_linked_object_t *) fc);

                logeater_log_format_destroy(fc->format);
                free(fc);
        }

        if ( source->rlist )
                regex_destroy(source->rlist);

        if ( source->name )
                free(source->name);

        if ( source->charset )
                logeater_charset_close(source->charset);

        free(source);
}



void logeater_log_source_warning(logeater_log_source_t *ls, const char *fmt, ...)
{
        va_list ap;

        /*
         * If the user provided a limit and we reached it, issue a warning and return.
         */
        if ( ls->warning_limit > 0 && ls->warning_count == ls->warning_limit ) {
                ls->warning_count++;

                requiem_log(REQUIEM_LOG_WARN, "Limit of %d errors for source %s reached. Further errors will be supressed.\n",
                            ls->warning_limit, logeater_log_source_get_name(ls));
                return;
        }

        else if ( ls->warning_limit >= 0 && ls->warning_count >= ls->warning_limit )
                return;

        ls->warning_count++;

        va_start(ap, fmt);
        requiem_log_v(REQUIEM_LOG_WARN, fmt, ap);
        va_end(ap);
}



requiem_list_t *logeater_log_source_get_format_list(logeater_log_source_t *source)
{
        return &source->format_list;
}

