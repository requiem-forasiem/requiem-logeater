/*****
*
* Copyright (C) 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef LOG_COMMON_H
#define LOG_COMMON_H

#include <pcre.h>
#include "regex.h"

typedef struct logeater_log_format logeater_log_format_t;
typedef struct logeater_log_format_container logeater_log_format_container_t;

/*
 * format
 */
logeater_log_format_t *logeater_log_format_container_get_format(logeater_log_format_container_t *fc);

logeater_log_format_t *logeater_log_format_new(const char *name);

const char *logeater_log_format_get_name(logeater_log_format_t *lf);

int logeater_log_format_set_prefix_regex(logeater_log_format_t *ls, const char *regex);

const pcre *logeater_log_format_get_prefix_regex(const logeater_log_format_t *ls);

const pcre_extra *logeater_log_format_get_prefix_regex_extra(const logeater_log_format_t *ls);

int logeater_log_format_set_ts_fmt(logeater_log_format_t *lf, const char *fmt);

const char *logeater_log_format_get_ts_fmt(const logeater_log_format_t *ls);

int logeater_log_format_set_idmef(logeater_log_format_t *format, const char *idmef_s, requiem_bool_t force);

void logeater_log_format_apply_idmef(const logeater_log_format_t *format, idmef_message_t *idmef);

/*
 *
 */
int logeater_log_source_preprocess_input(logeater_log_source_t *source, const char *in, size_t inlen, char **out, size_t *olen);

const char *logeater_log_source_get_format(logeater_log_source_t *ls);

const char *logeater_log_source_get_source(logeater_log_source_t *ls);

const char *logeater_log_source_get_name(const logeater_log_source_t *ls);

regex_list_t *logeater_log_source_get_regex_list(logeater_log_source_t *ls);

int logeater_log_source_new(logeater_log_source_t **ls, logeater_log_format_t *format, const char *name, const char *encoding);

void logeater_log_source_destroy(logeater_log_source_t *source);

int logeater_log_source_set_name(logeater_log_source_t *ls, const char *name);

void logeater_log_source_warning(logeater_log_source_t *ls, const char *fmt, ...);

requiem_list_t *logeater_log_source_get_format_list(logeater_log_source_t *source);

#endif
