/*****
*
* Copyright (C) 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _REQUIEM_Logeater_H
#define _REQUIEM_Logeater_H

#include <librequiem/requiem.h>
#include <librequiem/requiem-log.h>

typedef struct logeater_log_entry logeater_log_entry_t;
typedef struct logeater_log_source logeater_log_source_t;


typedef struct {
        REQUIEM_PLUGIN_GENERIC;
        void (*run)(requiem_plugin_instance_t *pi, const logeater_log_source_t *ls, logeater_log_entry_t *log);
} logeater_log_plugin_t;


void logeater_log_entry_destroy(logeater_log_entry_t *lc);

logeater_log_entry_t *logeater_log_entry_ref(logeater_log_entry_t *log_entry);


const char *logeater_log_entry_get_message(const logeater_log_entry_t *log_entry);

const char *logeater_log_entry_get_original_log(const logeater_log_entry_t *log_entry);

size_t logeater_log_entry_get_message_len(const logeater_log_entry_t *log_entry);

size_t logeater_log_entry_get_original_log_len(const logeater_log_entry_t *log_entry);

const struct timeval *logeater_log_entry_get_timeval(const logeater_log_entry_t *log_entry);

const char *logeater_log_entry_get_target_hostname(const logeater_log_entry_t *log_entry);

const char *logeater_log_entry_get_target_process(const logeater_log_entry_t *log_entry);

const char *logeater_log_entry_get_target_process_pid(const logeater_log_entry_t *log_entry);


/*
 * Alert emission
 */
int logeater_alert_set_infos(idmef_message_t *message, const logeater_log_entry_t *log);

void logeater_alert_emit(const logeater_log_source_t *ls, const logeater_log_entry_t *log, idmef_message_t *msg);

int logeater_alert_prepare(idmef_message_t *message, const logeater_log_source_t *ls, const logeater_log_entry_t *log);

int logeater_additional_data_prepare(requiem_list_t *adlist, const logeater_log_source_t *ls, const logeater_log_entry_t *log);
#endif
