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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>


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

#include <librequiem/common.h>
#include <librequiem/requiem.h>
#include <librequiem/requiem-log.h>
#include <librequiem/idmef-message-print.h>

#include "log-entry.h"
#include "logeater-alert.h"
#include "logeater-options.h"


extern logeater_config_t config;
static idmef_analyzer_t *idmef_analyzer;


#define ANALYZER_CLASS "Log Analyzer"
#define ANALYZER_MODEL "Requiem Logeater"
#define ANALYZER_MANUFACTURER "http://www.requiem-ids.com"



static int resolve_failed_fallback(idmef_node_t *node, const char *hostname)
{
        int ret, family;
        idmef_address_t *address;
        requiem_string_t *string;
        struct addrinfo hints, *res;


        /*
         * we want to know if it's an ip address or an hostname.
         */

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_flags  = AI_NUMERICHOST;

        ret = getaddrinfo(hostname, NULL, &hints, &res);
        if ( ret != 0 ) {
                /*
                 * hostname.
                 */
                ret = idmef_node_new_name(node, &string);
                if ( ret < 0 )
                        return ret;
        } else {
                family = res->ai_family;
                freeaddrinfo(res);

                ret = idmef_node_new_address(node, &address, IDMEF_LIST_APPEND);
                if ( ret < 0 )
                        return ret;

                ret = idmef_address_new_address(address, &string);
                if ( ret < 0 )
                        return ret;

                idmef_address_set_category(address, (family == AF_INET) ? IDMEF_ADDRESS_CATEGORY_IPV4_ADDR : IDMEF_ADDRESS_CATEGORY_IPV6_ADDR);
        }

        return requiem_string_set_dup(string, hostname);
}




static int fill_target_node_from_addrinfo(idmef_node_t *node, struct addrinfo *ai)
{
        int ret;
        char str[128];
        void *in_addr;
        idmef_address_t *addr;
        requiem_string_t *string;

        while ( ai ) {
                ret = idmef_node_new_address(node, &addr, IDMEF_LIST_APPEND);
                if ( ret < 0 )
                        return -1;

                in_addr = requiem_sockaddr_get_inaddr(ai->ai_addr);
                if ( ! in_addr )
                        return -1;

                idmef_address_set_category(addr, (ai->ai_family == AF_INET) ?
                                           IDMEF_ADDRESS_CATEGORY_IPV4_ADDR :
                                           IDMEF_ADDRESS_CATEGORY_IPV6_ADDR);

                if ( ! inet_ntop(ai->ai_family, in_addr, str, sizeof(str)) ) {
                        requiem_log(REQUIEM_LOG_ERR, "inet_ntop returned an error: %s.\n", strerror(errno));
                        return -1;
                }

                ret = idmef_address_new_address(addr, &string);
                if ( ret < 0 )
                        return -1;

                if ( requiem_string_set_dup(string, str) < 0 )
                        return -1;

                if ( ai->ai_canonname && strcmp(ai->ai_canonname, str) != 0 ) {
                        ret = idmef_node_new_name(node, &string);
                        if ( ret < 0 )
                                return -1;

                        if ( requiem_string_set_dup(string, ai->ai_canonname) < 0 )
                                return -1;
                }

                ai = ai->ai_next;
        }

        return 0;
}



static int fill_target_node(idmef_node_t *node, const char *host)
{
        int ret;
        struct addrinfo *ai, hints;

        if ( config.no_resolve )
                ret = resolve_failed_fallback(node, host);
        else {
                memset(&hints, 0, sizeof(hints));
                hints.ai_flags = AI_CANONNAME;
                hints.ai_socktype = SOCK_STREAM;

                ret = getaddrinfo(host, NULL, &hints, &ai);
                if ( ret != 0 ) {
                        requiem_log(REQUIEM_LOG_WARN, "error resolving \"%s\": %s.\n", host, gai_strerror(ret));
                        return resolve_failed_fallback(node, host);
                }

                ret = fill_target_node_from_addrinfo(node, ai);
                freeaddrinfo(ai);
        }

        return ret;
}



static int fill_analyzer(const logeater_log_entry_t *log_entry, idmef_analyzer_t *analyzer)
{
        int ret = 0;
        const char *tmp;
        idmef_node_t *node;
        requiem_string_t *str;
        idmef_process_t *process;

        tmp = logeater_log_entry_get_target_process(log_entry);

        if ( tmp && ! idmef_analyzer_get_process(analyzer) ) {
                ret = idmef_analyzer_new_process(analyzer, &process);
                if ( ret < 0 )
                        return -1;

                ret = idmef_process_new_name(process, &str);
                if ( ret < 0 )
                        return -1;

                requiem_string_set_ref(str, tmp);

                tmp = logeater_log_entry_get_target_process_pid(log_entry);
                if ( tmp )
                        idmef_process_set_pid(process, atoi(tmp));
        }

        tmp = logeater_log_entry_get_target_hostname(log_entry);
        if ( tmp && ! idmef_analyzer_get_node(analyzer) ) {

                ret = idmef_analyzer_new_node(analyzer, &node);
                if ( ret < 0 )
                        return -1;

                ret = fill_target_node(node, tmp);
        }

        return ret;
}


static int generate_target(const logeater_log_entry_t *log_entry, idmef_alert_t *alert)
{
        int ret = 0;
        const char *tmp;
        idmef_node_t *node;
        requiem_string_t *str;
        idmef_target_t *target;
        idmef_process_t *process;

        target = idmef_alert_get_next_target(alert, NULL);
        if ( ! target ) {
                ret = idmef_alert_new_target(alert, &target, IDMEF_LIST_APPEND);
                if ( ret < 0 )
                        return ret;
        }

        tmp = logeater_log_entry_get_target_process(log_entry);
        if ( tmp && ! idmef_target_get_process(target) ) {
                ret = idmef_target_new_process(target, &process);
                if ( ret < 0 )
                        return ret;

                ret = idmef_process_new_name(process, &str);
                if ( ret < 0 )
                        return ret;

                requiem_string_set_dup(str, tmp);

                tmp = logeater_log_entry_get_target_process_pid(log_entry);
                if ( tmp )
                        idmef_process_set_pid(process, atoi(tmp));
        }

        tmp = logeater_log_entry_get_target_hostname(log_entry);
        if ( tmp && ! idmef_target_get_node(target) ) {
                ret = idmef_target_new_node(target, &node);
                if ( ret < 0 )
                        return ret;

                ret = fill_target_node(node, tmp);
        }

        return ret;
}



static int generate_additional_data(idmef_additional_data_t **adata, const char *meaning, const char *data, size_t len)
{
        int ret;
        requiem_string_t *str;

        ret = idmef_additional_data_new(adata);
        if ( ret < 0 )
                return ret;

        ret = idmef_additional_data_new_meaning(*adata, &str);
        if ( ret < 0 )
                return ret;

        requiem_string_set_ref(str, meaning);

        return idmef_additional_data_set_string_dup_fast(*adata, data, len);
}



int logeater_additional_data_prepare(requiem_list_t *adlist, const logeater_log_source_t *ls, const logeater_log_entry_t *log)
{
        const char *ptr, *source;
        idmef_additional_data_t *adata;

        source = logeater_log_source_get_name(ls);
        if ( generate_additional_data(&adata, "Log received from", source, strlen(source)) < 0 )
                return -1;

        requiem_linked_object_add_tail(adlist, (requiem_linked_object_t *) adata);

        ptr = logeater_log_entry_get_original_log(log);
        if ( ptr ) {
                if ( generate_additional_data(&adata, "Original Log", ptr, logeater_log_entry_get_original_log_len(log)) < 0 )
                        return -1;

                requiem_linked_object_add_tail(adlist, (requiem_linked_object_t *) adata);
        }

        return 0;
}


int logeater_alert_set_infos(idmef_message_t *message, const logeater_log_entry_t *log)
{
        int ret;
        idmef_time_t *time;
        idmef_alert_t *alert;
        idmef_analyzer_t *cur_analyzer;

        ret = idmef_message_new_alert(message, &alert);
        if ( ret < 0 )
                return -1;

        ret = idmef_alert_new_detect_time(alert, &time);
        if ( ret < 0 )
                return ret;

        idmef_time_set_from_timeval(time, logeater_log_entry_get_timeval(log));

        if ( logeater_log_entry_get_target_hostname(log) || logeater_log_entry_get_target_process(log) ) {
                if ( generate_target(log, alert) < 0 )
                        return -1;

                cur_analyzer = idmef_alert_get_next_analyzer(alert, NULL);
                if ( cur_analyzer && fill_analyzer(log, cur_analyzer) < 0 )
                        return -1;
        }

        if ( logeater_log_entry_get_format(log) )
                logeater_log_format_apply_idmef(logeater_log_entry_get_format(log), message);

        return 0;
}



int logeater_alert_prepare(idmef_message_t *message, const logeater_log_source_t *ls, const logeater_log_entry_t *log)
{
        int ret;
        idmef_alert_t *alert;
        const char *ptr, *source;
        idmef_additional_data_t *adata;

        ret = idmef_message_new_alert(message, &alert);
        if ( ret < 0 )
                return -1;

        if ( ls ) {
                source = logeater_log_source_get_name(ls);

                if ( generate_additional_data(&adata, "Log received from", source, strlen(source)) < 0 )
                        return -1;

                idmef_alert_set_additional_data(alert, adata, IDMEF_LIST_APPEND);
        }

        if ( log ) {
                ptr = logeater_log_entry_get_original_log(log);
                if ( ptr ) {
                        if ( generate_additional_data(&adata, "Original Log", ptr, logeater_log_entry_get_original_log_len(log)) < 0 )
                                return -1;

                        idmef_alert_set_additional_data(alert, adata, IDMEF_LIST_APPEND);
                }

                logeater_alert_set_infos(message, log);
        }

        return 0;
}



void logeater_alert_emit(const logeater_log_source_t *ls, const logeater_log_entry_t *log, idmef_message_t *message)
{
        int ret;
        idmef_time_t *time;
        idmef_alert_t *alert;

        ret = logeater_alert_prepare(message, ls, log);
        if ( ret < 0 )
                return;

        alert = idmef_message_get_alert(message);
        if ( ! alert )
                return;

        ret = idmef_time_new_from_gettimeofday(&time);
        if ( ret < 0 )
                return;
        idmef_alert_set_create_time(alert, time);

        if ( idmef_analyzer )
                idmef_alert_set_analyzer(alert, idmef_analyzer_ref(idmef_analyzer), IDMEF_LIST_PREPEND);

        if ( config.text_output_fd )
                idmef_message_print(message, config.text_output_fd);

        if ( ! config.dry_run )
                requiem_client_send_idmef(config.logeater_client, message);

        config.alert_count++;
}




int logeater_alert_init(requiem_client_t *logeater_client)
{
        int ret;
        requiem_string_t *string;

        idmef_analyzer = requiem_client_get_analyzer(logeater_client);
        if ( ! idmef_analyzer )
                return -1;

        ret = idmef_analyzer_new_model(idmef_analyzer, &string);
        if ( ret < 0 )
                return -1;
        requiem_string_set_constant(string, ANALYZER_MODEL);

        ret = idmef_analyzer_new_class(idmef_analyzer, &string);
        if ( ret < 0 )
                return -1;
        requiem_string_set_constant(string, ANALYZER_CLASS);

        ret = idmef_analyzer_new_manufacturer(idmef_analyzer, &string);
        if ( ret < 0 )
                return -1;
        requiem_string_set_constant(string, ANALYZER_MANUFACTURER);

        ret = idmef_analyzer_new_version(idmef_analyzer, &string);
        if ( ret < 0 )
                return -1;
        requiem_string_set_constant(string, VERSION);

        return 0;
}
