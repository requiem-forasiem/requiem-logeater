/*****
*
* Copyright (C) 2006 PreludeIDS Technologies. All Rights Reserved.
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
#include <ctype.h>
#include <pcre.h>

#include <librequiem/requiem.h>
#include <librequiem/requiem-string.h>

#include "requiem-logeater.h"
#include "pcre-mod.h"
#include "value-container.h"


struct value_container {
        requiem_list_t list;
        requiem_list_t value_item_list;
        void *data;
};


typedef struct {
        requiem_list_t list;
        int refno;
        char *value;
} value_item_t;



static int add_dynamic_object_value(value_container_t *vcont, unsigned int reference)
{
        value_item_t *vitem;

        if ( reference >= MAX_REFERENCE_PER_RULE ) {
                requiem_log(REQUIEM_LOG_WARN, "reference number %d is too high.\n", reference);
                return -1;
        }

        vitem = malloc(sizeof(*vitem));
        if ( ! vitem ) {
                requiem_log(REQUIEM_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        vitem->value = NULL;
        vitem->refno = reference;
        requiem_list_add_tail(&vcont->value_item_list, &vitem->list);

        return 0;
}



static int add_fixed_object_value(value_container_t *vcont, requiem_string_t *buf)
{
        int ret;
        value_item_t *vitem;

        vitem = malloc(sizeof(*vitem));
        if ( ! vitem ) {
                requiem_log(REQUIEM_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        ret = requiem_string_get_string_released(buf, &vitem->value);
        if ( ret < 0 ) {
                requiem_perror(ret, "error getting released string");
                free(vitem);
                return -1;
        }

        vitem->refno = -1;
        requiem_list_add_tail(&vcont->value_item_list, &vitem->list);

        return 0;
}



static int parse_value(value_container_t *vcont, const char *line)
{
        int ret;
        char num[10];
        unsigned int i;
        const char *str;
        requiem_string_t *strbuf;

        str = line;

        while ( *str ) {
                if ( *str == '$' && *(str + 1) != '$' ) {

                        i = 0;
                        str++;

                        while ( isdigit((int) *str) && i < (sizeof(num) - 1) )
                                num[i++] = *str++;

                        if ( ! i )
                                return -1;

                        num[i] = 0;

                        if ( add_dynamic_object_value(vcont, atoi(num)) < 0 )
                                return -1;

                        continue;
                }

                ret = requiem_string_new(&strbuf);
                if ( ret < 0 ) {
                        requiem_perror(ret, "error creating new requiem-string");
                        return -1;
                }

                while ( *str ) {
                        if ( *str == '$' ) {
                                if ( *(str + 1) == '$' )
                                        str++;
                                else
                                        break;
                        }

                        if ( requiem_string_ncat(strbuf, str, 1) < 0 )
                                return -1;
                        str++;
                }

                if ( add_fixed_object_value(vcont, strbuf) < 0 )
                        return -1;

                requiem_string_destroy(strbuf);
        }

        return 0;
}



static void resolve_referenced_value(value_item_t *vitem, const pcre_rule_t *rule,
                                     const char *log_entry, int *ovector, size_t osize)
{
        int ret;

        ret = pcre_get_substring(log_entry, ovector, osize, vitem->refno, (const char **) &vitem->value);
        if ( ret < 0 ) {
                vitem->value = NULL;

                if ( ret == PCRE_ERROR_NOMEMORY )
                        requiem_log(REQUIEM_LOG_WARN, "not enough memory to get backward reference %d.\n",
                                    vitem->refno);

                else if ( ret == PCRE_ERROR_NOSUBSTRING )
                        requiem_log(REQUIEM_LOG_WARN, "backward reference number %d does not exist in rule id %d.\n",
                                    vitem->refno, rule->id);

                else
                        requiem_log(REQUIEM_LOG_WARN, "unknown PCRE error while getting backward reference %d.\n",
                                    vitem->refno);
        }
}



requiem_string_t *value_container_resolve(value_container_t *vcont, const pcre_rule_t *rule,
                                          const logeater_log_entry_t *lentry, int *ovector, size_t osize)
{
        int ret;
        value_item_t *vitem;
        requiem_list_t *tmp;
        requiem_string_t *str;

        ret = requiem_string_new(&str);
        if ( ret < 0 ) {
                requiem_perror(ret, "error creating requiem-string");
                return NULL;
        }

        requiem_list_for_each(&vcont->value_item_list, tmp) {
                vitem = requiem_list_entry(tmp, value_item_t, list);

                if ( vitem->refno != -1 ) {
                        resolve_referenced_value(vitem, rule, logeater_log_entry_get_message(lentry), ovector, osize);
                        if ( ! vitem->value )
                                continue;
                }

                ret = requiem_string_cat(str, vitem->value);

                if ( vitem->refno != -1 && vitem->value )
                        pcre_free_substring(vitem->value);

                if ( ret < 0 )
                        goto err;
        }

        if ( ! requiem_string_is_empty(str) )
                return str;

err:
        requiem_string_destroy(str);
        return NULL;
}




int value_container_new(value_container_t **vcont, const char *str)
{
        int ret;

        *vcont = malloc(sizeof(**vcont));
        if ( ! *vcont ) {
                requiem_log(REQUIEM_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        (*vcont)->data = NULL;
        requiem_list_init(&(*vcont)->value_item_list);

        ret = parse_value(*vcont, str);
        if ( ret < 0 ) {
                free(*vcont);
                return ret;
        }

        return 0;
}



void value_container_destroy(value_container_t *vcont)
{
        value_item_t *vitem;
        requiem_list_t *tmp, *bkp;

        requiem_list_for_each_safe(&vcont->value_item_list, tmp, bkp) {
                vitem = requiem_list_entry(tmp, value_item_t, list);

                if ( vitem->value && vitem->refno == -1 )
                        free(vitem->value);

                requiem_list_del(&vitem->list);
                free(vitem);
        }

        free(vcont);
}


void *value_container_get_data(value_container_t *vcont)
{
        return vcont->data;
}


void value_container_set_data(value_container_t *vcont, void *data)
{
        vcont->data = data;
}
