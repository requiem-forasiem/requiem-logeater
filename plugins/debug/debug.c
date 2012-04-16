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
#include <stdlib.h>
#include <string.h>
#include <librequiem/requiem.h>

#include "requiem-logeater.h"


int debug_LTX_requiem_plugin_version(void);
int debug_LTX_logeater_plugin_init(requiem_plugin_entry_t *pe, void *data);


typedef struct {
        int out_stderr;
} debug_plugin_t;



static logeater_log_plugin_t plugin;
extern requiem_option_t *logeater_root_optlist;



static void debug_run(requiem_plugin_instance_t *pi, const logeater_log_source_t *ls, logeater_log_entry_t *log_entry)
{
        int ret;
        debug_plugin_t *plugin;
        idmef_alert_t *alert;
        requiem_string_t *str;
        idmef_message_t *message;
        idmef_classification_t *class;

        plugin = requiem_plugin_instance_get_plugin_data(pi);

        ret = idmef_message_new(&message);
        if ( ret < 0 ) {
                requiem_perror(ret, "error creating idmef message");
                return;
        }

        ret = idmef_message_new_alert(message, &alert);
        if ( ret < 0 ) {
                requiem_perror(ret, "error creating idmef alert");
                goto err;
        }

        ret = idmef_alert_new_classification(alert, &class);
        if ( ret < 0 ) {
                requiem_perror(ret, "error creating idmef analyzer");
                goto err;
        }

        ret = idmef_classification_new_text(class, &str);
        if ( ret < 0 ) {
                requiem_perror(ret, "error creating model string");
                goto err;
        }
        requiem_string_set_constant(str, "Logeater debug Alert");

        logeater_alert_emit(ls, log_entry, message);

        if ( plugin->out_stderr )
                fprintf(stderr, "Debug: log received, log=%s\n", logeater_log_entry_get_original_log(log_entry));

 err:
        idmef_message_destroy(message);
}



static int debug_activate(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        debug_plugin_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new )
                return requiem_error_from_errno(errno);

        requiem_plugin_instance_set_plugin_data(context, new);

        return 0;
}




static void debug_destroy(requiem_plugin_instance_t *pi, requiem_string_t *err)
{
        debug_plugin_t *debug = requiem_plugin_instance_get_plugin_data(pi);
        free(debug);
}



static int debug_get_output_stderr(requiem_option_t *opt, requiem_string_t *out, void *context)
{
        debug_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(context);
        return requiem_string_sprintf(out, "%s", plugin->out_stderr ? "true" : "false");
}



static int debug_set_output_stderr(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        debug_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(context);

        plugin->out_stderr = ! plugin->out_stderr;

        return 0;
}



int debug_LTX_logeater_plugin_init(requiem_plugin_entry_t *pe, void *logeater_root_optlist)
{
        int ret;
        requiem_option_t *opt;
        int hook = REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG;

        ret = requiem_option_add(logeater_root_optlist, &opt, hook, 0, "debug", "Debug plugin option",
                                 REQUIEM_OPTION_ARGUMENT_OPTIONAL, debug_activate, NULL);

        requiem_plugin_set_activation_option(pe, opt, NULL);

        requiem_option_add(opt, NULL, hook, 's', "stderr",
                           "Output to stderr when plugin is called", REQUIEM_OPTION_ARGUMENT_NONE,
                           debug_set_output_stderr, debug_get_output_stderr);

        plugin.run = debug_run;
        requiem_plugin_set_name(&plugin, "Debug");
        requiem_plugin_set_destroy_func(&plugin, debug_destroy);

        requiem_plugin_entry_set_plugin(pe, (void *) &plugin);

        return 0;
}



int debug_LTX_requiem_plugin_version(void)
{
        return REQUIEM_PLUGIN_API_VERSION;
}

