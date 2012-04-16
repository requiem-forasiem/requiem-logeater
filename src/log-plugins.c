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
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>                /* for NAME_MAX */

#include <librequiem/requiem.h>
#include <librequiem/requiem-log.h>

#include "requiem-logeater.h"
#include "log-source.h"
#include "log-entry.h"
#include "log-plugins.h"


#define Logeater_PLUGIN_SYMBOL "logeater_plugin_init"


static REQUIEM_LIST(log_plugins_instance);


static int subscribe(requiem_plugin_instance_t *pi)
{
        requiem_plugin_generic_t *plugin = requiem_plugin_instance_get_plugin(pi);

        requiem_log(REQUIEM_LOG_DEBUG, "Subscribing plugin %s[%s]\n", plugin->name, requiem_plugin_instance_get_name(pi));
        requiem_linked_object_add(&log_plugins_instance, (requiem_linked_object_t *) pi);

        return 0;
}



static void unsubscribe(requiem_plugin_instance_t *pi)
{
        requiem_plugin_generic_t *plugin = requiem_plugin_instance_get_plugin(pi);

        requiem_log(REQUIEM_LOG_DEBUG, "Unsubscribing plugin %s[%s]\n", plugin->name, requiem_plugin_instance_get_name(pi));
        requiem_linked_object_del((requiem_linked_object_t *) pi);
}



void log_plugin_run(requiem_plugin_instance_t *pi, logeater_log_source_t *ls, logeater_log_entry_t *log)
{
        requiem_plugin_run(pi, logeater_log_plugin_t, run, pi, ls, log);
}




requiem_plugin_instance_t *log_plugin_register(const char *plugin)
{
        int ret;
        char pname[256], iname[256];
        requiem_plugin_generic_t *pl;
        requiem_plugin_instance_t *pi;

        ret = sscanf(plugin, "%255[^[][%255[^]]", pname, iname);

        pi = requiem_plugin_search_instance_by_name(NULL, pname, (ret == 2) ? iname : NULL);
        if ( pi )
                return pi;

        pl = requiem_plugin_search_by_name(NULL, pname);
        if ( ! pl )
                return NULL;

        ret = requiem_plugin_new_instance(&pi, pl, (ret == 2) ? iname : NULL, NULL);
        if ( ret < 0 )
                return NULL;

        return pi;
}




/*
 * Open the plugin directory (dirname),
 * and try to load all plugins located int it.
 */
int log_plugins_init(const char *dirname, void *data)
{
        int ret;

        ret = access(dirname, F_OK);
        if ( ret < 0 ) {
                if ( errno == ENOENT )
                        return 0;

                requiem_log(REQUIEM_LOG_ERR, "could not access '%s': %s.\n", dirname, strerror(errno));
                return -1;
        }

        ret = requiem_plugin_load_from_dir(NULL, dirname, Logeater_PLUGIN_SYMBOL, data, subscribe, unsubscribe);
        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_WARN, "error loading plugins: %s.\n", requiem_strerror(ret));
                return -1;
        }

        return ret;
}

