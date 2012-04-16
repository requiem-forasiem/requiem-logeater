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

#ifndef _LOG_ENTRY_H
#define _LOG_ENTRY_H

#include "requiem-logeater.h"
#include "log-source.h"

logeater_log_entry_t *logeater_log_entry_new(void);

int logeater_log_entry_set_log(logeater_log_entry_t *lc, logeater_log_source_t *ls, char *entry, size_t size);

const logeater_log_format_t *logeater_log_entry_get_format(const logeater_log_entry_t *log);

#endif /* _LOG_ENTRY_H */
