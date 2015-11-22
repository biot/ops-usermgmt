/*
 * Copyright (C) 2015 Bert Vermeulen <bert@biot.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#ifndef _OPS_USERMGMT_H
#define _OPS_USERMGMT_H

#define OVSDB_GID 1020
#define USERADD "/usr/sbin/useradd"
#define USERDEL "/usr/sbin/userdel"
#define USER_SHELL "/usr/bin/vtysh"

bool sync_to_db(void);
void sync_from_db(void);

#endif /* _OPS_USERMGMT_H */
