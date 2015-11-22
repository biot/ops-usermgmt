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

#include <sys/types.h>
#include <pwd.h>
#define _GNU_SOURCE
#include <crypt.h>
#include <strings.h>

#include "config.h"
#include <openvswitch/vlog.h>
#include <ovsdb-idl.h>
#include <vswitch-idl.h>

#include "usermgmt.h"

VLOG_DEFINE_THIS_MODULE(ops_usermgmt);

#define USERNAME_ALLOWED_CHARS "-_0123456789abcdefghijklmnopqrstuvwxyz"

extern struct ovsdb_idl *idl;


static const struct ovsrec_user *find_db_user(char *username)
{
    const struct ovsrec_user *user;

    OVSREC_USER_FOR_EACH(user, idl) {
        if (!strcmp(username, user->username))
            return user;
    }

    return NULL;
}

/* Some arbitrary sanity checks. */
static bool check_username(char *username)
{
    int i;

    if (strlen(username) > 80)
        return false;

    for (i = 0; username[i]; i++) {
        if (!index(USERNAME_ALLOWED_CHARS, username[i]))
            return false;
    }

    return true;
}

/*
 * Populate OVSDB User table from passwd, and drop any users in the
 * database not in passwd.
 */
bool
sync_to_db(void)
{
    struct ovsdb_idl_txn *txn;
    const struct ovsrec_user *old_user;
    struct ovsrec_user *user;
    struct passwd *pw;
    enum ovsdb_idl_txn_status st;
    bool ret;

    ret = true;

    /* Populate from passwd entries. */
    txn = NULL;
    setpwent();
    while ((pw = getpwent())) {
        if (pw->pw_gid != OVSDB_GID)
            continue;
        if (find_db_user(pw->pw_name))
            continue;
        VLOG_INFO("Adding database user %s.", pw->pw_name);
        if (!txn)
            txn = ovsdb_idl_txn_create(idl);
        user = ovsrec_user_insert(txn);
        ovsrec_user_set_username(user, pw->pw_name);
        ovsrec_user_set_password(user, "");
    }        
    endpwent();

    /* Delete any stray database users not in passwd. */
    OVSREC_USER_FOR_EACH(old_user, idl) {
        if (!getpwnam(old_user->username)) {
            VLOG_INFO("Removing database user %s.", old_user->username);
            if (!txn)
                txn = ovsdb_idl_txn_create(idl);
            ovsrec_user_delete(old_user);
        }
    }

    if (txn) {
        st = ovsdb_idl_txn_commit_block(txn);
        ovsdb_idl_txn_destroy(txn);
        if (st != TXN_SUCCESS) {
            VLOG_ERR("Failed to populate database: transaction status %d.", st);
            ret = false;
        }
    }

    return ret;
}

/*
 * Drop any passwd users not in the database, and add to passwd any new
 * users in the database.
 */
void
sync_from_db(void)
{
    struct ovsdb_idl_txn *txn;
    const struct ovsrec_user *user;
    enum ovsdb_idl_txn_status st;
    struct passwd *pw;
    int ret;
    char buf[256], *cpass;

    /* Delete old passwd entries. */
    setpwent();
    while ((pw = getpwent())) {
        if (pw->pw_gid != OVSDB_GID)
            continue;
        if (find_db_user(pw->pw_name))
            continue;
        VLOG_INFO("Removing local user %s.", pw->pw_name);
        snprintf(buf, 256, "%s --remove %s", USERDEL, pw->pw_name);
        ret = system(buf);
        if (ret) {
            VLOG_ERR("Failed to remove local user: %d.", ret);
        }
    }        
    endpwent();

    /* Add new database users to passwd. */
    OVSREC_USER_FOR_EACH(user, idl) {
        if (!check_username(user->username)) {
            VLOG_ERR("Skipping invalid username.");
            continue;
        }
        if (getpwnam(user->username))
            /* Already exists. */
            continue;

        cpass = crypt(user->password, "ab");
        snprintf(buf, 256, "%s --gid %d --password %s --shell %s %s",
                 USERADD, OVSDB_GID, cpass, USER_SHELL, user->username);
        VLOG_INFO("Adding local user %s.", user->username);
        ret = system(buf);
        if (ret) {
            VLOG_ERR("Failed to add local user: %d.", ret);
        }

        /* Blank password in database: we have a crypted version in passwd. */
        txn = ovsdb_idl_txn_create(idl);
        ovsrec_user_set_password(user, "");
        st = ovsdb_idl_txn_commit_block(txn);
        ovsdb_idl_txn_destroy(txn);
        if (st != TXN_SUCCESS)
            VLOG_ERR("Failed to blank password: transaction status %d.", st);
    }
}
