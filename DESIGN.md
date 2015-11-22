The ops-usermgmt daemon synchronizes the OpenSwitch OVSDB table `User` with
the local `/etc/passwd` file.

## General principle
At startup, the `/etc/passwd` file is considered to be the master source, and
the database is considered to be out of sync. Any users in passwd but not
in the database are added to the database, and any users in the database
but not in the passwd file are removed from the database.

After this initial population of the database, the database is considered
to be the master, since adding/removing users will be done there by various
front-end UIs. When a new user is found in the database, it is added to
the passwd file. A user in passwd that is no longer in the database will
be removed from the passwd file.

The actual operations on `/etc/passwd` are done by calling to the standard
`useradd` and `userdel` tools; no file manipulation is done by ops-usermgmt.

## Database
This daemon uses only the `User` table. Both the `username` and `password`
fields are read and written, depending on which direction is being
synchronized.

When a user is added to the database by a front-end, the cleartext password
in the database is run through `crypt()`, as the standard mechanism for
passwd accounts. After this is done the password is no longer needed in the
database, since actual authentication happens via the passwd file. The
cleartext password for the new account is thus set to the empty string.
This avoids cleartext passwords being permanently readable.

## Security considerations
Currently the daemon has to run as root, since it calls the `useradd` and
`userdel` tools. In addition, the DES-encrypted password is passed on the
commandline when adding a user.

This will be fixed in future versions.
