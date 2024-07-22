#!/bin/bash

# 1.6 패스워드 사용 규칙 적용 조치
echo '1.6 패스워드 사용 규칙 적용 조치 /etc/login.defs'
if [ $(cat /etc/issue | grep -i "ubuntu" | wc -l) -gt 0 ]; then
    echo 'ubuntu'
    cat <<eof >/etc/login.defs

# /etc/login.defs - Configuration control definitions for the login package.
#
# Three items must be defined:  MAIL_DIR, ENV_SUPATH, and ENV_PATH.
# If unspecified, some arbitrary (and possibly incorrect) value will
# be assumed.  All other items are optional - if not specified then
# the described action or option will be inhibited.
#
# Comment lines (lines beginning with "#") and blank lines are ignored.
#
# Modified for Linux.  --marekm

# REQUIRED for useradd/userdel/usermod
#   Directory where mailboxes reside, _or_ name of file, relative to the
#   home directory.  If you _do_ define MAIL_DIR and MAIL_FILE,
#   MAIL_DIR takes precedence.
#
#   Essentially:
#      - MAIL_DIR defines the location of users mail spool files
#        (for mbox use) by appending the username to MAIL_DIR as defined
#        below.
#      - MAIL_FILE defines the location of the users mail spool files as the
#        fully-qualified filename obtained by prepending the user home
#        directory before $MAIL_FILE
#
# NOTE: This is no more used for setting up users MAIL environment variable
#       which is, starting from shadow 4.0.12-1 in Debian, entirely the
#       job of the pam_mail PAM modules
#       See default PAM configuration files provided for
#       login, su, etc.
#
# This is a temporary situation: setting these variables will soon
# move to /etc/default/useradd and the variables will then be
# no more supported
MAIL_DIR        /var/mail
#MAIL_FILE      .mail

#
# Enable logging and display of /var/log/faillog login failure info.
# This option conflicts with the pam_tally PAM module.
#
FAILLOG_ENAB            yes

#
# Enable display of unknown usernames when login failures are recorded.
#
# WARNING: Unknown usernames may become world readable. 
# See #290803 and #298773 for details about how this could become a security
# concern
LOG_UNKFAIL_ENAB        no

#
# Enable logging of successful logins
#
LOG_OK_LOGINS           no

#
# Enable "syslog" logging of su activity - in addition to sulog file logging.
# SYSLOG_SG_ENAB does the same for newgrp and sg.
#
SYSLOG_SU_ENAB          yes
SYSLOG_SG_ENAB          yes

#
# If defined, all su activity is logged to this file.
#
#SULOG_FILE     /var/log/sulog

#
# If defined, file which maps tty line to TERM environment parameter.
# Each line of the file is in a format something like "vt100  tty01".
#
#TTYTYPE_FILE   /etc/ttytype

#
# If defined, login failures will be logged here in a utmp format
# last, when invoked as lastb, will read /var/log/btmp, so...
#
FTMP_FILE       /var/log/btmp

#
# If defined, the command name to display when running "su -".  For
# example, if this is defined as "su" then a "ps" will display the
# command is "-su".  If not defined, then "ps" would display the
# name of the shell actually being run, e.g. something like "-sh".
#
SU_NAME         su

#
# If defined, file which inhibits all the usual chatter during the login
# sequence.  If a full pathname, then hushed mode will be enabled if the
# user's name or shell are found in the file.  If not a full pathname, then
# hushed mode will be enabled if the file exists in the user's home directory.
#
HUSHLOGIN_FILE  .hushlogin
#HUSHLOGIN_FILE /etc/hushlogins

#
# *REQUIRED*  The default PATH settings, for superuser and normal users.
#
# (they are minimal, add the rest in the shell startup files)
ENV_SUPATH      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH        PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

#
# Terminal permissions
#
#       TTYGROUP        Login tty will be assigned this group ownership.
#       TTYPERM         Login tty will be set to this permission.
#
# If you have a "write" program which is "setgid" to a special group
# which owns the terminals, define TTYGROUP to the group number and
# TTYPERM to 0620.  Otherwise leave TTYGROUP commented out and assign
# TTYPERM to either 622 or 600.
#
# In Debian /usr/bin/bsd-write or similar programs are setgid tty
# However, the default and recommended value for TTYPERM is still 0600
# to not allow anyone to write to anyone else console or terminal

# Users can still allow other people to write them by issuing 
# the "mesg y" command.

TTYGROUP        tty
TTYPERM         0600

#
# Login configuration initializations:
#
#       ERASECHAR       Terminal ERASE character ('\010' = backspace).
#       KILLCHAR        Terminal KILL character ('\025' = CTRL/U).
#       UMASK           Default "umask" value.
#
# The ERASECHAR and KILLCHAR are used only on System V machines.
# 
# UMASK is the default umask value for pam_umask and is used by
# useradd and newusers to set the mode of the new home directories.
# 022 is the "historical" value in Debian for UMASK
# 027, or even 077, could be considered better for privacy
# There is no One True Answer here : each sysadmin must make up his/her
# mind.
#
# If USERGROUPS_ENAB is set to "yes", that will modify this UMASK default value
# for private user groups, i. e. the uid is the same as gid, and username is
# the same as the primary group name: for these, the user permissions will be
# used as group permissions, e. g. 022 will become 002.
#
# Prefix these values with "0" to get octal, "0x" to get hexadecimal.
#
ERASECHAR       0177
KILLCHAR        025
UMASK           022

#
# Password aging controls:
#
#       PASS_MAX_DAYS   Maximum number of days a password may be used.
#       PASS_MIN_DAYS   Minimum number of days allowed between password changes.
#       PASS_WARN_AGE   Number of days warning given before a password expires.
#
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   30

#
# Min/max values for automatic uid selection in useradd
#
UID_MIN                  1000
UID_MAX                 60000
# System accounts
#SYS_UID_MIN              100
#SYS_UID_MAX              999

#
# Min/max values for automatic gid selection in groupadd
#
GID_MIN                  1000
GID_MAX                 60000
# System accounts
#SYS_GID_MIN              100
#SYS_GID_MAX              999

#
# Max number of login retries if password is bad. This will most likely be
# overriden by PAM, since the default pam_unix module has it's own built
# in of 3 retries. However, this is a safe fallback in case you are using
# an authentication module that does not enforce PAM_MAXTRIES.
#
LOGIN_RETRIES           5

#
# Max time in seconds for login
#
LOGIN_TIMEOUT           60

#
# Which fields may be changed by regular users using chfn - use
# any combination of letters "frwh" (full name, room number, work
# phone, home phone).  If not defined, no changes are allowed.
# For backward compatibility, "yes" = "rwh" and "no" = "frwh".
# 
CHFN_RESTRICT           rwh

#
# Should login be allowed if we can't cd to the home directory?
# Default in no.
#
DEFAULT_HOME    yes

#
# If defined, this command is run when removing a user.
# It should remove any at/cron/print jobs etc. owned by
# the user to be removed (passed as the first argument).
#
#USERDEL_CMD    /usr/sbin/userdel_local

#
# Enable setting of the umask group bits to be the same as owner bits
# (examples: 022 -> 002, 077 -> 007) for non-root users, if the uid is
# the same as gid, and username is the same as the primary group name.
#
# If set to yes, userdel will remove the user's group if it contains no
# more members, and useradd will create by default a group with the name
# of the user.
#
USERGROUPS_ENAB yes

#
# Instead of the real user shell, the program specified by this parameter
# will be launched, although its visible name (argv[0]) will be the shell's.
# The program may do whatever it wants (logging, additional authentification,
# banner, ...) before running the actual shell.
#
# FAKE_SHELL /bin/fakeshell

#
# If defined, either full pathname of a file containing device names or
# a ":" delimited list of device names.  Root logins will be allowed only
# upon these devices.
#
# This variable is used by login and su.
#
#CONSOLE        /etc/consoles
#CONSOLE        console:tty01:tty02:tty03:tty04

#
# List of groups to add to the user's supplementary group set
# when logging in on the console (as determined by the CONSOLE
# setting).  Default is none.
#
# Use with caution - it is possible for users to gain permanent
# access to these groups, even when not logged in on the console.
# How to do it is left as an exercise for the reader...
#
# This variable is used by login and su.
#
#CONSOLE_GROUPS         floppy:audio:cdrom

#
# If set to "yes", new passwords will be encrypted using the MD5-based
# algorithm compatible with the one used by recent releases of FreeBSD.
# It supports passwords of unlimited length and longer salt strings.
# Set to "no" if you need to copy encrypted passwords to other systems
# which don't understand the new algorithm.  Default is "no".
#
# This variable is deprecated. You should use ENCRYPT_METHOD.
#
#MD5_CRYPT_ENAB no

#
# If set to MD5 , MD5-based algorithm will be used for encrypting password
# If set to SHA256, SHA256-based algorithm will be used for encrypting password
# If set to SHA512, SHA512-based algorithm will be used for encrypting password
# If set to DES, DES-based algorithm will be used for encrypting password (default)
# Overrides the MD5_CRYPT_ENAB option
#
# Note: It is recommended to use a value consistent with
# the PAM modules configuration.
#
ENCRYPT_METHOD SHA512

#
# Only used if ENCRYPT_METHOD is set to SHA256 or SHA512.
#
# Define the number of SHA rounds.
# With a lot of rounds, it is more difficult to brute forcing the password.
# But note also that it more CPU resources will be needed to authenticate
# users.
#
# If not specified, the libc will choose the default number of rounds (5000).
# The values must be inside the 1000-999999999 range.
# If only one of the MIN or MAX values is set, then this value will be used.
# If MIN > MAX, the highest value will be used.
#
# SHA_CRYPT_MIN_ROUNDS 5000
# SHA_CRYPT_MAX_ROUNDS 5000

################# OBSOLETED BY PAM ##############
#                                               #
# These options are now handled by PAM. Please  #
# edit the appropriate file in /etc/pam.d/ to   #
# enable the equivelants of them.
#
###############

#MOTD_FILE
#DIALUPS_CHECK_ENAB
#LASTLOG_ENAB
#MAIL_CHECK_ENAB
#OBSCURE_CHECKS_ENAB
#PORTTIME_CHECKS_ENAB
#SU_WHEEL_ONLY
#CRACKLIB_DICTPATH
#PASS_CHANGE_TRIES
#PASS_ALWAYS_WARN
#ENVIRON_FILE
#NOLOGINS_FILE
#ISSUE_FILE
PASS_MIN_LEN 9
#PASS_MAX_LEN
#ULIMIT
#ENV_HZ
#CHFN_AUTH
#CHSH_AUTH
#FAIL_DELAY

################# OBSOLETED #######################
#                                                 #
# These options are no more handled by shadow.    #
#                                                 #
# Shadow utilities will display a warning if they #
# still appear.                                   #
#                                                 #
###################################################

# CLOSE_SESSIONS
# LOGIN_STRING
# NO_PASSWORD_CONSOL
eof

else
    if [ $(cat /etc/*-release | grep "CentOS Linux 7" | wc -l) -gt 0 ]; then
        echo 'centos7'
        cat <<eof >/etc/login.defs
#
# Please note that the parameters in this configuration file control the
# behavior of the tools from the shadow-utils component. None of these
# tools uses the PAM mechanism, and the utilities that use PAM (such as the
# passwd command) should therefore be configured elsewhere. Refer to
# /etc/pam.d/system-auth for more information.
#

# *REQUIRED*
#   Directory where mailboxes reside, _or_ name of file, relative to the
#   home directory.  If you _do_ define both, MAIL_DIR takes precedence.
#   QMAIL_DIR is for Qmail
#
#QMAIL_DIR      Maildir
MAIL_DIR        /var/spool/mail
#MAIL_FILE      .mail

# Password aging controls:
#
#       PASS_MAX_DAYS   Maximum number of days a password may be used.
#       PASS_MIN_DAYS   Minimum number of days allowed between password changes.
#       PASS_MIN_LEN    Minimum acceptable password length.
#       PASS_WARN_AGE   Number of days warning given before a password expires.
#
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_MIN_LEN    9
PASS_WARN_AGE   7

#
# Min/max values for automatic uid selection in useradd
#
UID_MIN                  1000
UID_MAX                 60000
# System accounts
SYS_UID_MIN               201
SYS_UID_MAX               999

#
# Min/max values for automatic gid selection in groupadd
#
GID_MIN                  1000
GID_MAX                 60000
# System accounts
SYS_GID_MIN               201
SYS_GID_MAX               999

#
# If defined, this command is run when removing a user.
# It should remove any at/cron/print jobs etc. owned by
# the user to be removed (passed as the first argument).
#
#USERDEL_CMD    /usr/sbin/userdel_local

#
# If useradd should create home directories for users by default
# On RH systems, we do. This option is overridden with the -m flag on
# useradd command line.
#
CREATE_HOME     yes

# The permission mask is initialized to this value. If not specified, 
# the permission mask will be initialized to 022.
UMASK           077

# This enables userdel to remove user groups if no members exist.
#
USERGROUPS_ENAB yes

# Use SHA512 to encrypt password.
ENCRYPT_METHOD SHA512
eof

    else
        if [ $(cat /etc/*-release | grep Rocky | wc -l) -gt 0 ]; then
            echo 'Rocky9'
            authselect enable-feature with-faillock
            sed -i 's/# silent/silent/' /etc/security/faillock.conf
            sed -i 's/# deny = 3/deny = 10/' /etc/security/faillock.conf
            sed -i 's/# unlock_time = 600/unlock_time = 600/' /etc/security/faillock.conf
            sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
            sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs

            if [ $(cat /etc/login.defs | grep "PASS_MIN_LEN   9" | wc -l) -gt 0 ]; then
                echo 'already applied'
            else
                echo -e "PASS_MIN_LEN   9" | sudo tee -a /etc/login.defs
            fi

        else
            echo 'centos6'
            cat <<eof >/etc/login.defs
#
# Please note that the parameters in this configuration file control the
# behavior of the tools from the shadow-utils component. None of these
# tools uses the PAM mechanism, and the utilities that use PAM (such as the
# passwd command) should therefore be configured elsewhere. Refer to
# /etc/pam.d/system-auth for more information.
#

# *REQUIRED*
#   Directory where mailboxes reside, _or_ name of file, relative to the
#   home directory.  If you _do_ define both, MAIL_DIR takes precedence.
#   QMAIL_DIR is for Qmail
#
#QMAIL_DIR      Maildir
MAIL_DIR        /var/spool/mail
#MAIL_FILE      .mail

# Password aging controls:
#
#       PASS_MAX_DAYS   Maximum number of days a password may be used.
#       PASS_MIN_DAYS   Minimum number of days allowed between password changes.
#       PASS_MIN_LEN    Minimum acceptable password length.
#       PASS_WARN_AGE   Number of days warning given before a password expires.
#
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_MIN_LEN    9
PASS_WARN_AGE   7

#
# Min/max values for automatic uid selection in useradd
#
UID_MIN                   500
UID_MAX                 60000

#
# Min/max values for automatic gid selection in groupadd
#
GID_MIN                   500
GID_MAX                 60000

#
# If defined, this command is run when removing a user.
# It should remove any at/cron/print jobs etc. owned by
# the user to be removed (passed as the first argument).
#
#USERDEL_CMD    /usr/sbin/userdel_local

#
# If useradd should create home directories for users by default
# On RH systems, we do. This option is overridden with the -m flag on
# useradd command line.
#
CREATE_HOME     yes

# The permission mask is initialized to this value. If not specified, 
# the permission mask will be initialized to 022.
UMASK           077

# This enables userdel to remove user groups if no members exist.
#
USERGROUPS_ENAB yes

# Use SHA512 to encrypt password.
ENCRYPT_METHOD SHA512
eof

        fi

    fi

fi

# 1.6 패스워드 사용규칙 적용 조치
echo '1.6 패스워드 사용규칙 적용 조치 ubuntu-/etc/pam.d/common-auth, centos7-/etc/pam.d/password-auth'
if grep -Eiq "Ubuntu (18|20)\.04" /etc/issue; then
    echo 'Ubuntu 18.04 or Ubuntu 20.04'
    cat <<eof >/etc/pam.d/common-auth
#
# /etc/pam.d/common-auth - authentication settings common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of the authentication modules that define
# the central authentication scheme for use on the system
# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the
# traditional Unix authentication mechanisms.
#
# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.
# To take advantage of this, it is recommended that you configure any
# local modules either before or after the default block, and use
# pam-auth-update to manage selection of other modules.  See
# pam-auth-update(8) for details.

auth    required                        pam_tally2.so onerr=fail even_deny_root deny=10 unlock_time=600
# here are the per-package modules (the "Primary" block)
auth    [success=1 default=ignore]      pam_unix.so nullok_secure
# here's the fallback if no module succeeds
auth    requisite                       pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
auth    required                        pam_permit.so
# and here are more per-package modules (the "Additional" block)
auth    optional                        pam_cap.so
# end of pam-auth-update config
eof

else
    if grep -Eiq "Ubuntu 22\.04" /etc/issue; then
        echo 'Ubuntu 22.04'
        if grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
            echo 'pam_faillock.so is already configured'
        else
            sed -i '15iauth    required                        pam_faillock.so preauth silent audit deny=10 unlock_time=600' /etc/pam.d/common-auth
            sed -i '18iauth    [default=die]                   pam_faillock.so authfail audit deny=10 unlock_time=600' /etc/pam.d/common-auth
            sed -i '19iauth    sufficient                      pam_faillock.so authsucc audit deny=10 unlock_time=600' /etc/pam.d/common-auth
        fi

    else
        if [ $(cat /etc/*-release | grep "CentOS Linux 7" | wc -l) -gt 0 ]; then
            echo 'centos7'
            cat <<eof >/etc/pam.d/password-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        required      pam_tally2.so deny=10 unlock_time=600
auth        required      pam_faildelay.so delay=2000000
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        required      pam_deny.so

account     required      pam_unix.so
account     required      pam_tally2.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok


password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
eof

        else
            if [ $(cat /etc/*-release | grep -e Final | wc -l) -gt 0 ]; then
                echo 'centos6'
                cat <<eof >/etc/pam.d/password-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        required      pam_tally2.so deny=10 unlock_time=600
auth        sufficient    pam_unix.so try_first_pass nullok
auth        required      pam_deny.so

account     required      pam_unix.so
account     required      pam_tally2.so

password    requisite     pam_cracklib.so try_first_pass retry=3 type=
password    sufficient    pam_unix.so try_first_pass use_authtok nullok sha512 shadow
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
eof

            else
                if [ $(cat /etc/*-release | grep Rocky | wc -l) -gt 0 ]; then
                    echo 'Rocky9'

                else
                    echo 'amzn1'
                    cat <<eof >/etc/pam.d/password-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        required      pam_tally2.so deny=10 unlock_time=600
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet_success
auth        required      pam_deny.so

account     required      pam_unix.so
account     required      pam_tally2.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
eof

                fi

            fi

        fi

    fi

fi

if [ -f /etc/pam.d/common-account ]; then
    echo 'ubuntu'
    if [ $(cat /etc/issue | grep "Ubuntu 18.04.4 LTS" | wc -l) -gt 0 ]; then
        echo 'Ubuntu 18.04.4 LTS'

        if [ $(cat /etc/pam.d/common-account | grep pam_tally2.so | wc -l) -gt 0 ]; then
            echo 'already applied'
        else
            echo 'applying'
            echo 'account required pam_tally2.so' >>/etc/pam.d/common-account
        fi
    elif [ $(cat /etc/issue | grep "Ubuntu 22.04.2 LTS" | wc -l) -gt 0 ]; then
        echo 'Ubuntu 22.04.2 LTS'

        if [ $(cat /etc/pam.d/common-account | grep pam_faillock.so | wc -l) -gt 0 ]; then
            echo 'already applied'
        else
            echo 'applying'
            echo 'account required pam_faillock.so' >>/etc/pam.d/common-account
        fi
    fi
fi

# 1.8 SU 사용 제한 조치
echo '1.8 SU 사용 제한 조치'
if [ $(cat /etc/issue | grep -i "ubuntu" | wc -l) -gt 0 ]; then

    if [ $(cat /etc/pam.d/su | grep use_uid | wc -l) -gt 0 ]; then
        echo 'already applied'
    else
        echo 'ubuntu'
        sed -e '15 i\auth       required   pam_wheel.so use_uid' -i /etc/pam.d/su
    fi

else
    if [ $(cat /etc/*-release | grep "CentOS Linux 7" | wc -l) -gt 0 ]; then
        echo 'centos7'
        cat <<eof >/etc/pam.d/su
#%PAM-1.0
auth            sufficient      pam_rootok.so
# Uncomment the following line to implicitly trust users in the "wheel" group.
#auth           sufficient      pam_wheel.so trust use_uid
# Uncomment the following line to require a user to be in the "wheel" group.
auth            required        pam_wheel.so use_uid
auth            substack        system-auth
auth            include         postlogin
account         sufficient      pam_succeed_if.so uid = 0 use_uid quiet
account         include         system-auth
password        include         system-auth
session         include         system-auth
session         include         postlogin
session         optional        pam_xauth.so
eof
    else
        if [ $(cat /etc/*-release | grep -e Final | wc -l) -gt 0 ]; then
            echo 'centos6'
            cat <<eof >/etc/pam.d/su
#%PAM-1.0
auth            sufficient      pam_rootok.so
# Uncomment the following line to implicitly trust users in the "wheel" group.
#auth           sufficient      pam_wheel.so trust use_uid
# Uncomment the following line to require a user to be in the "wheel" group.
auth            required        pam_wheel.so use_uid
auth            include         system-auth
account         sufficient      pam_succeed_if.so uid = 0 use_uid quiet
account         include         system-auth
password        include         system-auth
session         include         system-auth
session         optional        pam_xauth.so
eof

        else
            if [ $(cat /etc/*-release | grep Rocky | wc -l) -gt 0 ]; then
                echo 'Rocky9'
                sed -e '4 i\auth            required        pam_wheel.so use_uid' -i /etc/pam.d/su

            else
                echo 'amzn1'
                cat <<eof >/etc/pam.d/su
#%PAM-1.0
auth		sufficient	pam_rootok.so
# Uncomment the following line to implicitly trust users in the "wheel" group.
#auth		sufficient	pam_wheel.so trust use_uid
# Uncomment the following line to require a user to be in the "wheel" group.
auth		required	pam_wheel.so use_uid
auth		substack	system-auth
auth		include		postlogin
account		sufficient	pam_succeed_if.so uid = 0 use_uid quiet
account		include		system-auth
password	include		system-auth
session		include		system-auth
session		include		postlogin
session		optional	pam_xauth.so
eof

            fi
        fi
    fi
fi

chmod 4751 /bin/su

# 1.8 wheel 그룹 추가
echo '1.8 wheel 그룹 추가'
if [ $(cat /etc/group | grep wheel | wc -l) -gt 0 ]; then
    echo 'already applied'
    usermod -G wheel JCAdmin
    usermod -G wheel jcadmin
    usermod -G wheel jcadmin01
    usermod -G wheel jcadmin02

else
    echo 'applying'
    addgroup --gid 10 wheel
    usermod -G wheel ubuntu
    usermod -G wheel rocky
    usermod -G wheel ec2-user
    usermod -G wheel centos
    usermod -G wheel JCAdmin
    usermod -G wheel jcadmin
    usermod -G wheel jcadmin01
    usermod -G wheel jcadmin02

fi

# 2.2 SUID, SGID 설정
echo '2.2 SUID, SGID 설정 applying'
chmod -s /sbin/unix_chkpwd
chmod -s /usr/bin/newgrp
chmod -s /sbin/dump
chmod -s /sbin/restore
chmod -s /usr/bin/at

# 2.05 Crontab 파일 권한 설정 및 관리
echo '2.05 Crontab 파일 권한 설정 및 관리'
if [ $(ls -al /scripts | grep drwxr--r-- | wc -l) -gt 0 ]; then
    echo 'already applied'

else
    echo 'applying'
    chmod -R 744 /scripts

fi

# 3.5 'r'command 조치
echo '3.5 'r'command 조치 applying'
chmod -s /usr/bin/newgrp
chmod -s /usr/bin/at

touch /etc/hosts.equiv
chmod 000 /etc/hosts.equiv
touch /root/.rhosts
chmod 000 /root/.rhosts

# 3.8 session timeout 설정 조치
echo '3.8 session timeout 설정 조치'
if [ $(cat /etc/issue | grep -i "ubuntu" | wc -l) -gt 0 ]; then

    if [ $(cat /etc/profile | grep TMOUT | wc -l) -gt 0 ]; then
        echo 'ubuntu'
        echo 'already applied'
    else
        echo 'ubuntu'
        echo 'applying'
        echo "TMOUT=600" | sudo tee -a /etc/profile
    fi

else
    if [ $(cat /etc/profile | grep TMOUT | wc -l) -gt 0 ]; then
        echo 'centos'
        echo 'already applied'
    else
        echo 'centos'
        echo 'applying'
        echo "TMOUT=600" | sudo tee -a /etc/profile
    fi

fi

if [ $(cat /etc/issue | grep -i "ubuntu" | wc -l) -gt 0 ]; then

    if [ $(cat /etc/profile | grep TMOUT=3600 | wc -l) -gt 0 ]; then
        echo 'ubuntu'
        echo 'applying'
        sed -i "s/TMOUT=3600/export TMOUT=600/g" /etc/profile
    fi

else
    if [ $(cat /etc/profile | grep TMOUT=3600 | wc -l) -gt 0 ]; then
        echo 'centos'
        echo 'applying'
        sed -i "s/TMOUT=3600/export TMOUT=600/g" /etc/profile

    else
        echo 'already applied'

    fi

fi

# 3.9 root 계정 telnet, ssh 접근 제한 조치 /etc/pam.d/login
echo '3.9 root 계정 telnet, ssh 접근 제한 조치 /etc/pam.d/login'
if [ $(cat /etc/os-release | grep -i "Rocky Linux 9" | wc -l) -gt 0 ]; then
    echo 'Rocky Linux 9'
elif [ $(cat /etc/issue | grep -i "ubuntu" | wc -l) -gt 0 ]; then
    if [ $(cat /etc/pam.d/login | grep pam_securetty.so | wc -l) -gt 0 ]; then
        echo 'ubuntu'
        echo 'already applied'
    else
        echo 'ubuntu'
        echo 'applying'
        sed -e '32 i\auth [success=ok new_authtok_reqd=ok ignore=ignore user_unknown=bad default=die] pam_securetty.so' -i /etc/pam.d/login
    fi
else
    if [ $(cat /etc/pam.d/login | grep pam_securetty.so | wc -l) -gt 0 ]; then
        echo 'centos'
        echo 'already applied'
    else
        echo 'centos'
        echo 'applying'
        sed -e '2 i\auth [user_unknown=ignore success=ok ignore=ignore default=bad] pam_securetty.so' -i /etc/pam.d/login
    fi
fi

# 3.9 root 계정 telnet, ssh 접근 제한 조치 /etc/ssh/sshd_config
echo '3.9 root 계정 telnet, ssh 접근 제한 조치 /etc/ssh/sshd_config applying'
sed -i "s/#PermitEmptyPasswords/PermitEmptyPasswords/g" /etc/ssh/sshd_config
sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/g" /etc/ssh/sshd_config
sed -i "s/#PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
sed -i "s/#PermitRootLogin no/PermitRootLogin no/g" /etc/ssh/sshd_config
sed -i "s/#PermitRootLogin prohibit-password/PermitRootLogin no/g" /etc/ssh/sshd_config
sed -i "s/#PermitEmptyPasswords no/PermitEmptyPasswords no/g" /etc/ssh/sshd_config

# 4.1 시스템 로그 설정
echo '4.1 시스템 로그 설정'
chmod 640 /etc/rsyslog.conf
chown root:root /etc/rsyslog.conf
chmod 640 /var/log/messages
chown root:root /var/log/messages

if [ $(cat /etc/os-release | grep -i "Rocky Linux 9" | wc -l) -gt 0 ]; then
    echo 'Rocky Linux 9'
elif [ $(cat /etc/issue | grep -i "ubuntu" | wc -l) -gt 0 ]; then
    if [ $(cat /etc/rsyslog.d/50-default.conf | grep "*.notice" | wc -l) -gt 0 ]; then
        echo 'ubuntu'
        echo 'already applied'
    else
        echo 'ubuntu'
        echo 'applying'
        cat >>/etc/rsyslog.d/50-default.conf <<eof

*.notice                /var/log/messages
eof
    fi
else
    if [ $(cat /etc/rsyslog.conf | grep "*.notice" | wc -l) -gt 0 ]; then
        echo 'centos'
        echo "already applied"
    else
        echo 'centos'
        echo "applying"
        cat >>/etc/rsyslog.conf <<eof

*.notice                /var/log/messages
eof
    fi
fi

if [ $(cat /etc/os-release | grep -i "Rocky Linux 9" | wc -l) -gt 0 ]; then
    echo 'Rocky Linux 9'
elif [ $(cat /etc/issue | grep -i "ubuntu" | wc -l) -gt 0 ]; then
    if [ $(cat /etc/rsyslog.d/50-default.conf | grep "*.alert" | wc -l) -gt 0 ]; then
        echo 'ubuntu'
        echo 'already applied'
    else
        echo 'ubuntu'
        echo 'applying'
        echo '*.alert                 /dev/console' >>/etc/rsyslog.d/50-default.conf
    fi
else
    if [ $(cat /etc/rsyslog.conf | grep "*.alert" | wc -l) -gt 0 ]; then
        echo 'centos'
        echo "already applied"
    else
        echo 'centos'
        echo "applying"
        echo '*.alert                 /dev/console' >>/etc/rsyslog.conf
    fi
fi

#CentOS6
# 1.01 Default 계정 삭제 조치
userdel lp
userdel uucp
userdel nuucp
