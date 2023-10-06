#!/bin/bash

# Apply ENV to ircd.conf
# ...

IRCDCONF=/home/nefarious/ircd/ircd.conf
IRCDPEM=/home/nefarious/ircd/ircd.pem

cp /home/nefarious/ircd/base.conf /home/nefarious/ircd/ircd.conf

if [ -z "${IRCD_GENERAL_NAME}" ]; then
        IRCD_GENERAL_NAME="localhost.localdomain"
fi
if [ -z "${IRCD_GENERAL_DESCRIPTION}" ]; then
        IRCD_GENERAL_DESCRIPTION="localhost.localdomain"
fi
if [ -z "${IRCD_ADMIN_LOCATION}" ]; then
        IRCD_ADMIN_LOCATION="Somewhere"
fi

if [ -z "${IRCD_ADMIN_CONTACT}" ]; then
        IRCD_ADMIN_CONTACT="root@localhost"
fi

if [ -z "${IRCD_GENERAL_NUMERIC}" ]; then
        IRCD_GENERAL_NUMERIC=1
fi


# phpLDAPadmin config
sed -i "s/%IRCD_GENERAL_NAME%/${IRCD_GENERAL_NAME}/g" $IRCDCONF
sed -i "s/%IRCD_GENERAL_DESCRIPTION%/${IRCD_GENERAL_DESCRIPTION}/g" $IRCDCONF
sed -i "s/%IRCD_GENERAL_NUMERIC%/${IRCD_GENERAL_NUMERIC}/g" $IRCDCONF
sed -i "s/%IRCD_ADMIN_LOCATION%/${IRCD_ADMIN_LOCATION}/g" $IRCDCONF
sed -i "s/%IRCD_ADMIN_CONTACT%/${IRCD_ADMIN_CONTACT}/g" $IRCDCONF

# Generate a pem file if there isnt one...
if [ ! -f /home/nefarious/ircd/ircd.pem ]; then
    echo "Generating self signed ssl key for ircd.pem"
    openssl req -new --x509 -days 365 -nodes -out ircd.pem -newkey rsa:4096 -keyout ircd.pem -subj "/CN=$IRCD_GENERAL_NAME/"
    #test 1 -eq 1 || test ! -f /dev/urandom || openssl gendh -rand $1/ircd.rand 512 >> $1/ircd.pem
    #test 1 -eq 1 || test -f /dev/urandom || openssl gendh 512 >> $1/ircd.pem
    openssl x509 -subject -dates -fingerprint -noout -in $IRCDPEM

fi


#Now run CMD from Dockerfile...
exec "$@"

