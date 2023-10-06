#!/bin/bash

# Apply ENV to ircd.conf
# ...

BASECONFDIST=/home/nefarious/ircd/base.conf-dist
BASECONF=/home/nefarious/ircd/base.conf
IRCDPEM=/home/nefarious/ircd/ircd.pem

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


#Copy the template to base.conf location
cp $BASECONFDIST $BASECONF

#Modify base.conf template with env variables
sed -i "s/%IRCD_GENERAL_NAME%/${IRCD_GENERAL_NAME}/g" $BASECONF
sed -i "s/%IRCD_GENERAL_DESCRIPTION%/${IRCD_GENERAL_DESCRIPTION}/g" $BASECONF
sed -i "s/%IRCD_GENERAL_NUMERIC%/${IRCD_GENERAL_NUMERIC}/g" $BASECONF
sed -i "s/%IRCD_ADMIN_LOCATION%/${IRCD_ADMIN_LOCATION}/g" $BASECONF
sed -i "s/%IRCD_ADMIN_CONTACT%/${IRCD_ADMIN_CONTACT}/g" $BASECONF

# Generate a pem file if there isnt one...
ls -l /home/nefarious/ircd/
if [ ! -f /home/nefarious/ircd/ircd.pem ]; then
    echo "Generating self signed ssl key for ircd.pem"
    openssl req -new --x509 -days 365 -nodes -out ircd.pem -newkey rsa:4096 -keyout ircd.pem -subj "/CN=$IRCD_GENERAL_NAME/"
    #test 1 -eq 1 || test ! -f /dev/urandom || openssl gendh -rand $1/ircd.rand 512 >> $1/ircd.pem
    #test 1 -eq 1 || test -f /dev/urandom || openssl gendh 512 >> $1/ircd.pem
    openssl x509 -subject -dates -fingerprint -noout -in $IRCDPEM

fi

#Now run CMD from Dockerfile...
exec "$@"

