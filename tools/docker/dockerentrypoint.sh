#!/bin/bash

# Nefarious IRCd Docker Entrypoint
# Reads base.conf-dist, replaces all %VARIABLE% placeholders with environment
# variable values, and writes out base.conf
# Volume permissions are handled by init container in docker-compose

BASECONFDIST=/home/nefarious/ircd/base.conf-dist
BASECONF=/home/nefarious/ircd/base.conf
IRCDPEM=/home/nefarious/ircd/ircd.pem

# Set defaults for required variables (can be overridden by environment)
: "${IRCD_GENERAL_NAME:=localhost.localdomain}"
: "${IRCD_GENERAL_DESCRIPTION:=localhost.localdomain}"
: "${IRCD_ADMIN_LOCATION:=Somewhere}"
: "${IRCD_ADMIN_CONTACT:=root@localhost}"
: "${IRCD_GENERAL_NUMERIC:=1}"

# Copy the template to base.conf location
cp "$BASECONFDIST" "$BASECONF"

# Find all %VARIABLE% placeholders in the config and substitute them
# with corresponding environment variable values
grep -oE '%[A-Za-z_][A-Za-z0-9_]*%' "$BASECONF" | sort -u | while read -r placeholder; do
    # Extract variable name (remove the % signs)
    varname="${placeholder:1:-1}"

    # Get the value from environment (indirect expansion)
    value="${!varname}"

    # Only substitute if the variable is set
    if [ -n "$value" ]; then
        # Escape special characters for sed (/, &, \)
        escaped_value=$(printf '%s\n' "$value" | sed -e 's/[\/&]/\\&/g')
        sed -i "s|${placeholder}|${escaped_value}|g" "$BASECONF"
    else
        echo "Warning: No value set for ${varname}, leaving ${placeholder} unchanged"
    fi
done

echo "Generated $BASECONF from template"

#If cmd is the ircd...
if [ "$1" == "/home/nefarious/bin/ircd" ]; then
    # Generate a pem file if there isnt one...
    if [ ! -f /home/nefarious/ircd/ircd.pem ]; then
        echo "Generating self signed ssl key for ircd.pem"
        openssl req -new --x509 -days 365 -nodes -out ircd.pem -newkey rsa:4096 -keyout ircd.pem -subj "/CN=$IRCD_GENERAL_NAME/"
        test 1 -eq 1 || test ! -f /dev/urandom || openssl gendh -rand $1/ircd.rand 512 >> $1/ircd.pem
        test 1 -eq 1 || test -f /dev/urandom || openssl gendh 512 >> $1/ircd.pem
        openssl x509 -subject -dates -fingerprint -noout -in $IRCDPEM

    fi
fi

# Run CMD from Dockerfile
exec "$@"

