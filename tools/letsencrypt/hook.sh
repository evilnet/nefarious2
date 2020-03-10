#!/usr/bin/env bash

NSUPDATE="nsupdate -k /home/alpha/dehydrated/nsupdate.key"
NSSERVER="127.0.0.1"
ZONE="le.example.net"
IRCDPEM="/home/alpha/ircd/lib/ircd.pem"
IRCDPID="/home/alpha/ircd/lib/ircd.pid"

deploy_challenge() {
    local nsudttxt="server ${DNSSERVER}\nzone ${ZONE}.\n"

    declare -a args=("$@")

    for i in `seq 0 3 $(($#-1))`;
    do
        local DOMAIN="${args[$i]}" TOKEN_FILENAME="${args[$(($i+1))]}" TOKEN_VALUE="${args[$(($i+2))]}"
        nsudttxt="${nsudttxt}update add _acme-challenge.${DOMAIN}.${ZONE}. 300 IN TXT \"${TOKEN_VALUE}\"\n"
        printf "ADD: _acme-challenge.%s.%s. 300 IN TXT \"%s\"\n" "${DOMAIN}" "${ZONE}" "${TOKEN_VALUE}"
    done

    nsudttxt="${nsudttxt}send\n"

    echo -e "${nsudttxt}" | $NSUPDATE

    /bin/sleep 0.5
}

clean_challenge() {
    local nsudttxt="server ${DNSSERVER}\nzone ${ZONE}.\n"

    declare -a args=("$@")

    for i in `seq 0 3 $(($#-1))`;
    do
        local DOMAIN="${args[$i]}" TOKEN_FILENAME="${args[$(($i+1))]}" TOKEN_VALUE="${args[$(($i+2))]}"
        nsudttxt="${nsudttxt}update del _acme-challenge.${DOMAIN}.${ZONE}. 300 IN TXT \"${TOKEN_VALUE}\"\n"
        printf "DEL: _acme-challenge.%s.%s. 300 IN TXT \"%s\"\n" "${DOMAIN}" "${ZONE}" "${TOKEN_VALUE}"
    done

    nsudttxt="${nsudttxt}send\n"

    echo -e "${nsudttxt}" | $NSUPDATE

    /bin/sleep 0.5
}

deploy_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}" TIMESTAMP="${6}"

    cat $KEYFILE > $IRCDPEM
    cat $FULLCHAINFILE >> $IRCDPEM
    kill -USR1 `cat $IRCDPID`
}

HANDLER="$1"; shift
if [[ "${HANDLER}" =~ ^(deploy_challenge|clean_challenge|deploy_cert)$ ]]; then
    "$HANDLER" "$@"
fi
