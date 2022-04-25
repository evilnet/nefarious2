#!/bin/bash

# If you put comments n your ircd.conf like this:
#
# SERVER foo.afternet.org
#
# then this script can parse those out and look up their IPs and add
# them to an icinga config file.
#

SRVLIST=/tmp/servers.txt
DATAFILE=/path/to/your/linesync/linesync.data

ICINGAFILE=/tmp/afternet_hosts.conf

# Run linesync


# Use linesync.data to get a server list

grep '# SERVER' "$DATAFILE" |awk '{print $3}' > "$SRVLIST"

while read servername; do
  echo "I got $servername"
  ip4=`host -t A "$servername"|awk '{print $4}'|grep -P '[0-9.]+'`
  ip6=`host -t AAAA "$servername"|awk '{print $5}'|grep -P '[0-9:]+'`

  echo "object Host \"$servername\" {" >> $ICINGAFILE
  echo "  import \"afternet-host\"" >> $ICINGAFILE

  if [ x"${ip4}" != "x" ]; then
      echo "  address = \"$ip4\"" >> $ICINGAFILE
  fi

  if [ x"${ip6}" != "x" ]; then
      echo "  address6 = \"$ip6\"" >> $ICINGAFILE
  fi

  echo "}" >> $ICINGAFILE

done < "$SRVLIST"

echo "Saved icinga config to $ICINGAFILE"

