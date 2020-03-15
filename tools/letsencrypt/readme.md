==== Lets Encrypt ircd Certificates ====

This directory contains files and notes (in this file) about a proposed
way to use lets-encript ssl certificates. The trouble with LE certificates
that needs to be solved is thus:

  * irc.network.org needs to point (via Route53 or similar) to any
  particular server, and be valid
  * servername.network.org needs to also point to that one server 
  and be valid
  * Servers are run by different admins and those admins don't have
  full trust to dns or website

Jobe has worked out a solution to this, and I am attempting to document
it for others to impliment easier.

The solution is to run an instance of the BIND dns server and
alias the acme lets-encript name to it from the primary domain.
Then in BIND, we setup access to each ircd server to add/remove TXT
entries to it. Each ircd server has its own key with privs that can
be revoked.

In our example we will use network.org as the primary network name
and lechallange.network.org as the subdomain used by BIND

First thing is to setup BIND somewhere. We make bind in charge of
the sub-domain le.network.org, specifically we are interested in adding 
and removing TXT records as: _acme-challenge.le.network.org

Next setup the real network.org dns server. We add a CNAME from 
_acme-challenge.network.org to _acme-challenge.le.network.org and an 
NS record to le.network.org to our BIND server.

Finally, we set up dehydrated, and feed it in the required domain
consisting of: someserver.network.org with SAN of irc.network.org

dehydrated will add a TXT record called _acme-challenge.le.network.org
to BIND.  Lets-encrypt will check _acme-challenge.network.org but will find
the CNAME to _acme-challenge.le.network.org and will follow it. When
complete, dehydrated will remove it again (And anyway, multiple TXT records
can exist and lets-encrypt will find the one it wants)

Finally, dehydrated will copy the files together as needed to create ircd.pem
and send a SIGUSR1 to ircd to reload.

This is a work in progress...


