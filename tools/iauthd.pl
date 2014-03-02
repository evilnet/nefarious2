#!/usr/bin/perl

##############################################
# iauthd for doing DNSBL lookups, implimented in perl. Can be extended easily to also handle LOC/SASL
# 
# Requirements:
#   You need to install some perl dependancies for this to run.
#
#   Debian/ubuntu/mint:
#     apt-get install libpoe-perl libpoe-component-client-dns-perl libterm-readkey-perl libfile-slurp-perl
#   
#   fedora/redhat/centos:
#     yum install perl-POE perl-POE-Component-Client-DNS perl-TermReadKey perl-slurp
#  
#   freebsd: TODO: how to add File::Slurp
#     ports dns/p5-POE-Component-Client-DNS
#     (use cpan for Term::ReadKey)
#  
#   or via cpan:
#     cpan install Term::ReadKey POE::Component::Client::DNS File::Slurp
#
# Installation:
#   Copy somewhere convenient
#
# Usage:
#   iauth.pl -f /path/to/config
#
# Configuration:
#
#   * Config directives begin with #IAUTHD and are one per line
#   * Because configuration begins with a #, it can piggy back on existing 
#     ircd.conf file. ircd will ignore it. Handy for those using linesync.
#   * Syntax is: #IAUTHD <directive> <arguments>
# 
# 
# Description of config directives:
#
#     POLICY: 
#        see docs/readme.iauth section on Set Policy Options
# 
#     DNSTIMEOUT:
#          seconds to time out for DNSBL lookups. Default is 5
#
#     DNSBL <key=value [key=value..]>
#        where keys are:
#          server   -  dnsbl server to look up, eg dnsbl.sorbs.net
#          bitmask  -  matches if response is true after being bitwise-and'ed with mask
#          index    -  matches if response is exactly index (comma seperated values ok)
#          class    -  assigns the user to the named class
#          mark     -  marks the user with the given mark
#          block    -  all - blocks connection if matched
#                      anonymous - blocks connection unless LOC/SASL
#          whitelist- listed users wont be blocked by any rbl            
#  
#     DEBUG:      - values greater than 0 turn iauth debugging on in the ircd
#
# Example:

  #IAUTH POLICY RTAWUwFr
  #IAUTH DNSBL server=dnsbl.sorbs.net mask=74 class=loosers mark=sorbs
  #IAUTH DNSBL server=dnsbl.ahbl.org index=99,3,14,15,16,17,18,19,20 class=loosers mark=ahbl
  #IAUTH DEBUG 0

#
# ircd.conf:
#
# IAuth {
#    program = "/usr/bin/perl" "/home/rubin/afternet/nef2/nefarious2/tools/iauthd.pl" "-v" "-c" "/home/rubin/afternet/nef2/lib/ircd.conf" "-d";
# };
#
# Debugging:
#  * oper up first
#  * set snomask /quote mode yournick +s 262144
#
########################3

=head1 NAME

iauthd.pl - a perl based iauthd daemon supporting DNSBL lookups

=head1 SYNOPSIS

iauthd.pl [options] --config=configfile.conf

    Options: (short)
    --help    (-h)    Print this message
    --config  (-c)    Config file to read
    --debug   (-d)    Turn on debugging in the ircd
    --verbose (-v)    Turn on debugging in iauthd

=cut

use strict;
use warnings;

use Getopt::Long;
use Pod::Usage;

use POE qw ( Wheel::SocketFactory Wheel::ReadWrite Filter::Line  Driver::SysRW );
use POE::Driver::SysRW;
use POE::Filter::Line;        
use POE::Wheel::ReadWrite;
use POE::Component::Client::DNS;

use Term::ReadKey;
use POSIX;
use File::Slurp;
use Data::Dumper;

my %clients;
my %dnsbl_cache;

my $count_pass = 0;
my $count_reject = 0;


my %options;
GetOptions( \%options, 'help', 'config:s', 'debug', 'verbose') or confess("Error");

pod2usage(1) if ($options{'help'} or !$options{'config'});

my %config = read_configfile($options{'config'});

my $named = POE::Component::Client::DNS->spawn(
    Alias => "named",
    Timeout => ($config{'dnstimeout'} ? $config{'dnstimeout'} : 5)
);

# Create the POE object with callbacks
POE::Session->create (
  inline_states => {
   _start => \&poe_start,
   #_stop  => \&poe_stop,
   myinput_event => \&myinput_event,
   myerror_event => \&myerror_event,
   myint_event => \&myint_event,
   myresponse_event => \&myresponse_event,
  }
);

# Start the event loop
POE::Kernel->run();
exit 0;


#####
#
# Subs
#
#####

sub debug {
    my $str = join(' ', @_);
    if($options{'debug'}) {
        print "> :iauthd.pl: $str\n";
    }
}

sub poe_start {
    my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
    
    handle_startup();
    
    # Start the terminal reader/writer.
    $heap->{stdio} = POE::Wheel::ReadWrite->new (
        InputHandle => \*STDIN,
        OutputHandle => \*STDOUT,
        InputEvent => "myinput_event",
        Filter => POE::Filter::Line->new(),
        ErrorEvent => "myerror_event",
    );
    $kernel->sig(INT => "myint_event");
}

sub poe_stop {
    my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
    print "Doing poe_stop\n";
    #$kernel->alias_remove($fileio_uuid);
}

sub myinput_event {
    my ( $kernel, $heap, $line ) = @_[ KERNEL, HEAP, ARG0 ];
    #debug("read a line...... '$line'");
    return unless($line);

    my @line = split / /, $line;

    my $source = shift @line;
    my $message = shift @line;
    my $args = join(' ', @line);

    return unless(defined $message);

    # warning, this one can contain passwords...
    #debug("<-- $line");

    #print "Parsed source=$source, message=$message\n";
    if($message eq 'C') { #client introduction: <remoteip> <remoteport> <localip> <localport>
        my ($ip, $port, $serverip, $serverport) = split( / /, $args);

        if(!defined $ip) {
            debug("Got a C without a valid IP. Ignoring");
            return;
        }
        handle_client($kernel, $heap, $source, $ip, $port, $serverip, $serverport);
    }
    elsif($message eq 'D') { #Client disconnect
        debug("Client $source disconnected.");
        if(exists $clients{$source}) {
            client_delete($clients{$source});
        }
    }
    elsif($message eq 'F') { #Client has ssl cert: <fingerprint>
    }
    elsif($message eq 'R') { #Client authed with sasl or loc: <account>
        my $account = $args;
        handle_auth($kernel, $heap, $source, $account);
    }
    elsif($message eq 'N') { #hostname received: <hostname>
    }
    elsif($message eq 'd') { #hostname timed out
    }
    elsif($message eq 'P') { #Client Password: :<password>
    }
    elsif($message eq 'U') { #client username: <username> <hostname> <servername> :<user info ...>
    }
    elsif($message eq 'u') { #client username: <username>
    }
    elsif($message eq 'n') { #client nickname: <nickname>
    }
    elsif($message eq 'H') { #Hurry up: <class>
        handle_hurry($source, $args);
    }
    elsif($message eq 'T') { #Client Registered
    }
    elsif($message eq 'E') { #Error: :<aditional text>
        debug("ircd complaining of error: $args");
    }
    elsif($message eq 'M') { #Server name an dcapacity: <servername> <capacity>
    }
    elsif($message eq 'X') { #extension query reply: <servername> <routing> :<reply>
    }
    elsif($message eq 'x') { #extension query reply not linked: <servername> <routing> :Server not online
    }
    elsif($message eq 'W' || $message eq 'w') { #webirc received from client (or W trusted client): <pass> <user> <host> <ip>
        my ($pass, $user, $host, $ip) = split(/ /, $args);
        print "Got a W line: pass=<notshown>, user=$user, host=$host, ip=$ip\n";
        return if($message eq 'W'); #untrusted ones are ignored TODO: send a kill? (k)

        # TODO: abort/ignore previous check, start checking this new IP
        handle_webirc($kernel, $heap, $source, $pass, $user, $host, $ip);

    }
    else {
        print "Got unknown message '$message' from server\n";
    }
}

sub myerror_event {
    my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
    debug("Everything either went to hell or we got to the end.  Shutting down...");
    exit 0;
    #delete $heap->{wheels}->{$fileio_uuid};
    $kernel->yield("_stop");
}

sub myresponse_event {
    my ( $kernel, $heap, $response ) = @_[ KERNEL, HEAP, ARG0 ];
    #debug("Got a response ... ");
    my @result;
    if(!defined $response->{response}) {
        debug("got an empty response.. probably a timeout");
    }
    else {
        foreach my $answer ($response->{response}->answer()) {
            debug( 
               "$response->{host} = ",
               $answer->type(), " ", 
               $answer->rdatastr(),
            );
            push @result, $answer->rdatastr();
        }
    }
    handle_dnsbl_response($kernel, $heap, $response->{'host'}, \@result);
}



sub read_configfile {
    my $file = shift;
    my %config;
    my @dnsbls;
    my $cfgnum = 0;
    $config{'dnsbls'} = \@dnsbls;
    debug("Reading $file...");
    send_newconfig();
    foreach my $line (read_file($file)) {
        chomp $line;
    	if($line =~ /^\#IAUTH\s(\w+)(\s+(.+))?/) {
	    my $directive = $1;
	    my $args = $3;
            $cfgnum++;
            send_config("$cfgnum: $directive $args");
            #debug("Got a config line: $line");
	    #debug("    directive is $directive");
	    #debug("    arg is $args");
            if($directive eq 'POLICY') {
                $config{'policy'} = $args;
            }
	    elsif($directive eq 'DNSBL') {
	    	my %dnsblconfig;
		foreach my $arg (split /\s+/, $args) {
		    if($arg =~ /(\w+)\=(.+)/) { #key=val pair
                        my $k = $1;
                        my $v = $2;
                        $dnsblconfig{$k} = $v;
                    }
                    else {
                        $dnsblconfig{$arg} = 1;
                    }
		}
                $dnsblconfig{'cfgnum'} = $cfgnum;
                push @dnsbls, \%dnsblconfig;
	    }
	    elsif($directive eq 'DEBUG') {
	    	$config{'debug'} = 1;
	    }
            elsif($directive eq 'DNSTIMEOUT') {
                $config{'dnstimeout'} = $args;
            }
            else {
                debug("Unknown IAUTH directive '$directive'");
            }
        }
    }
    #print Dumper(\%config);
    return %config;
}

sub handle_startup {
    print "G 1\n";
    print "V :Nefarious2 iauthd.pl\n";

    #TODO: send the config version of this..
    print "O RTAWUwFr\n";

    #print "a\n";
    #print "A * version :Nefarious iauthd.pl\n";
    #print "s\n";
    debug("Starting up");
}


sub handle_client {
    my ($kernel, $heap, $source, $ip, $port, $serverip, $serverport) = @_;
    debug("Handling client connect: $source from $ip");

    if(exists $clients{$source}){ #existing entry. 
        debug("ERROR: Found existing entry for client $source (ip=$ip). Something got left hanging? Exiting..");
        exit 1;
    }
    else {
        #add client to list
        debug("Adding new entry for client $source (ip=$ip)");
        my $client = { id=>$source, ip=>$ip, port=>$port, serverip=>$serverip, serverport=>$serverport,
                       whitelist=>0, block=>0, mark=>undef, class=>undef, pending_lookups=>0, hurry=>0};
        $clients{$source} = $client;
    }

    if($ip =~ /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/) {
        my $pi = join('.', reverse(split(/\./,$ip)));
        #debug("Converted $ip to $pi");

        my %handle_cached_responses;
        foreach my $dnsbl (@{$config{'dnsbls'}}) {
            my $server = $dnsbl->{'server'};
            $clients{$source}->{'pending_lookups'}++;
            debug("Looking up client $source: $pi.$server now ". $clients{$source}->{'pending_lookups'} . " left");

            if(exists $dnsbl_cache{"$pi.$server"}) { #Found a cache entry
                my $cache_entry = $dnsbl_cache{"$pi.$server"};
                debug("Found dnsbl cache entry for $pi.$server");
                if(defined $cache_entry) { #got a completed lookup in the cache
                    #Instead of calling handle_dnsbl_response here we
                    #save and de-duplicate them, to be executed below
                    $handle_cached_responses{"$pi.$server"} = $cache_entry;
                }
                else { #we started looking it up but no reply yet
                    debug("Cache pending... on $pi.$server");
                }
            }
            else { #This lookup is not in the cache yet
                #debug("Adding cache entry for $pi.$server");
                $dnsbl_cache{"$pi.$server"} = undef;

                #Begin a POE lookup on the dnsbl
                my $response = $named->resolve(
                    event => "myresponse_event",
                    host => "$pi.$server",
                    context => { },
                );
                if($response) {
                    $kernel->yield(response => $response);
                }
            }
        }

        #handle response for each unique cache result we found
        foreach my $k (keys %handle_cached_responses) {
            handle_dnsbl_response($kernel, $heap, $k, $handle_cached_responses{$k});
        }
    }
    else {
        debug("Unknown IP format: $ip, probably ipv6 or something... ignoring");
    }
}

sub handle_webirc {
    my ($kernel, $heap, $source, $pass, $user, $newhost, $newip);

    my $client = $clients{$source};

    #Save some values to recreate the client
    my $port = $client->{'port'};
    my $serverip = $client->{'serverip'};
    my $serverport = $client->{'serverport'};

    #Delete the client record, we need to start over
    delete_client($clients{$source});

    #Create a new client and start fresh
    handle_client($kernel, $heap, $source, $newip, $port, $serverip, $serverport);
}

sub handle_auth {
    my ( $kernel, $heap, $source, $account ) = @_;
    my $client = $clients{$source};

    debug("Client authed as $account");
    $client->{'account'} = $account;
    handle_client_update($client);
}

sub handle_dnsbl_response {
    my ( $kernel, $heap, $host, $results ) = @_;
    my $lookup_string;
    #Save the answer in the cache.
    $dnsbl_cache{$host} = $results;

    $host =~ /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.(.+)$/;

    my $host_ip = "$4.$3.$2.$1";
    my $dnsbl = "$5";
    debug("Got a DNS reply for $host_ip from $dnsbl...");

    if(@$results < 1) {
        #Negative result. Update any affected clients
        foreach my $client_id (keys %clients) {
            my $client = $clients{$client_id};
            next unless($client->{'ip'} eq $host_ip);

            #For every dnsbl that uses this replies dnsbl server...
            foreach my $config_dnsbl (@{$config{'dnsbls'}}) {
                 next unless($config_dnsbl->{'server'} eq $dnsbl);

                 $client->{'pending_lookups'}--;
                 debug("Decrementing client $client_id lookups due to negative result ($dnsbl:$config_dnsbl->{cfgnum}). Now ". $client->{'pending_lookups'} . " left");

                 handle_client_update($client);
            }
        }
    }

    my %lookups;
    foreach my $ip (@$results) {
        if($ip =~ /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/) {
            my $value = $4;
            #debug("Looking at response value $value from $host");

            foreach my $config_dnsbl (@{$config{'dnsbls'}}) {
                next unless($config_dnsbl->{'server'} eq $dnsbl);
                foreach my $index (split(/,/, $config_dnsbl->{'index'})) {
                    if($value eq $index) {
                        #Go through all the client records. Check if this positive dnsbl hit affects them
                        foreach my $client_id (keys %clients) {
                            my $client = $clients{$client_id};
                            if($client->{'ip'} eq $host_ip) {
                                #We found a client in the queue which matches this
                                #dnsbl. Mark them and flag them etc
                                debug("client $client->{id} matches $config_dnsbl->{server} result $value");
                                foreach my $field (qw( whitelist mark block class )) {
                                    if($config_dnsbl->{$field}) {
                                        $client->{$field} = $config_dnsbl->{$field};
                                    }
                                }
                                
                                #Record the hit in a de-duplicated way
                                #debug("Marking $client->{id} $config_dnsbl->{server}");
                                $lookups{$client->{'id'}.$config_dnsbl->{'server'}.':'.$config_dnsbl->{'cfgnum'}} = $client;
                            } #client matches reply
                        } #each client
                    }
                } #each index
            } #each dnsbl

        }
        else {
            debug("Unable to parse dnsbl result: $ip");
        }
    } #foreach @results

    #Now go through each client we found and record the hit
    foreach my $client (values %lookups) {
        $client->{'pending_lookups'}--;
        debug("Decrementing pending lookup for client " . $client->{'id'}. " now ". $client->{'pending_lookups'} . "lookups left");
        handle_client_update($client);
    }
}

#The client has been updated. Check if its done
sub handle_client_update {
    my $client = shift;
    if($client->{'hurry'}) {
        debug("Client $client->{id} has Hurry set");
        if($client->{'pending_lookups'} < 1) {
            debug("Client has no pending dnsbl lookups");
            if($client->{'whitelist'}) {
                client_pass($client);
            }
            elsif( ($client->{'block'} eq 'all') 
                   || ($client->{'block'} eq 'anonymous' && !$client->{'account'})) {
                client_reject($client, "You match one or more DNSBL lists");
            }
            else {
                client_pass($client);
            }
        }
    }
}

sub handle_hurry {
    my $source = shift;
    my $class = shift;
    my $client = $clients{$source};

    if(!$client) {
        debug("ERROR: Got a hurry for a client we arent even holding on to!");
        return;
    }
    debug("Handling a hurry on $source");

    $client->{'hurry'} = 1;
    handle_client_update($client);
}

sub client_pass {
    my $client = shift;
    debug("Passing client ". $client->{'id'} . ' ('. $client->{'ip'} . ')');
    send_mark($client->{'id'}, $client->{'ip'}, $client->{'port'}, 'MARK', $client->{'mark'});
    send_done($client->{'id'}, $client->{'ip'}, $client->{'port'}, $client->{'class'}?$client->{'class'}:undef);
    $count_pass++;
    client_delete($client);
    send_stats();
}

sub client_reject {
    my $client = shift;
    my $reason = shift;
    debug("Rejecting client " . $client->{'id'} . ' ('. $client->{'ip'} . "): $reason");
    send_kill($client->{'id'}, $client->{'ip'}, $client->{'port'}, $reason);
    $count_reject++;
    client_delete($client);
    send_stats();
}

sub client_delete {
    my $client = shift;
    debug("Deleting client from hash tables");
    delete($clients{$client->{'id'}});
}

sub send_mark {
    my $id = shift;
    my $remoteip = shift;
    my $remoteport = shift;
    my $marktype = shift;
    my $markdata = shift;

    return unless($markdata);

    print "m $id $remoteip $remoteport $marktype $markdata\n";
}

sub send_done {
    my $id = shift;
    my $remoteip = shift;
    my $remoteport = shift;
    my $class = shift;

    if($class) {
        print "D $id $remoteip $remoteport $class\n";
    }
    else {
        print "D $id $remoteip $remoteport\n";
    }
}

sub send_kill {
    my $id = shift;
    my $remoteip = shift;
    my $remoteport = shift;
    my $reason = shift;


    print "k $id $remoteip $remoteport :$reason\n";
}

sub send_newconfig {
    print "a\n";
}
sub send_config {
    my $config = shift;
    print "A * iauthd.pl :$config\n";
}

sub send_stats {
    print "s\n";
    print "S iauthd.pl :Passed $count_pass\n";
    print "S iauthd.pl :Rejected $count_reject\n";
}


