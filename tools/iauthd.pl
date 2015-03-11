#!/usr/bin/perl

##############################################
# iauthd for doing DNSBL lookups, implimented in perl. Can be extended easily to also handle LOC/SASL
# 
# Requirements:
#   You need to install some perl dependancies for this to run.
#
#   Debian/ubuntu/mint:
#     apt-get install libpoe-perl libpoe-component-client-dns-perl libterm-readkey-perl libfile-slurp-perl libtime-duration-perl
#   
#   fedora/redhat/centos:
#     yum install perl-POE perl-POE-Component-Client-DNS perl-TermReadKey perl-slurp perl-Time-Duration
#  
#   freebsd:
#     ports dns/p5-POE-Component-Client-DNS devel/p5-Time-Duration devel/p5-File-Slurp devel/p5-Term-ReadKey
#  
#   or via cpan:
#     cpan install Term::ReadKey POE::Component::Client::DNS File::Slurp Time::Duration
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
#IAUTH CACHETIME 86400
#IAUTH BLOCKMSG Sorry! Your connection has been rejected because of your internet address's poor reputation.
#IAUTH DNSBL server=dnsbl.sorbs.net index=2,3,4,5,6,7,9 mark=sorbs block=anonymous
#IAUTH DNSBL server=dnsbl.dronebl.org index=2,3,5,6,7,8,9,10,13,14,15 mark=dronebl block=anonymous
#IAUTH DNSBL server=rbl.efnetrbl.org index=4 mark=tor
#IAUTH DNSBL server=rbl.efnetrbl.org index=1,2,3,5 mark=efnetrbl block=anonymous

#
# ircd.conf:
#
# IAuth {
#    program = "/usr/bin/perl" "iauthd.pl" "-v" "-d" "-c" "ircd.conf";
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

use Time::Duration;

my $DEFAULT_CACHETIME = 60 * 60 * 24;

my $STARTTIME = time();

my $VERSION = "6";

my %clients;
my %dnsbl_cache;

my $count_pass = 0;
my $count_reject = 0;

my %dnsbl_counters;

my $poe_heap;


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

sub poe_print {
    my $str = join(' ', @_);
    if($poe_heap) {
        $poe_heap->{stdio}->put($str);
    }
    else {
        print "$str\n";
    }
}

sub debug {
    my $str = join(' ', @_);
    if($options{'debug'}) {
        poe_print("> :$str");
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

    $poe_heap = $heap;
}

sub poe_stop {
    my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
    poe_print "Doing poe_stop";
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
    elsif($message eq 'e') { #Error: :<aditional text>
        if($args eq 'rehash') {
            debug("Got a rehash. Rereading config file");
            %config = read_configfile($options{'config'});
        }
    }
    elsif($message eq 'M') { #Server name an dcapacity: <servername> <capacity>
    }
    elsif($message eq 'X') { #extension query reply: <servername> <routing> :<reply>
    }
    elsif($message eq 'x') { #extension query reply not linked: <servername> <routing> :Server not online
    }
    elsif($message eq 'W' || $message eq 'w') { #webirc received from client (or W trusted client): <pass> <user> <host> <ip>
        my ($pass, $user, $host, $ip) = split(/ /, $args);
        debug("Got a W line: $source - pass=<notshown>, user=$user, host=$host, ip=$ip");
        if($message eq 'W') { #untrusted ones are ignored TODO: send a kill? (k)
            debug("Got an untrusted WEBIRC attempt. Ignoring.");
        }
        else {
            handle_webirc($kernel, $heap, $source, $pass, $user, $host, $ip);
        }

    }
    else {
        debug("Got unknown message '$message' from server");
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
    handle_dnsbl_response($kernel, $heap, $response->{'host'}, \@result, 0);
}



sub read_configfile {
    my $file = shift;
    my %config;
    my @dnsbls;
    my $cfgnum = 0;
    $config{'dnsbls'} = \@dnsbls;
    $config{'blockmsg'} = "Your internet address has been rejected due to reputation (DNSBL).";
    $config{'cachetime'} = $DEFAULT_CACHETIME;
    debug("Reading $file...");
    send_newconfig();
    poe_print "A * version :Nefarious iauthd.pl $VERSION";
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
                $dnsbl_counters{$dnsblconfig{'cfgnum'}} = 0;
	    }
	    elsif($directive eq 'DEBUG') {
	    	$config{'debug'} = 1;
	    }
            elsif($directive eq 'DNSTIMEOUT') {
                $config{'dnstimeout'} = $args;
            }
            elsif($directive eq 'BLOCKMSG') {
                $config{'blockmsg'} = $args;
            }
            elsif($directive eq 'CACHETIME') {
                $config{'cachetime'} = $args;
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
    poe_print "G 1";
    poe_print "V :Nefarious2 iauthd.pl version $VERSION";

    #TODO: send the config version of this..
    poe_print "O RTAWUwFr";

    #print "a\n";
    #print "s\n";
    debug("Starting up");
    send_stats();
}


sub handle_client {
    my ($kernel, $heap, $source, $ip, $port, $serverip, $serverport) = @_;
    debug("Handling client connect: $source from $ip");

    if(exists $clients{$source}){ #existing entry. 
        debug("ERROR: Found existing entry for client $source (ip=$ip). Something got left hanging? Exiting..");
        exit 1;
    }
    #add client to list
    debug("Adding new entry for client $source (ip=$ip)");
    my $client = { id=>$source, 
                   ip=>$ip, 
                   port=>$port, 
                   serverip=>$serverip, 
                   serverport=>$serverport,
                   whitelist=>0, 
                   block=>0, 
                   marks=>{}, 
                   class=>undef, 
                   hurry=>0,
                   lookups=>{},
                 };
    $clients{$source} = $client;

    if($ip =~ /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/) {
        my $pi = join('.', reverse(split(/\./,$ip)));

        foreach my $dnsbl (@{$config{'dnsbls'}}) {
            my $server = $dnsbl->{'server'};

            #Mark the lookup as pending.. (1)
            $client->{'lookups'}->{$dnsbl->{'cfgnum'}} = 1;
            debug("Looking up client $source: $pi.$server");

            #purge from the cache if it matches...
            if(exists $dnsbl_cache{"$pi.$server"} && exists $dnsbl_cache{"$pi.$server"}->{'ts'} && $dnsbl_cache{"$pi.$server"}->{'ts'} < ( time() - $config{'cachetime'}) ) {
                
                debug("Deleting stale cache entry for $pi.$server");
                delete $dnsbl_cache{"$pi.$server"};
            }

            #Look up in the cache
            if(exists $dnsbl_cache{"$pi.$server"}) { #Found a cache entry
                my $cache_entry = $dnsbl_cache{"$pi.$server"};
                debug("Found dnsbl cache entry for $pi.$server");
                if(defined $cache_entry->{'result'}) { #got a completed lookup in the cache
                    handle_dnsbl_response($kernel, $heap, "$pi.$server", $cache_entry->{'result'}, 1);
                }
                else { #we started looking it up but no reply yet
                    debug("Cache pending... on $pi.$server");
                }
            }
            else { #This lookup is not in the cache yet
                #Adding pending cache entry
                debug("Adding cache entry for pending lookup $pi.$server");
                $dnsbl_cache{"$pi.$server"} = { result=>undef, ts=>time()};

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
        } #each dnsbl
    }
    else {
        debug("Unknown IP format: $ip, probably ipv6 or something... ignoring");
    }
}

sub handle_webirc {
    my ($kernel, $heap, $source, $pass, $user, $newhost, $newip) = @_;

    if(exists $clients{$source}) {
        my $client = $clients{$source};

        #Save some values to recreate the client
        my $port = $client->{'port'};
        my $serverip = $client->{'serverip'};
        my $serverport = $client->{'serverport'};
        my $washurry = $client->{'hurry'};

        #Delete the client record, we need to start over
        client_delete($clients{$source});
        #Create a new client and start fresh
        handle_client($kernel, $heap, $source, $newip, $port, $serverip, $serverport);
        if($washurry) {
            $clients{$source}->{'hurry'} = 1;
        }
    }
    else {
        debug("Got a webirc for a client we don't know about? Ignored.");
    }

}

sub handle_auth {
    my ( $kernel, $heap, $source, $account ) = @_;
    my $client = $clients{$source};

    debug("Client authed as $account");
    $client->{'account'} = $account;
    handle_client_update($client);
}

#Got a DNS reply, or found a cached one.
sub handle_dnsbl_response {
    my ( $kernel, $heap, $host, $results, $iscached ) = @_;
    my $lookup_string;
    #Save the answer in the cache.

    $dnsbl_cache{$host} = { result=>$results, ts=>time()} unless($iscached);

    $host =~ /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.(.+)$/;

    my $host_ip = "$4.$3.$2.$1";
    my $dnsbl_server = "$5";
    debug("Got a DNS reply for $host_ip from $dnsbl_server...");

    #If this result is a hit for any dnsbls, find related clients and mark/block/whitelist etc
    foreach my $ip (@$results) {
        if($ip =~ /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/) {
            my $value = $4;
            #debug("Looking at response value $value from $host");

            foreach my $config_dnsbl (@{$config{'dnsbls'}}) {
                next unless($config_dnsbl->{'server'} eq $dnsbl_server);
                my $flag;
                if(exists $config_dnsbl->{'index'}) {
                    foreach my $index (split(/,/, $config_dnsbl->{'index'})) {
                        if($value eq $index) {
                            $flag++;
                        }
                    }
                }
                if(exists $config_dnsbl->{'bitmask'}) {
                    foreach my $bitmask (split(/,/, $config_dnsbl->{'bitmask'})) {
                        if($bitmask & $value) {
                            $flag++;
                        }
                    }
                }
                if($flag) {
                    #Go through all the client records. Check if this positive dnsbl hit affects them
                    foreach my $client_id (keys %clients) {
                        my $client = $clients{$client_id};
                        if($client->{'ip'} eq $host_ip) {
                            #We found a client in the queue which matches this
                            #dnsbl. Mark them and flag them etc
                            debug("client $client->{id} matches $config_dnsbl->{server} result $value");
                            #$dnsbl_counters{$config_dnsbl->{'cfgnum'}}++;
                            foreach my $field (qw( whitelist block class )) {
                                if($config_dnsbl->{$field}) {
                                    $client->{$field} = $config_dnsbl->{$field};
                                }
                            }
                            if($config_dnsbl->{'mark'}) {
                                $client->{'marks'}->{$config_dnsbl->{'mark'}} = $config_dnsbl;
                            }
                            $client->{'hits'}->{$config_dnsbl->{'cfgnum'}} = 1;
                        } #client matches reply
                    } #each client
                }
                # #each index
            } #each dnsbl

        }
        else {
            debug("Unable to parse dnsbl result: $ip");
        }
    } #foreach @results
    foreach my $client (values %clients) {
        if($client->{'hits'}) {
            foreach my $cfgnum (keys %{$client->{'hits'}}) {
                $dnsbl_counters{$cfgnum}++;
                delete $client->{'hits'};
            }
        }
    }

    #Clear all pending states on all clients with matching ips waiting on any related dnsbls.
    foreach my $dnsbl (@{$config{'dnsbls'}}) {
        if($dnsbl_server eq $dnsbl->{'server'}) {
            foreach my $client (values %clients) {
                if($client->{'ip'} eq $host_ip) {
                    if($client->{'lookups'}->{$dnsbl->{'cfgnum'}}) {
                        $client->{'lookups'}->{$dnsbl->{'cfgnum'}} = 0;
                        handle_client_update($client);
                    }
                }
            }
        }
    }

}

#The client has been updated. Check if its done
sub handle_client_update {
    my $client = shift;
    my $pending = 0;
    foreach my $v (values %{$client->{'lookups'}}) {
        $pending += $v;
    }
    if($client->{'hurry'}) {
        debug("Client $client->{id} has Hurry set and $pending pending requests");
        if($pending < 1) {
            if($client->{'whitelist'}) {
                client_pass($client);
            }
            elsif( ($client->{'block'} eq 'all') 
                   || ($client->{'block'} eq 'anonymous' && !$client->{'account'})) {
                client_reject($client, $config{'blockmsg'});
            }
            else {
                client_pass($client);
            }
        }
    }
    else {
        debug("Client $client->{id} has $pending pending requests");
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
    #print Dumper($client);
    foreach my $mark (keys %{$client->{'marks'}}) {
        send_mark($client->{'id'}, $client->{'ip'}, $client->{'port'}, 'MARK', $mark);
    }
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

    poe_print "m $id $remoteip $remoteport $marktype $markdata";
}

sub send_done {
    my $id = shift;
    my $remoteip = shift;
    my $remoteport = shift;
    my $class = shift;

    if($class) {
        poe_print "D $id $remoteip $remoteport $class";
    }
    else {
        poe_print "D $id $remoteip $remoteport";
    }
}

sub send_kill {
    my $id = shift;
    my $remoteip = shift;
    my $remoteport = shift;
    my $reason = shift;

    poe_print "k $id $remoteip $remoteport :$reason";
}

sub send_newconfig {
    poe_print "a";
}
sub send_config {
    my $config = shift;
    poe_print "A * iauthd.pl :$config";
}

sub send_stats {
    my $up = POSIX::strftime "%a %b %e %H:%M:%S %Y", localtime($STARTTIME);
    my $uptime = duration(time() - $STARTTIME);
    poe_print "s";
    poe_print "S iauthd.pl :Up since $up ($uptime)";
    poe_print "S iauthd.pl :Cache size: ". %dnsbl_cache . "";
    poe_print "S iauthd.pl :Total Passed: $count_pass";
    poe_print "S iauthd.pl :Total Rejected: $count_reject";
    foreach my $config_dnsbl (@{$config{'dnsbls'}}) {
            my $d = $config_dnsbl->{'server'};
            if(exists $config_dnsbl->{'index'}) {
               $d .= " (" . $config_dnsbl->{'index'}. ")";
            }
            if(exists $config_dnsbl->{'bitmask'}) {
               $d .= " (" . $config_dnsbl->{'bitmask'}. ")";
            }
            my $c = 0;
            if( exists $dnsbl_counters{$config_dnsbl->{'cfgnum'}}) {
                $c = $dnsbl_counters{$config_dnsbl->{'cfgnum'}};
            }
            
            poe_print "S iauthd.pl :$d: $c";
    }
}


