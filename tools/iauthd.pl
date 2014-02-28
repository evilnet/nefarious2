#!/usr/bin/perl
#
# iauthd for doing DNSBL lookups, implimented in perl. Can be extended easily to also handle LOC/SASL
# 
# Requirements:
#
# Debian/ubuntu/mint:
# apt-get install libpoe-perl libpoe-component-client-dns-perl libterm-readkey-perl
# 
# fedora/redhat/centos:
# yum install perl-POE perl-POE-Component-Client-DNS perl-TermReadKey
#
# freebsd:
# ports dns/p5-POE-Component-Client-DNS (use cpan for Term::ReadKey)
#
# or via cpan:
# cpan install Term::ReadKey POE::Component::Client::DNS
#
# Installation:
# Copy somewhere convenient
#
# Usage:
# iauth.pl -f /path/to/config
#
# Configuration:
#
# Configuration can piggy back in ircd.conf because # lines are part of the config and ignored by ircd
# 
# example:

#IAUTH POLICY RTAWUwFr
#IAUTH DNSBL server=dnsbl.sorbs.net mask=74 class=loosers mark=sorbs
#IAUTH DNSBL server=dnsbl.ahbl.org index=99,3,14,15,16,17,18,19,20 class=loosers mark=ahbl
#IAUTH DEBUG 0

# 
# Description of config values:
#
#     POLICY: 
#        see docs/readme.iauth section on Set Policy Options
# 
#     DNSBL:
#        bitmask  -  matches if response is true after being bitwise-and'ed with mask
#        index    -  matches if response is exactly index
#        class    -  assigns the user to the named class
#        mark     -  marks the user with the given mark
#        block    -  all - blocks connection if matched
#                    anonymous - blocks connection unless LOC/SASL
#        whitelist- listed users wont be blocked by any rbl            
#
#     DEBUG:      - values greater than 0 turn iauth debugging on in the ircd




use strict;
use warnings;

use POE qw ( Wheel::SocketFactory Wheel::ReadWrite Filter::Line  Driver::SysRW );
use POE::Driver::SysRW;
use POE::Filter::Line;        
use POE::Wheel::ReadWrite;
use POE::Component::Client::DNS;

use Term::ReadKey;

use POSIX;

my $named = POE::Component::Client::DNS->spawn(
    Alias => "named"
);

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

POE::Kernel->run();
exit 0;

sub debug {
    print "DEBUG: ". join(' ', @_). "\n";
}

sub poe_start {
    my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
    #print "Doing poe_start\n";
    print "G 1\n";
    print "V :Rubin\'s iauthd\n";
    print "O RTAWUwFr\n";
    print "a\n";
    print "A * version :Rubin\'s iauthd\n";
    print "s\n";
    print "> :Rubin\'s iauthd is now online\n";

    
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
    print "read a line...... $line\n";
    my @line = split / /, $line;

    my $source = shift @line;
    my $message = shift @line;
    my $args = join(' ', @line);

    print "Parsed source=$source, message=$message\n";

    if($message eq 'C') { #client introduction: <remoteip> <remoteport> <localip> <localport>
        my ($ip, $port, $serverip, $serverport) = split( / /, $args);

        # TODO: store info and begin checking
        handle_client($ip, $port, $serverip, $serverport);

        print "Got a client line. Checking $ip for rbl entries\n";
        my $response = $named->resolve(
            event => "myresponse_event",
            host => $ip,
            context => { },
        );
        if($response) {
            $kernel->yield(response => $response);
        }
    }
    elsif($message eq 'D') { #Client disconnect
    }
    elsif($message eq 'F') { #Client has ssl cert: <fingerprint>
    }
    elsif($message eq 'R') { #Client authed with sasl or loc: <account>
        my $account = $args;
        print "Client authed to account $account\n";
        # TODO: trust client, send an m and D
        handle_auth($account);
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
        # TODO
        # If we have the results, return them
        # D for everything is ok
        # K for bad
        # m for mark
        # otherwise keep waiting
        handle_hurry();
    }
    elsif($message eq 'T') { #Client Registered
    }
    elsif($message eq 'E') { #Error: :<aditional text>
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
        handle_webirc($pass, $user, $host, $ip);  #pass will not be used by us

    }
    else {
        print "Got unknown message '$message' from server\n";
    }
}

sub myerror_event {
    my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
    print "Everything either went to hell or we got to the end.  Shutting down...\n";
    exit 0;
    #delete $heap->{wheels}->{$fileio_uuid};
    $kernel->yield("_stop");
}

sub myresponse_event {
    my ( $kernel, $heap, $response ) = @_[ KERNEL, HEAP, ARG0 ];
    print "Got a response ... \n";
    foreach my $answer ($response->{response}->answer()) {
        print( 
           "$response->{host} = ",
           $answer->type(), " ", 
           $answer->rdatastr(), "\n"
        );
    }
}

POE::Kernel->run();

