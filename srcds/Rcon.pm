package Rcon;

use strict;
use IO::Socket::INET;
use IO::Select;

##########################
# Base RCON functions 
##########################
#
# http://css.setti.info/downloads/munin-srcds-plugin/
#
# Functions:
# sock_connect
#  + Opens TCP connection to a server.
# sock_receive
#  + Receives RCON reply from a server.
# rcon_auth
#  + Sends RCON password to a server and authorizes the connection.
# rcon_command
#  + Executes RCON command on a server.
# print_data
#  + Prints any string as HEX format. This is for debugging.

#
# Open socket connection to a server
#
sub sock_connect ($$) {
    my ($ip, $port) = @_;
    my $sock = new IO::Socket::INET (
				     PeerAddr => $ip,
				     PeerPort => $port,
				     Proto => 'tcp'
				     );
    return $sock;
}

#
# Receive data from a socket
#
# The function reads all data from a socket, and parses the actual message
# from the packet data contents.
#
sub sock_receive ($$) {
    my ($sock, $req_id) = @_;
    # I/O handle to lookup if there's data
    my $can_read = new IO::Select($sock);
    my $buffer;
    my ($size, $request_id, $command_response, $data);
    while ($can_read->can_read(0.1)) {
	$sock->recv($buffer, 4, MSG_PEEK); # Peek size field (32b int)
	$size = unpack('V', $buffer); # Convert bytes to int
	last if (!defined($size));
	$sock->recv($buffer, $size+4, MSG_WAITALL); # Read the whole packet
	($size, $request_id, $command_response, $data) =
	    unpack('VVVZ*x', $buffer); # Convert values from the packet
        if (($size > 10 || $command_response == 2) && $req_id == $request_id) { # SPEED-HACK
            return ($data, $request_id, $command_response);
        }
    }
    return ($data, $request_id, $command_response);
}

#
# Authorize RCON connection
#
# The function tries to authenticate opened RCON connection. Returns 1 if
# the authorization succeeded or 0 otherwise.
#
sub rcon_auth ($$) {
    my ($sock, $rcon_pass) = @_;
    return undef unless ($sock);
    # Packet format:
    # len (32b int),
    # requestid (32b int),
    # command code (32b int),
    # string (ASCIIZ),
    # null byte

    # command code: 3 = auth, 2 = command
    my $request_id = int(rand()*1000000);
    my $msg = pack('VVVZ*x',
		   10+length($rcon_pass),
		   $request_id,
		   3,
		   $rcon_pass);
    print $sock $msg;
    my ($reply, $request_id_r, $command_response) = sock_receive($sock, $request_id);
    return (defined($request_id_r) && $request_id == $request_id_r);
}

#
# Execute RCON command
#
# Returns server reply to the RCON command, or undefined value if the RCON
# connection wasn't authenticated properly or the connection timeouted.
#
sub rcon_command ($$) {
    my ($sock, $data) = @_;
    # Packet format same as in rcon_auth
    my $request_id = int(rand()*1000000);
    my $msg = pack('VVVZ*x',
		   10+length($data),
		   $request_id,
		   2,
		   $data);
    print $sock $msg;
    my ($reply, $request_id_r, $command_response) = sock_receive($sock, $request_id);
    return undef if (!defined($command_response) || $command_response != 0);
    return $reply;
}

#
# Debug TCP packet
#
sub print_data ($) {
    my $data = shift;
    my @hexdata = split('',unpack('H*', $data));

    print " === REPLY (ascii) ===\n";
    print "\"$data\"\n";
    print " === REPLY (hex) ===\n";

    for my $i (0 .. $#hexdata) {
	if ($i > 0 && $i % 32 == 0) {
	    print "\n";
	}
	elsif ($i > 0 && $i % 16 == 0) {
	    print "   ";
	}
	elsif ($i > 0 && $i % 2 == 0) {
	    print " ";
	}
	print "$hexdata[$i]";
    }
    print "\n\n";
}

1;
