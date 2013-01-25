#!/usr/bin/perl
use IO::Socket::INET;
use strict;
use warnings;
use feature qw/switch/;

my $port = 4005;
my $socket = IO::Socket::INET->new(LocalPort => $port, Proto => 'udp') or die "CANT CONNECT";
my $recvData = "";
my $interval = "1";	# 30 minute 
my $cai = "9";

my $ARSpduTypes = {
	'0' =>  { DESCRIPTION => "ARS REGISTRATION" },
	'1' =>  { DESCRIPTION => "ARS DEREGISTRATION" },
	'4' =>  { DESCRIPTION => "ARS QUERY" },
	'15' => { DESCRIPTION => "ARS REPLY" } 
}; 

sub decodeARSHeader { 
	print "INCOMING ARS PACKET\n";
	my $packet = $_[0];
	my $packetLength = length($packet);
	if ($packetLength < 2) {
		print "INVALID: PACKET TO SHORT\n";
		return;
	}
	my ($size, $header1) = unpack("nC", $_[0]);
	if (($packetLength-2) != $size) {
		print "INVALID: PACKET SIZE MISMATCH\n";
		return;
	};
	return ($header1 & 15);
}
sub id2ip {
	my $id = $_[0];
	return ($cai.".".(($id >> 16) & 0xff) .'.' . (($id >> 8) & 0xff) . '.' . ($id & 0xff));
}
sub ip2id {
	my ($a, $b, $c, $d) = split(/\./, $_[0]);
	return (($b << 16) + ($c << 8 ) + ($d));
}

sub txARSRegReply {
	my ($id, $interval) = @_;
	my $ip = id2ip($id);
	print "SENDING ACK TO RADIO $id AT $ip WITH ".($interval*30)." MINUTE REFRESH TIME\n";
	my $packet = "\x00\x02\xBF".pack("c",$interval);
	my $txsocket = IO::Socket::INET->new(Proto => 'udp', PeerPort => 4005, PeerAddr => $ip);
	$txsocket->send($packet);
}
sub rxARSRegMsg {
	print "RECIEVED DEVICE REGISTRATION REQUEST\n";
	my ($idLen) = unpack("x4C", $_[0]);
	my $id = unpack("x5a$idLen",$_[0]);
	print "REQUESTING RADIO: $id\n";
	#DO SOMETHING TO DATABASE HERE
	return $id;
};	
sub rxARSDeRegMsg{
	my $id = ip2id($_[0]);
	print "RECIEVED DEVICE DE-REGISTRATION REQUEST\n";
	print "REQUEST FROM $_[0] RADIO ID $id\n";
	#DO SOMETHING TO DATABASE HERE
}
	
sub rxARSQueryReply {
	print "RECIEVED DEVICE QUERY REPLY\n";
	# NEED TO ADD DECODERS
	# DO SOMETHING TO DATABASE
};
sub txARSQuery {
	print "SENDING DEVICE QUERY\n";
	# DO SOMETHING
	# DO SOMETHING WITH DATABASE
}

while (1) {
	$socket->recv($recvData, 1024);
	my $ip = $socket->peerhost;
	my $pdu = decodeARSHeader($recvData);
	given ($pdu){ 
		when (0) {
			my $id = rxARSRegMsg($recvData); 
			txARSRegReply($id, $interval);
		};
		when (1) {
			rxARSDeRegMsg($ip); 
		};
		when (4) {
			rxARSeply($ip); 
		};
	};
};

