#!/usr/bin/perl
use strict;

$ARGV[0] || die("Usage: $0 <file>");

open(IN, '<', $ARGV[0]) || die("Cannot read '$ARGV[0]': $!");
my $header;

my $ok = read IN, $header, 15+4+4;
if(!defined $ok) { die "Cannot read header: $!"; }
if($ok != 15+4+4) { 
	die("Too few bytes in header");
}
my ($magic,$crc,$ver) = unpack("A15 N N",$header);

die "Bad magic" if $magic ne "\x00\xB5\x00mosquitto db";
warn sprintf("l=%d version=%x crc=%d\n", length($magic), $ver, $crc);
die "Unsupported version $ver" unless $ver == 6;

while(1) { 
	my $chunk_header;
	$ok = read IN, $chunk_header, 8;
	die "Cannot read chunk header: $!" unless defined $ok;
	last if $ok == 0;
	die "Too few bytes in chunk header" if $ok != 8;
	my ($type, $len) = unpack("N N", $chunk_header);
	my $data;
	if($type == 1) { # configuration chunk
		$ok = read IN, $data, $len;
		die "Cannot read config chunk data: $!" unless defined $ok;
		die "Too few bytes in config chunk data: $!" unless $ok==$len;
		my ($last_store_id_l, $last_store_id_h, $shutdown, $storeId) = unpack ("N N C C", $data);
		printf "Last store id: %x %x shutdown=%d storeId=%d\n",$last_store_id_l, $last_store_id_h, $shutdown, $storeId;
	} elsif($type == 2) { # message data chunk
		$ok = read IN, $data, 32;
		die "Cannot read message data chunk data: $!" unless defined $ok;
		die "Too few bytes in message data chunk data: $!" unless $ok==32;
		my ($msg_store_id_l, $msg_store_id_h, $expiry_l, $expiry_h, $payload_len, 
		    $source_mid ,$sourceidlen, $sourceuserlen, $topiclen, $sourceport, $quos, $retain) = unpack ("N N N N N n n n n n C C", $data);
				$ok = read IN, $data, $sourceidlen;
		die "Cannot read message data chunk source id: $!" unless defined $ok;
		die "Too few bytes in message data chunk source id: $!" unless $ok==$sourceidlen;
		my $sourceid = $data;

		$ok = read IN, $data, $sourceuserlen;
		die "Cannot read message data chunk username: $!" unless defined $ok;
		die "Too few bytes in message data chunk username: $!" unless $ok==$sourceuserlen;
		my $sourceusername = $data;
		
		$ok = read IN, $data, $topiclen;
		die "Cannot read message data chunk topic: $!" unless defined $ok;
		die "Too few bytes in message data chunk topic: $!" unless $ok==$topiclen;
		my $topic = $data;
		
		$ok = read IN, $data, $payload_len;
		die "Cannot read message data chunk payload: $!" unless defined $ok;
		die "Too few bytes in message data chunk payload: $!" unless $ok==$payload_len;
		my $payload = $data;
		
		my $residual =  $len - (32+ $sourceidlen + $sourceuserlen+ $topiclen + $payload_len);
		if($residual > 0) {
			$ok = read IN, $data, $residual;
			die "Cannot read message data chunk residual: $!" unless defined $ok;
		} elsif($residual<0) { 
			die("Chunk length mismatch");
		}
		printf("Data msg store id: %x %x expiry: %x %x PayloadLen=%d SourceMid=%d SourceIDLen=%d SourceUsernameLen=%d TopicLen=%d SourcePort=%d QoS=%d Retain=%d".
				" srcid=%s srcuser=%s topic=%s payload=%s\n",
		     $msg_store_id_l, $msg_store_id_h, $expiry_l, $expiry_h, $payload_len, 
		    $source_mid ,$sourceidlen, $sourceuserlen, $topiclen, $sourceport, $quos, $retain, $sourceid, $sourceusername, $topic, $payload);
	} elsif($type == 3) { # client message chunk
		$ok = read IN, $data, 16;
		die "Cannot read client data chunk data: $!" unless defined $ok;
		die "Too few bytes in client data chunk data: $!" unless $ok==16;
		my ($msg_store_id_l, $msg_store_id_h, $msgid, $client_id_len, $quos, $state, $retaindup, $direction) = unpack ("N N n n C C C C", $data);
		$ok = read IN, $data, $client_id_len;
		die "Cannot read client data chunk client id: $!" unless defined $ok;
		die "Too few bytes in client data chunk client id: $!" unless $ok==$client_id_len;
		my $client_id = $data;
		printf("Client msg store id %x %x msgid=%d client_id_len=%d QoS=%d state=%d retaindup=%x dir=%x client_id=%s\n",
  			$msg_store_id_l, $msg_store_id_h, $msgid, $client_id_len, $quos, $state, $retaindup, $direction ,$client_id);
		
		my $residual =  $len - (16+ $client_id_len);
		if($residual > 0) {
			$ok = read IN, $data, $residual;
			die "Cannot read client data chunk residual: $!" unless defined $ok;
		} elsif($residual<0) { 
			die("Chunk length mismatch");
		}
	} elsif($type == 4) { # retain message chunk
		$ok = read IN, $data, 8;
		die "Cannot read client data chunk data: $!" unless defined $ok;
		die "Too few bytes in client data chunk data: $!" unless $ok==8;
		my ($store_id_l, $store_id_h) = unpack ("N N", $data);
		printf("Retain msg store id %x %x\n",
  			$store_id_l, $store_id_h);
		
	} elsif($type == 5) { # subscription data chunk
		$ok = read IN, $data, 10;
		die "Cannot read subscription data chunk data: $!" unless defined $ok;
		die "Too few bytes in subscription data chunk data: $!" unless $ok==10;
		my ($id, $client_id_len, $topic_len, $qos, $options) = unpack ("N n n C C", $data);
		
		$ok = read IN, $data, $client_id_len;
		die "Cannot read subscription data chunk client id: $!" unless defined $ok;
		die "Too few bytes in subscription data chunk client id: $!" unless $ok==$client_id_len;
		my $client_id = $data;
		
		$ok = read IN, $data, $topic_len;
		die "Cannot read subscription data chunk topic: $!" unless defined $ok;
		die "Too few bytes ($ok) in subscription data topic: $!" unless $ok==$topic_len;
		my $topic = $data;
		
		printf("Subsciption msg id=%d client_id_len=%d topic_len=%d QoS=%d Options=%x client_id=%d topic=%s\n",
  			$id, $client_id_len, $topic_len, $qos, $options,$client_id);
		
		my $residual =  $len - (10+ $client_id_len+$topic_len);
		if($residual > 0) {
			$ok = read IN, $data, $residual;
			die "Cannot read subscription data chunk residual: ($len, $client_id_len, $topic_len) $!" unless defined $ok;
		} elsif($residual<0) { 
			die("Chunk length mismatch ($len, $client_id_len, $topic_len) ");
		}
	} elsif($type == 6) { # client data chunk
		$ok = read IN, $data, 24;
		die "Cannot read client data chunk data: $!" unless defined $ok;
		die "Too few bytes in client data chunk data: $!" unless $ok==24;
		my ($session_exipiry_l, $session_exipiry_h, $session_exipiry_interval, $lastmid, $client_id_len, $listener_port, $username_len, $padding) 
		   =  unpack ("N N N n n n n N", $data);

		$ok = read IN, $data, $client_id_len;
		die "Cannot read client data chunk client id: $!" unless defined $ok;
		die "Too few bytes in client data chunk client id: $!" unless $ok==$client_id_len;
		my $client_id = $data;

		$ok = read IN, $data, $username_len;
		die "Cannot read client data chunk client id: $!" unless defined $ok;
		die "Too few bytes in client data chunk client id: $!" unless $ok==$username_len;
		my $username = $data;
		
		printf("Client session expiry %d %d interval=%d lastmid=%d client_id_len=%d port=%d username_len=%d client_id=%s username=%s\n",
  			$session_exipiry_l, $session_exipiry_h, $session_exipiry_interval, $lastmid, $client_id_len, $listener_port, $username_len, $client_id, $username);
  			
		my $residual =  $len - (24 + $client_id_len + $username_len);
		if($residual > 0) {
			$ok = read IN, $data, $residual;
			die "Cannot read client data chunk residual: $!" unless defined $ok;
		} elsif($residual<0) { 
			die("Chunk length mismatch");
		}
	    
	} else {
		die "Unsupoported chunk type $type";
	}	
	

}

