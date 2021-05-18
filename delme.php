<?php

/*
	Program to get IP whois data
*/

$ip = "74.65.112.23";
$ip = "AS32934";
$whois = get_whois($ip);
print $whois;
die();

/**
	Get the whois content of an ip by selecting the correct server
*/
function get_whois($ip)
{
	$w = get_whois_from_server('whois.iana.org' , $ip);

	print "Response: " . PHP_EOL;
	print $w;
	print PHP_EOL;

	preg_match("#whois:\s*([\w.]*)#si" , $w , $data);

	$whois_server = $data[1];

	print "Whois Server: $whois_server " . PHP_EOL;

	// now get actual whois data
	$whois_data = get_whois_from_server($whois_server , $ip);

	return $whois_data;
}

/**
	Get the whois result from a whois server
	return text
*/
function get_whois_from_server($server , $ip)
{
	$data = '';

	// Before connecting lets check whether server alive or not

	$server = trim($server);

	if(!strlen($server))
	{
        print "Blank string provided for server" . PHP_EOL;
        die();
	}

	// Create the socket and connect
	print "Connecting to server $server ...";
	$f = fsockopen($server, 43, $errno, $errstr, 3);	//Open a new connection

	if(!$f)
	{
		print "Failed";
		return false;
	}
	print "Done" . PHP_EOL;

	// Set the timeout limit for read
	if(!stream_set_timeout($f , 3))
	{
		die('Unable to set set_timeout');	#Did this solve the problem ?
	}

	// Send the IP to the whois server
	if($f)
	{
		print "Sending request for ip: $ip" . PHP_EOL;
		$message = $ip . "\r\n";
		fputs($f, $message);
	}

	/*
		Theory : stream_set_timeout must be set after a write and before a read for it to take effect on the read operation
		If it is set before the write then it will have no effect : http://in.php.net/stream_set_timeout
	*/

	// Set the timeout limit for read
	if( !stream_set_timeout($f , 3) )
	{
		die('Unable to stream_set_timeout');	#Did this solve the problem ?
	}

	// Set socket in non-blocking mode
	stream_set_blocking ($f, 0 );

	// If connection still valid
	if($f)
	{
		print "Starting to read socket".PHP_EOL;
		while (!feof($f))
		{
			//print "Read attempt...".PHP_EOL;
			$data .= fread($f , 128);
		}
	}

	// Now return the data
	return $data;
}
