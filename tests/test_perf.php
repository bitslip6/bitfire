<?php declare(strict_types=1);

function test_basic_request() {
    $_SERVER = full_server();
    $_GET = array('one_param' => 'a parameter with some data', 'two_param' => 'another parameter value', 'three_param' => 012, 'four_paraam' => 12391);
    $s0 = microtime(true);
    $bitfire = \Bitfire\BitFire::get_instance(); 
    $bitfire->inspect();
    $s1 = microtime(true);
    $t = $s1 - $s0;
    assert_lt($t, 0.0015, "inspection took too long!");
}

function full_server() {
return array (
    'USER' => 'www-data',
    'HOME' => '/var/www',
    'HTTP_COOKIE' => '_rok=bIFXctjJlUMU1M0Uw2UGSqTaqs%2BtETT95ZS4d3I9sEYUQoxpCGwY1YkGDravX24U.yQYPvBWViqe6t6he',
    'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
    'HTTP_ACCEPT_ENCODING' => 'gzip, deflate, br',
    'HTTP_SEC_FETCH_DEST' => 'document',
    'HTTP_SEC_FETCH_USER' => '?1',
    'HTTP_SEC_FETCH_MODE' => 'navigate',
    'HTTP_SEC_FETCH_SITE' => 'none',
    'HTTP_ACCEPT' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36',
    'HTTP_UPGRADE_INSECURE_REQUESTS' => '1',
    'HTTP_DNT' => '1',
    'HTTP_AUTHORIZATION' => 'Basic OjI5X1Jvbmlu',
    'HTTP_CACHE_CONTROL' => 'max-age=0',
    'HTTP_HOST' => 'www.bitslip6.com',
    'REDIRECT_STATUS' => '200',
    'SERVER_NAME' => 'www.bitslip6.com',
    'SERVER_PORT' => '443',
    'SERVER_ADDR' => '172.30.2.135',
    'REMOTE_PORT' => '56232',
    'REMOTE_ADDR' => '63.227.245.106',
    'SERVER_SOFTWARE' => 'nginx/1.14.0',
    'GATEWAY_INTERFACE' => 'CGI/1.1',
    'HTTPS' => 'on',
    'REQUEST_SCHEME' => 'https',
    'SERVER_PROTOCOL' => 'HTTP/2.0',
    'DOCUMENT_ROOT' => '/var/www/bitslip/public',
    'DOCUMENT_URI' => '/app.php',
    'REQUEST_URI' => '/some/path/to/something',
    'SCRIPT_NAME' => '/app.php',
    'CONTENT_LENGTH' => '',
    'CONTENT_TYPE' => '',
    'REQUEST_METHOD' => 'GET',
    'QUERY_STRING' => '__x',
    'SCRIPT_FILENAME' => '/var/www/bitslip/public/app.php',
    'FCGI_ROLE' => 'RESPONDER',
    'PHP_SELF' => '/app.php',
    'PHP_AUTH_USER' => '',
    'PHP_AUTH_PW' => '29_Ronin',
    'REQUEST_TIME_FLOAT' => 1611184784.43334,
    'REQUEST_TIME' => 1611184784,
  );
}