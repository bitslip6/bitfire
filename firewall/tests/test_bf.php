<?php declare(strict_types=1);


use \BitFire\Config;
use ThreadFin\CacheStorage;

require_once \BitFire\WAF_SRC."const.php";
//die("test bf req const\n");


function newbotfilter() : BitFire\BotFilter {
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    $cache = CacheStorage::get_instance();
    return new BitFire\BotFilter($cache);
}

function test_can_new_botfilter() : void {
    $bf = newbotfilter();
    // return print_r($bf, true);
    assert_instanceof($bf, '\BitFire\BotFilter', "unable to create botfilter");
}

function host_header_data() : array {
    return array(
        "valid .bitslip6 header" => array("bitslip6.com", true),
        "valid www.bitslip6 header" => array("www.bitslip6.com", true),
        "valid api.bitslip6 header" => array("api.bitslip6.com", true),
        "invalid .bitslip header" => array("api.bitslip.com", false),
        "invalid api.bitslip header" => array("api.bitslip.com", false),
        "invalid .bitslip.co header" => array(".bitslip.co", false),
    );
}

/**
 * @dataprovider host_header_data
 */
function it_should_validate_host_headers(array $data) : void {
    $is_valid = \BitFireBot\validate_host_header(array("bitslip6.com"), $data[0]);
    assert_eq($is_valid, $data[1], "host header validation failed [{$data[0]}]");
}


function agent_list3() : array {
    return array(
        "linux browser 1" => array("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36", "linux", "chrome", "44.0"),
        "linux browser 2" => array("Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:24.0) Gecko/20100101 Firefox/24.0", "linux", "firefox", "24.0"),
        "linux browser 3" => array("Apache/2.4.34 (Ubuntu) OpenSSL/1.1.1 (internal dummy connection)", 'bot', '', 'x'),
        "android 1" => array("Mozilla/5.0 (Linux; U; Android 2.2) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1", "android", "android", "2.2"),
        "android 2" => array("Mozilla/5.0 (Linux; Android 9; SM-G950F Build/PPR1.180610.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.157 Mobile Safari/537.36", "android", "chrome", "74.0"),
        "android 3" => array("Mozilla/5.0 (Linux; U; Android 4.3; de-de; GT-I9300 Build/JSS15J) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30", "android", "android", "4.3"),
        "android 4" => array("Mozilla/5.0 (Linux; U; Android 6.0.1; zh-CN; F5121 Build/34.0.A.1.247) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/40.0.2214.89 UCBrowser/11.5.1.944 Mobile Safari/537.36", "android", "chrome", "40.0"),
        "safari 1" => array("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.59.10 (KHTML, like Gecko) Version/5.1.9 Safari/534.59.10", "os x", "safari", "534.59")
    );
}

/**
 * @dataprovider agent_list3
 */
function it_should_identify_agents(array $data) : void {
    $parsed = BitFireBot\parse_agent(strtolower($data[0]));
    //print_r($parsed);
    assert_eqic($parsed->os, $data[1], "unable to detect os");
    if ($data[2] != null) {
        assert_eqic($parsed->browser, $data[2], "unable to detect browser");
    }
    if ($data[3] != null) {
        assert_eqic($parsed->ver, $data[3], "unable to detect version");
    }
}


/**
 * @phperror warn: Deprecated
 * @exception AssertionError
 */
function test_empty_botlist_returns_false() : void {
    $botlist1 = array("" => "", false => false, "something" => "something");
    $empty_array = array();
    $in_list = BitFireBot\agent_in_list("", "157.240.213.10", $empty_array);
    assert_eq($in_list, 0, "test empty bot list returned valid bot!");

    $in_list = BitFireBot\agent_in_list("no agent", "157.240.213.10", $botlist1);
    assert_eq($in_list, -1, "test empty random agent returned valid bot!");
    
    $in_list = BitFireBot\agent_in_list("", "157.240.213.10", $botlist1);
    assert_eq($in_list, 0, "test empty empty agent returned valid bot!");
}


function google_tests() : void {
    $pass = BitFireBot\verify_bot_ip("66.249.66.123", "example.co,googlebot.com,foobar.com");
    assert_true($pass, "unable to verify 66.249.66.123 is googlebot");
    $pass = BitFireBot\verify_bot_ip("66.249.66.123", "google.com");
    assert_false($pass, "unable to verify 66.249.66.123 is google.com");
    $pass = BitFireBot\verify_bot_ip("4.2.2.2", "googlebot.com");
    assert_false($pass, "shit, bad ip 4.2.2.2 is googlebot");
    $pass = BitFireBot\verify_bot_ip("1.1.1.1", "googlebot.com");
    assert_false($pass, "shit, bad ip 1.1.1.1 is googlebot");
}

/**
 * @type network
 */
function test_verify_google_crawler() : void {

    google_tests();
    //google_tests();
/*
    CacheStorage::set_type('apcu');
    google_tests();
    CacheStorage::set_type('shmop');
    google_tests();
*/
}


/**
 * @exception invalid ipv4 address
 * @TOTO this test requires expected assertion errors in tinytest.php
 *       in the main catch \Error block near 575
 */
function test_verify_google_crawler_fails() : void {
    //$pass = BitFireBot\verify_bot_ip("66.249.66", "googlebot.com");
    //assert_false($pass, "shit, bad ip 66.249.66 is googlebot");
    assert_true(true, "fix this test");
}

/**
 * @type network
 */
function test_verify_facebook_crawler() : void {
    $agents = array("facebookexternalhit" => "AS32934,AS46606");


    $works = BitFireBot\agent_in_list("facebookexternalhit", "157.240.213.10", $agents);
    assert_true($works, " facebook external hit as lookup1 failed");

    $works = BitFireBot\agent_in_list("facebookexternalhit", "67.20.116.202", $agents);
    assert_true($works, " facebook external hit as lookup2 failed");

    $works = BitFireBot\agent_in_list("facebookexternalhit", "4.2.2.2", $agents);
    assert_true($works, " facebook external hit as lookup4 failed");
    //$works = BitFireBot\agent_in_list("facebookexternalhit", "4.2.2.1", $agents);
    //assert_false($works, " facebook external hit as lookup returned true incorrectly");
}


// todo, add more browsers here ...
function test_parse_agent2() : void {
    $answer = BitFireBot\parse_agent(strtolower("Mozilla/5.0 (Linux; Android 7.1.2; AFTMM Build/NS6265; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/70.0.3538.110 Mobile Safari/537.36"));
    assert_eq($answer->os, "android", "unable to find android os in user agent");
    assert_eq($answer->browser, "chrome", "unable to find android browser in user agent");
    assert_eq($answer->ver, "70.0", "unable to find android ver in user agent");

    $answer = BitFireBot\parse_agent(strtolower("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"));
    assert_eq($answer->os, "windows", "unable to find windows os in user agent");
    assert_eq($answer->browser, "chrome", "unable to find chrome browser in user agent");
    assert_eq($answer->ver, "65.0", "unable to find chrome ver in user agent");

    $answer = BitFireBot\parse_agent(strtolower("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36 OPR/36.0.2130.32"));
    assert_eq($answer->os, "windows", "unable to find windows os in user agent");
    assert_eq($answer->browser, "opera", "unable to find opera browser in user agent");
    assert_eq($answer->ver, "36.0", "unable to find opera ver in user agent");
}



function ip_verify_list() : array {
    return array(
        "127.0.0.1" => "127.0.0.1",
        "127.0.0.1" => "127.0.*.1",
        "127.0.0.1" => "127.0.0.*",
        "127.0.0.1" => "127.*",
        "127.0.0.1" => "10.10.10.1,1.2.3.4,example.com,127.0.0.1,"
    );
}

function test_whitelist_inspection() : void {
    Config::set_value("whitelist_enable", 'block');
    //$result = BitFireBot\whitelist_inspection("Mozilla/5.0 googlebot/1.0", "66.249.66.123", array('googlebot' => 'google(bot?).com'));
    //assert_true($result->empty(), "did not correctly hit whitelist googlebot");
    $result = BitFireBot\whitelist_inspection("Mozilla/5.0 googlebot/1.0", "66.249.66.123", array('googlebot' => 'gooogle(bot?).com'));
    assert_false($result->empty(), "did not correctly miss whitelist goo(o)glebot 1");
    $result = BitFireBot\whitelist_inspection("Mozilla/5.0 goooglebot/1.0", "66.249.66.123", array('googlebot' => 'google(bot?).com'));
    assert_false($result->empty(), "did not correctly miss whitelist goo(o)glebot 2");
    $result = BitFireBot\whitelist_inspection("", "66.249.66.123", array('googlebot' => 'google(bot?).com'));
    assert_false($result->empty(), "did not correctly miss empty UA");
    $result = BitFireBot\whitelist_inspection("Mozilla/5.0 googlebot/1.0", "54.213.205.144", array('googlebot' => 'google(bot?).com'));
    assert_false($result->empty(), "did not correctly miss whitelist googlebot from non google ip");
}

function test_blacklist_inspection2() : void {
    $_SERVER = array();
    $_SERVER['HTTP_USER_AGENT'] = 'T';
    $_SERVER['REQUEST_SCHEME'] = 'http';
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    \BitFire\Config::set_value(\BitFire\CONFIG_CHECK_DOMAIN, true);
    \BitFire\Config::set_value("blacklist_enable", true);
    $request = \BitFire\process_request2(array(), array(), $_SERVER, array());

    $request->agent = "Mozilla/5.0 nmap1.2.3.4";
    $result = BitFireBot\blacklist_inspection($request, file('cache/bad-agent.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
    assert_false($result->empty(), "did not correctly blacklist nmap");

    $request->agent = "Mozilla/5.0 netsparker/1.0";
    $result = BitFireBot\blacklist_inspection($request, file('cache/bad-agent.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
    assert_false($result->empty(), "did not correctly blacklist netsparker");

    $request->agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36";
    $result = BitFireBot\blacklist_inspection($request, file('cache/bad-agent.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
    assert_true($result->empty(), "did not correctly blacklist netsparker");
}

function test_basic_request_passes() : void {
    $bf = newbotfilter();
    Config::set_value("require_full_browser", false);

    $_SERVER = array();
    $_SERVER['REQUEST_URI'] = 'https://localhost:8080/foobar/something?param1=value1';
    $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/80.2 AppleWebKit/537.3';
    $_SERVER['HTTP_HOST'] = 'localhost:8080';
    $_SERVER['REQUEST_SCHEME'] = 'http';
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    $request = \BitFire\process_request2(array(), array(), $_SERVER, array());

    $maybe_block = $bf->inspect($request);
    assert_true($maybe_block->empty(), "blocked simple request!");
}

function test_parse_whois_line() : void {
    $line1 ='route    : 1.2.3.4/24';
    assert_eq(\BitFireBot\parse_whois_line($line1), '1.2.3.4/24', 'failed parse ipv4 whois line');

    $line2 =' route6:         2403:6b80:bf::/48';
    assert_eq(\BitFireBot\parse_whois_line($line2), '2403:6b80:bf::/48', 'failed parse ipv6 whois line');

    $line3 =' route6         2403:6b80:bf::/48';
    assert_eq(\BitFireBot\parse_whois_line($line3), '', 'failed parse ipv6 whois line');
}

function test_parse_whois_route() : void {
    $line1 = " route    : 1.2.3.4/24\n route6:         2403:6b80:bf::/48";
    $res = array('1.2.3.4/24', '2403:6b80:bf::/48');
    assert_eq(\BitFireBot\parse_whois_route($line1), $res, 'failed parse ipv6 whois line');

    $line2 = "";
    $res = array('');
    assert_eq(\BitFireBot\parse_whois_route($line2), $res, 'failed parse ipv6 whois line');
}

function test_is_ip_in_cidr_list() : void {
    $result = \BitFireBot\is_ip_in_cidr_list("192.168.0.21", array("192.168.0.0/24"));
    assert_true($result, "192.168.0.24 not in 192.168.0.0/24???");

    $result = \BitFireBot\is_ip_in_cidr_list("192.168.1.21", array("192.168.0.0/24"));
    assert_false($result, "192.168.1.24 in 192.168.0.0/24???");

    $result = \BitFireBot\is_ip_in_cidr_list("192.168.254.254", array("192.168.0.0/16"));
    assert_true($result, "192.168.1.24 NOT in 192.168.0.0/24???");

    $result = \BitFireBot\is_ip_in_cidr_list("2403:6b80:bf01:0001::", array("2403:6b80:bf01::/48"));
    assert_true($result, "2403:6b80:bf01::0001 NOT in 2403:6b80:bf::/48 ??");

    $result = \BitFireBot\is_ip_in_cidr_list("2403:6b80:be01:0001::", array("2403:6b80:bf01::/48"));
    assert_false($result, "2403:6b80:be01::0001 IN 2403:6b80:bf::/48 ??");
    //var_dump($result);
}