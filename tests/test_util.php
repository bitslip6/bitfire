<?php declare(strict_types=1);

if (!defined("WAF_DIR")) {
    define('WAF_DIR', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)));
}
include_once WAF_DIR . "util.php";

function somefunc($a1, $a2, $a3, $a4 = "foobar") {
    return "some func [$a1] [$a2] [$a3] [$a4]";
}

function test_do_for_all() : void {
    $start = array("item1" => array("value1", "v2", "v3"), "item2" => "value2");
    \TF\do_for_all($start, 'json_encode');
    assert_true(true, "empty test");
}


function test_ends_with() : void {
    $needle = "foobar";
    $haystack = "a thing foobar another thing";
    assert_false(\TF\ends_with($haystack, $needle), "constains string ends with incorrectly");
    $haystack = "a thing foobar another thing foobar";
    //assert_true(\TF\endsWith($haystack, $needle), "2x constains string ends with incorrectly");
    $haystack = "another thing foobar";
    //assert_true(\TF\endsWith($haystack, $needle), "1x constains string ends with incorrectly");
}

/**
 * @type external
 */
function dead_can_ping_api() : void {
    $id = uniqid();
    $response = TF\apidata("ping", array("id" => $id));
    $pong = $response['response']['pong'] ?? '';
    assert_eq($pong, $id, "pong response invalid");
}

function test_can_encrypt_ssl() : void {
    $response = TF\encrypt_ssl("passwordpasswordpassword", "a test message");
    $parts = explode(".", $response);
    assert_eq(count($parts), 2, "encrypted message did not match format");
}

function test_can_decrypt_ssl() : void {
    $original_message = "a test message";
    $encrypted = TF\encrypt_ssl("passwordpasswordpassword", $original_message);
    $decrypted = TF\decrypt_ssl("passwordpasswordpassword", $encrypted)();
    assert_eq($original_message, $decrypted , "decrypted message did not match original");
}

function test_between_is_exclusive() : void  {
    assert_true(TF\between(5, 4, 6), "5 is between 4 and 6");
    assert_true(TF\between(5, 5, 6), "5 is not between 5 and 6");
    assert_true(TF\between(5, 5, 5), "5 is not between 5 and 5");
    assert_true(!TF\between(3, 4, 10), "5 is not between 3 and 5");
}

function test_is_ipv6() : void {
    assert_true(TF\is_ipv6("1234:0000:0000:1234:0000:1234"), "5 : should be ipv6 addr");
    assert_true(!TF\is_ipv6("1.1.1.1"), "1.1.1.1 : should not be ipv6 addr");
    //assert_true(!TF\is_ipv6("1234:1234"), "1234:1234 : should not be ipv6 addr");
    assert_true(!TF\is_ipv6("random string"), "random string : should not be ipv6 addr");
    assert_true(!TF\is_ipv6(""), "empty string : should not be ipv6 addr");
}

/**
 * @type files
 */
function dead_file_recurse() : void {
    $ctr = 0;
    \TF\file_recurse(__DIR__ . DIRECTORY_SEPARATOR . "..", function($item) use (&$ctr) {
        $ctr++;
    });
    assert_gt($ctr, 42, " files in directory");
} 

/**
 * @type integration
 * @dataprovider ip_to_domain
 */
function test_can_ip_lookup(array $data) : void {
    $ipaddr = $data[0];
    $dnsname = $data[1];
    $lookup = TF\reverse_ip_lookup($ipaddr);
    //$v = $lookup->empty() ? '' : $lookup();
    assert_icontains($lookup(), $dnsname, "reverse ip lookup of $ipaddr ($dnsname)");
}

function ip_to_domain() : array {
    return array(
        "google reverse lookup" => array("2607:f8b0:4005:808::200e", "1e100.net"),
        "facebook reverse lookup" => array("157.240.3.35", "facebook.com")
    );
}

/**
 * @type integration
 */
function test_get_remote_list() : void {
    $result = TF\apidata("getlist", ["type" => "blacklist"]);
    //print_r($result);
}

/**
 * @exception RuntimeException
 */
function test_exception_correct() : void {
    assert_true(true, "foobar");
    throw new RuntimeException("this is okay");
}

function times($a, $b) { return $a * $b; }
function add($a, $b) { return $a + $b; }

function test_partial() : void {
    $times3 = TF\partial("times", 3);
    assert_eq($times3(9), 27, "partial app of *3 failed");
}    
function test_box() : void {
    $test_ar = array(array("boo" => "bar"));
    $val = TF\Maybe::of($test_ar)
        ->then('TF\en_json')
        ->then('base64_encode')();
    assert_eq($val, 'W3siYm9vIjoiYmFyIn1d', "unable to base64 and json encode");

    $result = TF\Maybe::of($val)
    ->then('base64_decode')
    ->then('TF\un_json')();
    assert_eq($result[0]['boo'], "bar", "undecoded json data not equal");
} 


function test_ssl() : void {
    $pass = "passwordpasswordpassword";
    $test_text = "hypertext_processor";
    $encrypt = TF\encrypt_ssl($pass, $test_text);
    $r = TF\decrypt_ssl($pass, $encrypt);
    assert_neq($encrypt, $test_text, "unable to encrypt");
    assert_eq($r(), $test_text, "unable to encrypt and then decrypt");
}

function test_write_file() : void {
    assert_true(\TF\file_write("/tmp/test_util.txt", "text_content"), "unable to write file to /tmp");
}

function test_file_replace() : void {
    $c = file_put_contents("/tmp/test_util.txt", "this is an example test file\nwith a multiline example thing");
    \TF\file_replace("/tmp/test_util.txt",  "example", "foobar");
    assert_true(file_get_contents("/tmp/test_util.txt") == "this is an foobar test file\nwith a multiline foobar thing", "unable to replace file contents");
    unlink("/tmp/test_util.txt");
}

function test_http_ctx() : void {

    $ctx = \TF\http_ctx("POST", 123);
    assert_eq($ctx['http']['method'], "POST", "unable to set http POST type");
    assert_eq($ctx['http']['timeout'], 123, "unable to set http timeout");
}

function test_str_reduce() : void {
    $ip = "127.0.0.1";
    $lookup_addr = \TF\str_reduce($ip, function($chr) { return $chr . "."; }, "", "ip6.arpa");
    assert_eq($lookup_addr, "1.2.7...0...0...1.ip6.arpa", "str reduce returned error");
}

function test_ip_to_country() : void {
    assert_eq(\TF\ip_to_country("54.213.205.144"), 1, "bitslip not in US");
}

