<?php declare(strict_types=1);

use ThreadFin\CacheItem;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;
use ThreadFin\Maybe;

use function BitFire\ip_to_country;
use function BitFire\is_ipv6;
use function BitFire\reverse_ip_lookup;
use function ThreadFin\between;
use function ThreadFin\decrypt_ssl;
use function ThreadFin\encrypt_ssl;
use function ThreadFin\ends_with;
use function ThreadFin\file_write;
use function ThreadFin\func_name;
use function ThreadFin\partial;
use function ThreadFin\recache2_file;
use function ThreadFin\str_reduce;

if (!defined("WAF_DIR")) {
    define('WAF_DIR', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)));
}
include_once WAF_DIR . "src/util.php";
include_once WAF_DIR . "src/botfilter.php";
include_once WAF_DIR . "src/tar.php";

function somefunc($a1, $a2, $a3, $a4 = "foobar") {
    return "some func [$a1] [$a2] [$a3] [$a4]";
}

function test_effects() : void {
    $e = Effect::new();
    $e->cookie("boobaz");
    assert_eq($e->read_cookie(), "boobaz", "cookie set failed");
    $e->exit(true);
    assert_eq($e->read_exit(), true, "exit set failed");
    $f = new FileMod("/tmp/test.txt", "boobaz", 0444, 1628874000);
    $f2 = new FileMod("/tmp/test2.txt", "foobar", 0444, 1628874000);
    $e->file($f);
    $e->file($f2);
    assert_eq($e->read_files()[1], $f2, "file set failed");
    $e->header("x-bitfire", "foobar");
    $e->header("x-bitfire", "boobaz");
    assert_eq($e->read_headers()["x-bitfire"], "boobaz", "header set failed");
    //$e->out("line1");
    //$e->out("line2");
    //assert_eq($e->read_out(), "line1line2", "stdout set failed");
    $e->response_code(404);
    assert_eq($e->read_code(), 404, "set response code failed");
    $ci = new CacheItem("foobar", function($x) { return $x."boobaz"; }, function() { return "nill";}, 800);
    $e->update($ci);
    assert_eq($e->read_cache()["foobar"], $ci, "unable to set cache item");
    $e->status(99);
    assert_eq($e->read_status(), 99, "unable to set effect status");
    $e->exit(false);
    $e->run();
    assert_true(file_exists("/tmp/test.txt"), "effect did not create /tmp/test.txt");
    assert_true(file_get_contents("/tmp/test.txt") === "boobaz", "effect did not create /tmp/test.txt");
}

function test_func_name() {
    assert_eq(func_name("strtolower"), "strtolower", "unable to get simple function name");
    assert_eq(func_name("\ThreadFin\\func_name"), "\ThreadFin\\func_name", "unable to get namespace function name");
    assert_eq(func_name(array("\ThreadFin\Effect", "cookie")), "\ThreadFin\Effect::cookie", "unable to get object function name");
}

function test_wp() : void {
    require_once WAF_DIR . "src/wordpress.php";
    $creds = \BitFireWP\wp_parse_credentials("/var/www/wordpress");
    assert_gt(strlen($creds->password), 4, "unable to parse wp-config");
    assert_gt(strlen($creds->host), 4, "unable to parse wp-config");
    assert_gt(strlen($creds->prefix), 1, "unable to parse wp-config");
    assert_gt(strlen($creds->username), 3, "unable to parse wp-config");
} 


function test_ends_with() : void {
    $needle = "foobar";
    $haystack = "a thing foobar another thing";
    assert_false(ends_with($haystack, $needle), "constains string ends with incorrectly");
    $haystack = "a thing foobar another thing foobar";
    //assert_true(endsWith($haystack, $needle), "2x constains string ends with incorrectly");
    $haystack = "another thing foobar";
    //assert_true(endsWith($haystack, $needle), "1x constains string ends with incorrectly");
}


function test_encryption() : void {
    $pass = "passwordpasswordpassword";
    $message = "a secret message";

    $enc = encrypt_ssl("short", $message);
    assert_true(empty($enc), "short key allows encryption");
    
    $enc = encrypt_ssl($pass, $message);
    assert_neq($enc, $message, "unable to encrypt");
    $dec = decrypt_ssl($pass, $enc);
    assert_eq($dec(), $message, "unable to decrypt");
    assert_false($dec->empty(), "empty decrypted message");

    $dec = decrypt_ssl("p", $enc);
    assert_true($dec->empty(), "bad key produced decrypted message");
    $dec = decrypt_ssl($pass, "");
    assert_true($dec->empty(), "bad key produced decrypted message");
    
}

function test_map_reduce() : void {
    
    $test = array("key" => "value", 12 => "number value", "anything" => "else");
    $result = map_reduce($test, function ($k, $v, $c) {
        return (is_int($k)) ? true : $c;
    }, false);
    assert_eq($result, true, "map reduce seems to not work");

    unset($test[12]);
    $result = map_reduce($test, function ($k, $v, $c) {
        return (is_int($k)) ? true : $c;
    }, false);
    assert_eq($result, false, "map reduce seems to not work");

}

/**
 * @type speed
 */
function test_read_raw_speed() : void {
    $f1 = file ("/home/cory/tools/bitfire-release/cache/values.txt");
    $f2 = file ("/home/cory/tools/bitfire-release/cache/keys.txt");
}

/**
 * @type speed
 */
function test_read_enc_speed() : void {
    $f1 = file_get_contents("/home/cory/tools/bitfire-release/cache/values.txt");
    $dec = decrypt_ssl("some_password", $f1);
    $f2 = file_get_contents("/home/cory/tools/bitfire-release/cache/keys.txt");
    $dec2 = decrypt_ssl("some_password", $f2);
}

/**
 * @type speed
 */
function test_recache_speed() : void {
    $t1 = microtime(true);
    $p1 = recache2_file(WAF_DIR."cache/keys.raw");
    $t2 = microtime(true);
    $p2 = recache2_file(WAF_DIR."cache/values.raw");
    $t3 = microtime(true);
    assert_lt(($t2-$t1), 0.00001, "key decomplie time too slow");
    assert_lt(($t3-$t2), 0.00001, "value decomplie time too slow");
}

function test_can_encrypt_ssl() : void {
    $response = encrypt_ssl("passwordpasswordpassword", "a test message");
    $parts = explode(".", $response);
    assert_eq(count($parts), 2, "encrypted message did not match format");
}

function test_can_decrypt_ssl() : void {
    $original_message = "a test message";
    $encrypted = encrypt_ssl("passwordpasswordpassword", $original_message);
    $decrypted = decrypt_ssl("passwordpasswordpassword", $encrypted)();
    assert_eq($original_message, $decrypted , "decrypted message did not match original");
}

function test_between_is_exclusive() : void  {
    assert_true(between(5, 4, 6), "5 is between 4 and 6");
    assert_true(between(5, 5, 6), "5 is not between 5 and 6");
    assert_true(between(5, 5, 5), "5 is not between 5 and 5");
    assert_true(!between(3, 4, 10), "5 is not between 3 and 5");
}

function test_is_ipv6() : void {
    assert_true(is_ipv6("1234:0000:0000:1234:0000:1234"), "5 : should be ipv6 addr");
    assert_true(!is_ipv6("1.1.1.1"), "1.1.1.1 : should not be ipv6 addr");
    //assert_true(!is_ipv6("1234:1234"), "1234:1234 : should not be ipv6 addr");
    assert_true(!is_ipv6("random string"), "random string : should not be ipv6 addr");
    assert_true(!is_ipv6(""), "empty string : should not be ipv6 addr");
}

/**
 * @type files
 */
function dead_file_recurse() : void {
    $ctr = 0;
    file_recurse(__DIR__ . DIRECTORY_SEPARATOR . "..", function($item) use (&$ctr) {
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
    $lookup = reverse_ip_lookup($ipaddr);
    assert_icontains($lookup(), $dnsname, "reverse ip lookup of $ipaddr ($dnsname)");

    \BitFire\Config::set_value("dns_service", "1.1.1.1");
    $lookup = reverse_ip_lookup($ipaddr);
    assert_icontains($lookup(), $dnsname, "reverse ip lookup of $ipaddr ($dnsname)");
}

function ip_to_domain() : array {
    return array(
        //"google reverse lookup" => array("2607:f8b0:4005:808::200e", "1e100.net"),
        "google reverse lookup" => array("4.2.2.2", "level3.net"),
        "facebook reverse lookup" => array("157.240.3.35", "facebook.com")
    );
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
    $times3 = partial("times", 3);
    assert_eq($times3(9), 27, "partial app of *3 failed");
}    
function test_box() : void {
    $test_ar = array(array("boo" => "bar"));
    $val = Maybe::of($test_ar)
        ->then('ThreadFin\en_json')
        ->then('base64_encode')();
    assert_eq($val, 'W3siYm9vIjoiYmFyIn1d', "unable to base64 and json encode");

    $result = Maybe::of($val)
    ->then('base64_decode')
    ->then('ThreadFin\un_json')();
    assert_eq($result[0]['boo'], "bar", "undecoded json data not equal");
} 


function test_ssl() : void {
    $pass = "passwordpasswordpassword";
    $test_text = "hypertext_processor";
    $encrypt = encrypt_ssl($pass, $test_text);
    $r = decrypt_ssl($pass, $encrypt);
    assert_neq($encrypt, $test_text, "unable to encrypt");
    assert_eq($r(), $test_text, "unable to encrypt and then decrypt");
}


function test_file_replace() : void {
    $c = file_put_contents("/tmp/test_util.txt", "this is an example test file\nwith a multiline example thing");
    file_replace("/tmp/test_util.txt",  "example", "foobar");
    assert_true(file_get_contents("/tmp/test_util.txt") == "this is an foobar test file\nwith a multiline foobar thing", "unable to replace file contents");
    unlink("/tmp/test_util.txt");
}

function test_http_ctx() : void {

    $ctx = http_ctx("POST", 123);
    assert_eq($ctx['http']['method'], "POST", "unable to set http POST type");
    assert_eq($ctx['http']['timeout'], 123, "unable to set http timeout");
}

function test_str_reduce() : void {
    $ip = "127.0.0.1";
    $lookup_addr = str_reduce($ip, function($chr) { return $chr . "."; }, "", "ip6.arpa");
    assert_eq($lookup_addr, "1.2.7...0...0...1.ip6.arpa", "str reduce returned error");
}

function test_ip_to_country() : void {
    assert_eq(ip_to_country("54.213.205.144"), 1, "bitslip not in US");
}


/**
 * @type tar
 */
function test_untar() : void {
    tar_extract(WAF_DIR."tests/bitfire-1.6.3.tar.gz", "/tmp");
    assert_true(file_exists("/tmp/bitfire-1.6.3"), "unable to extract test file");
    assert_gt(system("find /tmp/bitfire-1.6.3 | wc -l"), 90, "not all files extracted");
}

function test_file_data() : void {

    $raw_text = "this is an example test file\nwith a multiline example thing\ninteresting";
    file_put_contents("/tmp/test_util.txt", $raw_text);
    $file_data = FileData::new("/tmp/test_util.txt");
    assert_true($file_data->exists, "file data not found");
    assert_true($file_data->writeable, "file data not writable");
    assert_true($file_data->readable, "file data not readable");

    $read_text = $file_data->raw();
    assert_eq($raw_text, $read_text, "file data not read correctly");

    $file_data->read();
    assert_eq(count($file_data->lines), 3, "file data not read correctly");

}