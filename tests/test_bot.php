<?php declare(strict_types=1);

use BitFire\UserAgent;

use const BitFire\STATUS_FAIL;
use const BitFire\STATUS_SERVER_STATE_FAIL;

use function BitFireBot\js_int_obfuscate;
use function BitFireBot\make_js_challenge;

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

function test_make_js_challange() : void {
    $ip = \BitFire\IPData::make_new("127.0.0.1", "Mozilla/5.0 chrome 125");
    $s = make_js_challenge($ip);
    assert_gt(strlen($s), 2048, "js challenge too short");
}

function test_js_obfuscate() : void {
    $js = js_int_obfuscate(91231);
    assert_gt(strlen($js->fn_name), 3, "function name not set on int obfuscator");
    assert_gt(strlen($js->js_code), 80, "int obfuscation length too small");
}

function agent_list() : array {
    
    $data = array(
        array(
            strtolower("Mozilla/5.0 (Linux; Android 7.1.2; AFTMM Build/NS6265; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/70.0.3538.110 Mobile Safari/537.36"),
            new UserAgent("android", "chrome", "70.0", false, false)
        ),
        array(
            strtolower("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"),
            new UserAgent("windows", "chrome", "65.0", false, false)
        ),
        array(
            strtolower("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36 OPR/36.0.2130.32"),
            new UserAgent("windows", "opera", "36.0", false, false)
        )
    );

    return $data;
}

// todo, add more browsers here ...
/**
 * @dataprovider agent_list
 */
function test_parse_agent($data) : void {
    $answer = \BitFireBot\parse_agent($data[0]);
    assert_eq($answer->os, $data[1]->os, "os match failed");
    assert_eq($answer->browser, $data[1]->browser, "browser match failed");
    assert_eq($answer->ver, $data[1]->ver, "version match failed");
}


function test_browser_send_verify() : void {
    $ip_data = \BitFire\IPData::make_new("Mozilla/5.0 unit test browser", "127.0.0.1");
    $effect = \BitFireBot\send_browser_verification($ip_data);

    assert_eq($effect->read_code(), 300, "did not set http response value correctly");
    assert_true(in_array("expires", array_keys($effect->read_headers())), "did not set expires header");
    assert_true(in_array("cache-control", array_keys($effect->read_headers())), "did not set cache-control header");
    assert_gt(count($effect->read_cache()), 0, "no cache update found");
    assert_icontains($effect->read_out(), "domcontentloaded", "unable to find content loaded event");
}

function test_verify_browser() : void {
    $agent = "Mozilla/5.0 unit test browser";
    $ip = "127.0.0.1";
    $ip_data = \BitFire\IPData::make_new($agent, $ip);
    $request = new \BitFire\Request();
    $request->ip = $ip;
    $request->agent = $agent;
    $request->post = array('_bfxa' => 1, '_bfa' => 0);

    $cookie = \TF\MaybeStr::of(NULL);

    $effects = \BitFire\verify_browser($request, $ip_data, $cookie);
    assert_eq($effects->read_status(), STATUS_SERVER_STATE_FAIL, "verify browser with no server state did not fail");

    $request->post = array('_bfxa' => 1, '_bfa' => 81);
    $effects = \BitFire\verify_browser($request, $ip_data, $cookie);
    assert_eq($effects->read_status(), STATUS_SERVER_STATE_FAIL, "verify browser with no server state did not fail");

    // verify with server side state
    $ip_data->op1 = 123;
    $ip_data->op2 = 123;
    $ip_data->oper = 3;
    $request->post = array('_bfxa' => 1, '_bfa' => 246);
    $effects = \BitFire\verify_browser($request, $ip_data, $cookie);

    assert_eq($effects->read_status(), \BitFire\STATUS_OK, "verify addition JS with server side state fail");

    $cookie = \TF\un_json($effects->read_cookie());
    assert_eq($cookie['ip'], $ip, "did not set internal cookie IP value");
    assert_gt($cookie['v'], 1, "did not set valid cookie value");
    assert_gt($cookie['et'], time()+60, "did not set valid cookie expire time");
    assert_gt(count($effects->read_cache()), 1, "did not update enough server side state/metrics");

    // verify with cookie state
    $cookie = \TF\MaybeA::of(array('a' => 245));
    $ip_data = \BitFire\IPData::make_new($agent, $ip);
    $effects = \BitFire\verify_browser($request, $ip_data, $cookie);
    assert_eq($effects->read_status(), STATUS_FAIL, "fail with incorrect cookie answer");
    
    $cookie = \TF\MaybeA::of(array('a' => 246));
    $effects = \BitFire\verify_browser($request, $ip_data, $cookie);
    assert_eq($effects->read_status(), \BitFire\STATUS_OK, "fail to verify cookie answer");
    $cookie = \TF\un_json($effects->read_cookie());
    assert_eq($cookie['ip'], $ip, "did not set internal cookie IP value");
    assert_gt($cookie['v'], 1, "did not set valid cookie value");
    assert_gt($cookie['et'], time()+60, "did not set valid cookie expire time");
    assert_gt(count($effects->read_cache()), 1, "did not update enough server side state/metrics");
}