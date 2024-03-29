<?php declare(strict_types=1);

use BitFire\Answer;
use BitFire\BotFilter;
use BitFire\Request;
use BitFire\UserAgent;
use ThreadFin\MaybeA;
use ThreadFin\MaybeStr;

use const BitFire\CONFIG_BLACKLIST;
use const BitFire\CONFIG_CHECK_DOMAIN;
use const BitFire\STATUS_FAIL;
use const BitFire\STATUS_OK;
use const BitFire\STATUS_SERVER_STATE_FAIL;

use function BitFire\verify_browser_effect;
use function BitFireBot\bot_authenticate;
use function BitFireBot\js_int_obfuscate;
use function BitFireBot\make_js_challenge;
use function ThreadFin\dbg;
use function ThreadFin\un_json;
use function ThreadFin\debug;
use function ThreadFin\trace;

if (!defined("\BitFire\WAF_ROOT")) {
    define('\BitFire\WAF_ROOT', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)) . DIRECTORY_SEPARATOR);
}
include_once \BitFire\WAF_SRC."util.php";

$bf = \BitFire\BitFire::get_instance();

function test_make_js_challange() : void {
    $ip_data = \BitFire\map_ip_data(\BitFire\new_ip_data("127.0.0.1", "Mozilla/5.0 chrome 12.5"));
    $script = \BitFireBot\make_js_script($ip_data->op1, $ip_data->op2, $ip_data->oper);
    assert_gt(strlen($script), 2048, "js challenge too short");
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
        ),
        [strtolower('mozilla/5.0 (linux; android 10; lio-an00 build/huaweilio-an00; wv) applewebkit/537.36 (khtml, like gecko) chrome/103.0.5060.114 mobile safari/537.36'),
        new UserAgent('android', 'huaweilio', '537.36', false, false)],
        [strtolower('mozilla/5.0 (windows nt 6.1; wow64) applewebkit/537.36 (khtml, like gecko) chrome/63.0.3239.132 safari/537.36 qihu 360se'),
        new UserAgent('windows', 'qihu', '6.1', false, false)],
        [strtolower('expanse, a palo alto networks company, searches across the global ipv4 space multiple times per day to identify customers&#39; presences on the internet. if you would like to be excluded from our scans, please send ip addresses/domains to: scaninfo@paloaltonetworks.com'),
        new UserAgent('bot', 'expanse, a palo alto networks company, searches across the global ipv4 space multiple times per day to identify customers&#39; presences on the internet. if you would like to be excluded from our scans, please send ip addresses/domains to: scaninfo@paloaltonetworks.com', 'x', false, true)],
        [strtolower("Cloud mapping experiment. Contact research@pdrlabs.net"),
        new UserAgent('bot', 'cloud mapping experiment. contact research@pdrlabs.net', 'x', false, true)]

    );

    return $data;
}

// todo, add more browsers here ...
/**
 * @dataprovider agent_list
 */
function test_parse_agent($data) : void {
    $m0 = microtime(true);
    $answer = \BitFireBot\parse_agent($data[0]);
    assert_eq($answer->os, $data[1]->os, "os match failed");
    assert_eq($answer->browser, $data[1]->browser, "browser match failed");
    assert_eq($answer->ver, $data[1]->ver, "version match failed");
    assert_eq($answer->bot, $data[1]->bot, "bot match failed");
}

function test_bot_auth() : void {
    \BitFire\Config::set_value("dynamic_exceptions", 0);
    $agent = "mozilla/5.0 (compatible; censysinspect/1.1; +https://about.censys.io/)";
    $ua = \BitFireBot\parse_agent($agent);
    //print_r($ua);
    /*
    $ua = new UserAgent("bot", $agent, "1.1", false, true);
    \BitFire\Config::set_value("debug_file", "/tmp/unit_test.log");
    */
    $auth = bot_authenticate($ua, "205.204.182.192", $agent);

    $debug = debug(null);
    $trace = trace(null);
    print_r($debug);
    print_r($trace);
    //print_r($auth);
}


function test_send_browser_verification() : void {
    \BitFire\Config::set_value("cookies_enabled", true);
    $ip_data = \BitFire\IPData::make_new("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36", "127.0.0.1");
    $request = new Request();
    $request->agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36";
    $effect = \BitFireBot\send_browser_verification($ip_data, $request, true);
    //\TF\dbg($effect);

    assert_eq($effect->read_code(), 303, "did not set http response value correctly");
    assert_true(in_array("expires", array_keys($effect->read_headers())), "did not set expires header");
    assert_true(in_array("cache-control", array_keys($effect->read_headers())), "did not set cache-control header");
    assert_gt(count($effect->read_cache()), 0, "no cache update found");
    assert_icontains($effect->read_out(), "domcontentloaded", "unable to find content loaded event");
}

function test_verify_browser() : void {
    $agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36";
    $ip = "127.0.0.1";
    $ip_data = \BitFire\IPData::make_new($agent, $ip);
    $request = new \BitFire\Request();
    $request->ip = $ip;
    $request->agent = $agent;
    $request->path = "/";
    $request->post = array('_bfxa' => 1, '_bfa' => 0);

    $cookie = MaybeA::of(['a' => ['ans' => 99]]);
    //dbg($cookie);

    $effects = verify_browser_effect($request, $ip_data, $cookie);
    assert_eq($effects->read_status(), STATUS_SERVER_STATE_FAIL, "verify browser with no server state did not fail");

    $request->post = array('_bfxa' => 1, '_bfa' => 81);
    $effects = verify_browser_effect($request, $ip_data, $cookie);
    assert_eq($effects->read_status(), STATUS_SERVER_STATE_FAIL, "verify browser with no server state did not fail");

    // verify with server side state
    $ip_data->op1 = 123;
    $ip_data->op2 = 123;
    $ip_data->oper = 3;
    $request->post = array('_bfxa' => 1, '_bfa' => 246);
    $effects = verify_browser_effect($request, $ip_data, $cookie);

    print_r($effects);
    assert_eq($effects->read_status(), STATUS_OK, "verify addition JS with server side state fail");

    $cookie = un_json($effects->read_cookie());
    assert_eq($cookie['ip'], crc32($ip), "did not set internal cookie IP value");
    assert_gt($cookie['v'], 1, "did not set valid cookie value");
    assert_gt($cookie['et'], time()+60, "did not set valid cookie expire time");
    assert_gt(count($effects->read_cache()), 1, "did not update enough server side state/metrics");

    // verify with cookie state
    $cookie = MaybeA::of(array('a' => array('ans' => 245)));
    $ip_data = \BitFire\IPData::make_new($agent, $ip);
    $effects = verify_browser_effect($request, $ip_data, $cookie);
    assert_eq($effects->read_status(), STATUS_FAIL, "fail with incorrect cookie answer");
    
    $cookie = MaybeA::of(array('a' => array('ans' => 246)));
    $effects = verify_browser_effect($request, $ip_data, $cookie);
    assert_eq($effects->read_status(), STATUS_OK, "fail to verify cookie answer");
    $cookie = un_json($effects->read_cookie());
    assert_eq($cookie['ip'], crc32($ip), "did not set internal cookie IP value");
    assert_gt($cookie['v'], 1, "did not set valid cookie value");
    assert_gt($cookie['et'], time()+60, "did not set valid cookie expire time");
    assert_gt(count($effects->read_cache()), 1, "did not update enough server side state/metrics");
}

function test_bot_metric_inc() : void {
    $item = \BitFire\bot_metric_inc("valid");
    assert_gt(strlen($item->key), 8, "did not set metric");
    assert_gt($item->ttl, 0, "cache item ttl is too short");
    assert_true(is_callable($item->fn) , "cache fn is not callable");
}

function test_make_challenge_cookie() : void {
    $answer = new Answer(513, 9123, 4);
    $cookie = \BitFireBot\make_challenge_cookie($answer->ans, "127.0.0.1", "some user agent");
    assert_gt($cookie['et'], time()+60, "expire time too short");
    assert_eq($cookie['v'], 1, "verify did not default to 1");
    assert_eq($cookie['a'], -8610, "challenge answer was not encoded correctly");
    assert_eq($cookie['ip'], "127.0.0.1", "source ip was not encoded correctly");
}

function test_open_char() : void {
    assert_eq(\BitFireBot\oper_char(1), "*", "operation mulitplication failed");
    assert_eq(\BitFireBot\oper_char(2), "/", "operation division failed");
    assert_eq(\BitFireBot\oper_char(3), "+", "operation addition failed");
    assert_eq(\BitFireBot\oper_char(4), "-", "operation subtraction failed");
    assert_eq(\BitFireBot\oper_char(0), "+", "operation default failed");
}

function test_js_fn() : void {
    $fn = \BitFireBot\js_fn('foofunc');

    assert_eq($fn("arg1"), "foofunc(arg1)", "calling foofunc from function generator failed");
}

function test_blacklist_inspection() : void {

    $request = new \Bitfire\Request();
    $request->agent = "Mozilla/5.0 chrome 15.5 evil/1.0 safari 536.17";
    $blacklist = array("curl/1.0", "evil/1.0");
    \BitFire\Config::set_value(CONFIG_CHECK_DOMAIN, true);
    \BitFire\Config::set_value("blacklist_enable", true);
    $block = \BitFireBot\blacklist_inspection($request, $blacklist);

    assert_false($block->empty(), "black list block did not block");
    assert_eq($block->extract("parameter")->value("string"), "user_agent", "black list block did not block");
    assert_eq($block->extract("code")->value("int"), 25001, "block code incorrect");

    $blacklist = array("curl/1.0", "foobar/1.0");
    $block = \BitFireBot\blacklist_inspection($request, $blacklist);
    assert_true($block->empty(), "black list block did not block");
}

/**
 * @type network
 */
function test_verify_bot_as() : void {
    $result = \BitFireBot\verify_bot_as("129.134.27.1", "AS32934");
    assert_true($result, "facebook as match");

    /*
    $result = \BitFireBot\verify_bot_as("192.134.27.1", "AS32934");
    assert_false($result, "facebook as MIS match");
    */
}


/**
 * @type network
 */
function test_memoization_verify_bot_as() : void {
    $result = \BitFireBot\fast_verify_bot_as("129.134.27.1", false, "AS32934");
    assert_true($result, "facebook as match");

    $result = \BitFireBot\fast_verify_bot_as("129.134.27.1", false, "AS32934");
    assert_true($result, "FAST facebook as match");
    
    \BitFire\Config::set_value(\BitFire\CONFIG_CACHE_TYPE, 'shmop');
    
    $result = \BitFireBot\fast_verify_bot_as("129.134.27.1", false, "AS32934");
    assert_true($result, "facebook as match");

    $result = \BitFireBot\fast_verify_bot_as("129.134.27.1", false, "AS32934");
    assert_true($result, "FAST facebook as match");

}

/**
 * validate request rate
 */
function test_validate_rr() : void {
    $agent = "Mozilla/5.0 unit test browser";
    $ip = "127.0.0.1";
    $ip_data = \BitFire\IPData::make_new($agent, $ip);

    \BitFire\Config::set_value("rate_limit", "block");
    $ip_data->rr = 39;
    $block = \BitFireBot\validate_rr(40, $ip_data);
    assert_true($block->empty(), "sub threshold rate was incorrectly blocked");

    $ip_data->rr = 40;
    $block = \BitFireBot\validate_rr(40, $ip_data);
    assert_true($block->empty(), "sub threshold rate was incorrectly blocked");

    $ip_data->rr = 41;
    $block = \BitFireBot\validate_rr(40, $ip_data);
    assert_false($block->empty(), "above threshold rate was incorrectly NOT blocked");

    \BitFire\Config::set_value("rate_limit", "report");
    $ip_data->rr = 41;
    $block = \BitFireBot\validate_rr(40, $ip_data);
    assert_true($block->empty(), "REPORT about threshold rate was incorrectly blocked");

    \BitFire\Config::set_value("rate_limit", "report");
    $block = \BitFireBot\validate_rr(40, $ip_data);
    assert_true($block->empty(), "BLOCK about threshold rate was incorrectly blocked");
}

function test_ip_to_int() : void {
    $id = \BitFireBot\ip_to_int("127.0.0.1");
    assert_eq($id, 3619153832, "ip to int produced unexpected number");
    $id = \BitFireBot\ip_to_int("fe80::6ce4:e95c:5c83:8d91");
    assert_eq($id, 3624240963, "ip to int produced unexpected number");
}

function test_header_check() : void {
    $request = new \BitFire\Request();
    $request->host = "anormaldomainname.com";
    assert_true(\BitFireBot\header_check($request)->empty(), "normal domain name failed header check");

    $request->host = "a really long abnormal domain name with lots of crap in it and another whatever com";
    assert_false(\BitFireBot\header_check($request)->empty(), "normal domain name failed header check");
}

