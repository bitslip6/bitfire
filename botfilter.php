<?php
namespace BitFire;

use TF\Maybe;

const BOT_ANS_CODE_POS=2;
const BOT_ANS_OP_POS=1;
const BOT_ANS_ANS_POS=0;

const FAIL_HONEYPOT=50001;
const FAIL_PHPUNIT=50004;
const FAIL_WP_ENUM=50003;
const FAIL_METHOD=50002;
const FAIL_INVALID_DOMAIN=23001;
const FAIL_RR_TOO_HIGH=26001;

const FAIL_HOST_TOO_LONG=22001;

const FAIL_FAKE_WHITELIST=24001;
const FAIL_MISS_WHITELIST=24002;
const FAIL_IS_BLACKLIST=25001;

const BLOCK_LONG=3;
const BLOCK_MEDIUM=2;
const BLOCK_SHORT=1;
const BLOCK_NONE=0;
const BLOCK_WARN=-1;

const IPDATA_RR_1M='rr_1m';
const IPDATA_RR_5M='rr_5m';

const CONFIG_HONEYPOT='honeypot_url';
const CONFIG_METHODS='allowed_methods';
const CONFIG_WHITELIST='botwhitelist';
const CONFIG_RATE_LIMIT_ACTION='rate_limit_action';
const CONFIG_MFA_PAGES='mfa_pages';
const CONFIG_BLACKLIST='blacklist';


const AGENT_OS = 'os';
const AGENT_BROWSER = 'browser';
const AGENT_BOT = 'bot';
const AGENT_WHITELIST = 'whitelist';
const AGENT_BLACKLIST = 'blacklist';

const FAIL_DURATION = array(FAIL_HONEYPOT => BLOCK_LONG, FAIL_METHOD => BLOCK_SHORT);

const AGENT_MATCH = array(
        "opera" => "(opr)/\s*([\d+\.]+)",
        "chrome" => "(chrome)/\s*([\d+\.]+)",
        "firefox" => "(firefox)/?\s*([\d+\.]+)",
        "android" => "(android)/?\s*([\d+\.]+)",
        "safari" => "(safari)/\s*([\d+\.]+)",
        "edge" => "(edge)/\s*([\d+\.]+)",
        "explorer" => "(msie\s*|trident/)\s*([\d+\.]+)",
        "msie" => "(msie\s*|trident/[\d+\.]+;\s+rv:)\s*([\d+\.]+)",
        "vivaldi" => "(vivaldi)/\s*([\d+\.]+)",
        "bot" => "(\w+)\s*([\d+\.]+)"
    );


// 2 calls = 29: cpu
function match_fails(int $fail_code, MatchType $type, $request) : \TF\Maybe {
    if ($type->match($request)) {
        return BitFire::new_block($fail_code, $type->get_field(), $type->matched_data(), 'static match', FAIL_DURATION[$fail_code]??0);
    }

    return \TF\Maybe::$FALSE;
}

/**
 * TODO: add blocking for amazon, digital ocean, ms azure, google cloud 
 */
class BotFilter {

    public $browser;
    public $cache;

    protected $_ip_key;
    public $ip_data;

    protected $_constraints;

    public function __construct(\TF\CacheStorage $cache) {
        $this->cache = $cache;
        $this->_constraints = array(
            FAIL_PHPUNIT => new MatchType(MatchType::CONTAINS, REQUEST_PATH, '/phpunit', BLOCK_SHORT),
            FAIL_WP_ENUM => new MatchType(MatchType::CONTAINS, REQUEST_PATH, '/wp-json/wp/v2/users', BLOCK_SHORT),
            FAIL_HONEYPOT => new MatchType(MatchType::EXACT, REQUEST_PATH, Config::str(CONFIG_HONEYPOT, '/nosuchpath'), BLOCK_MEDIUM),
            FAIL_METHOD => new MatchType(MatchType::NOTIN, REQUEST_METHOD, Config::arr(CONFIG_METHODS), BLOCK_SHORT)
        );
    }

    protected function get_ip_data(string $remote_addr) {
        $this->_ip_key = "BITFIRE_IP_$remote_addr";
        $t = time();
        // todo: move ip data to bot filter
        $this->ip_data = $this->cache->update_data($this->_ip_key, function ($data) use ($t){

            if ($data['rr_1t'] < $t) { $data['rr_1m'] = 0; $data['rr_1t'] = $t+60; }
            if ($data['rr_5t'] < $t) { $data['rr_5m'] = 0; $data['rr_5t'] = $t+(60*5); }
            $data['rr_1m']++;
            $data['rr_5m']++;

            return $data;
        }, array('rr_5t' => $t+60*5, 'rr_5m' => 0, 'rr_1m' => 0, 'rr_1t' => $t+60, 'ref' => \substr(\uniqid(), 5, 8), '404' => 0, '500' => 0),
        60*6);
    }


    /**
     * inspect the UA, determine human or bot
     * perform human validation, bot white/black listing
     * 
     * TODO: simplify with Maybe
     * returns true if all tests pass
     * CPU: 359
     */
    public function inspect(array $request) : \TF\Maybe {

        // request has no host header
        if (Config::enabled(CONFIG_CHECK_DOMAIN)) {
            if (!\BitFireBot\validate_host_header(Config::arr(CONFIG_VALID_DOMAIN_LIST), $request)) {
                // allow valid whitelist bots to access the site
                if (!isset($this->browser[AGENT_WHITELIST])) {
                    $maybe = BitFire::new_block(FAIL_INVALID_DOMAIN, REQUEST_HOST, $request[REQUEST_HOST], \TF\en_json(Config::arr(CONFIG_VALID_DOMAIN_LIST)), BLOCK_MEDIUM);
                    if (!$maybe->empty()) { return $maybe; }
                }
            }
        }

        if (strlen($request[REQUEST_HOST]) > 80) {
            $maybe = BitFire::new_block(FAIL_HOST_TOO_LONG, "HTTP_HOST", $request[REQUEST_HOST], 'len < 80', BLOCK_SHORT);
            if (!$maybe->empty()) { return $maybe; }
        }

        // ugly, impure crap
        $this->get_ip_data($request[REQUEST_IP]);
    

        // bot tracking cookie
        $maybe_botcookie = \BitFireBot\decrypt_tracking_cookie(
            $request[REQUEST_COOKIE][Config::str(CONFIG_USER_TRACK_COOKIE)] ?? '',
            Config::str(CONFIG_ENCRYPT_KEY),
            $request[REQUEST_IP]);


        // get details about the agent
        $this->browser = \BitFireBot\parse_agent($request[REQUEST_UA]);
        $this->browser['valid'] = $maybe_botcookie->extract('v', 0)();

        // match constraints
        // TODO: better naming
        // cpu: 52
        $maybe_block = \TF\map_whilenot($this->_constraints, "\BitFire\match_fails", $request);
        $maybe_block->doifnot('\BitFireBot\validate_rr',
            Config::int(CONFIG_RR_1M), Config::int(CONFIG_RR_5M), $this->ip_data);


        // check the browser cookie answer matches the request
        // TODO: move to a function
        if ($request[REQUEST_PATH] === "/bitfire_browser_required") {
            exit(include WAF_DIR . "views/browser_required.phtml");
        }
        if (isset($_REQUEST[Config::str(CONFIG_USER_TRACK_PARAM)])) {
            $url = \BitFireBot\strip_path_tracking_params($request);
            // response answer matches cookie
            if (intval($maybe_botcookie->extract('a')()) === intval($_GET['_bfa'])) {
                \TF\CacheStorage::get_instance()->update_data('metrics-'.date('G'), function($data) { $data['valid'] = ($data['valid']??0) + 1; return $data; }, \BitFire\BITFIRE_METRICS_INIT, \TF\DAY);
                $valid_cookie = \TF\encrypt_ssl(Config::str(CONFIG_ENCRYPT_KEY),
                    \TF\en_json( array('ip' => $request[REQUEST_IP], 'v' => 2, 'et' => time() + 60*60)));
                \TF\cookie(Config::str(CONFIG_USER_TRACK_COOKIE), $valid_cookie, time() + \TF\DAY*30, false, true);
            } else {
                $url = "/bitfire_browser_required";
            }
            $foo = "Location: " . $request['SCHEME'] . '://' . $request['HOST'] . ":" . $request['PORT'] . "$url";
            header($foo);
            exit();
        }

        // handle robots
        if ($this->browser[AGENT_BOT]) {
            $this->browser[AGENT_WHITELIST] = false;
            if (Config::enabled(CONFIG_WHITELIST_ENABLE)) {
                $maybe_block->doifnot('\BitFireBot\whitelist_inspection',
                    $request[REQUEST_UA],
                    $request[REQUEST_IP],
                    Config::arr(CONFIG_WHITELIST));


                // set agent whitelist status
                $this->browser[AGENT_WHITELIST] = ($maybe_block->empty());
            } 
            else if (Config::enabled(CONFIG_BLACKLIST_ENABLE)) {
                $maybe_block->doifnot('\BitFireBot\blacklist_inspection', $request, file(WAF_DIR.'bad-agent.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));  
            }
        }
        // handle humans
        else if (Config::enabled(CONFIG_REQUIRE_BROWSER)) {
            \BitFireBot\require_browser_or_die($request, $maybe_botcookie);
        }

        return $maybe_block;
    }
}


namespace BitFireBot;

use BitFire\BitFire;
use BitFire\Block;
use BitFire\Config;
use TF\CacheStorage;

use function BitFire\reporting;

use const BitFire\AGENT_MATCH;
use const BitFire\BITFIRE_METRICS_INIT;
use const BitFire\BLOCK_MEDIUM;
use const BitFire\BLOCK_SHORT;
use const BitFire\CACHE_NAME_JS_SEND;
use const BitFire\CONFIG_ENCRYPT_KEY;
use const BitFire\CONFIG_REQUIRE_BROWSER;
use const BitFire\CONFIG_USER_TRACK_COOKIE;
use const BitFire\CONFIG_USER_TRACK_PARAM;
use const BitFire\FAIL_FAKE_WHITELIST;
use const BitFire\FAIL_IS_BLACKLIST;
use const BitFire\FAIL_MISS_WHITELIST;
use const BitFire\FAIL_RR_TOO_HIGH;
use const BitFire\IPDATA_RR_1M;
use const BitFire\IPDATA_RR_5M;
use const BitFire\REQUEST_HOST;
use const BitFire\REQUEST_IP;
use const BitFire\REQUEST_UA;

/**
 * test if the ipdata exceeds request rate
 * PURE
 */
function validate_rr(int $rr_1m, int $rr_5m, array $ip_data) : \TF\Maybe {
    if ($ip_data[IPDATA_RR_1M] > $rr_1m || $ip_data[IPDATA_RR_5M] > $rr_5m) {
        return BitFire::new_block(FAIL_RR_TOO_HIGH, 'REQUEST_RATE', 
        $ip_data[IPDATA_RR_1M] . ' / ' . $ip_data[IPDATA_RR_5M], "$rr_1m / $rr_5m", BLOCK_MEDIUM);
    }
    return \TF\Maybe::$FALSE;
}

/**
 * do a reverse lookup and return true if remote_ip matches network_regex
 * depends on ip lookup 
 */
function verify_bot_ip(string $remote_ip, string $network_regex) : bool {
    // check if the remote IP is in an allowed list of IPs
    //\TF\dbg("$remote_ip / $network_regex");
    $ip_checks = (strpos($network_regex, ',') > 0) ? explode(',', $network_regex) : array($network_regex);
    $ip_matches = array_reduce($ip_checks, \TF\is_regex_reduced($remote_ip), false);
    if ($ip_matches) { return true; }

    // fwd and reverse lookup
    $ip = \TF\reverse_ip_lookup($remote_ip)
        ->then(function($value) use ($ip_checks) {
//\TF\dbg("v: $value, ch: $ip_checks\n");
            return array_reduce($ip_checks, \TF\find_regex_reduced($value), false);
        })->then('TF\\fast_ip_lookup');

    return $ip() === $remote_ip;
}

function fast_verify_bot_as(string $remote_ip, string $network) : bool {
    return \TF\memoize('\BitFireBot\verify_bot_as', "_bf_as_{$network}_{$remote_ip}", 3600)($remote_ip, $network);
}

// verify that $remote ip is part of the AS network number $network
// depends on whois in system path
// EXEC CALL
function verify_bot_as(string $remote_ip, string $network) : bool {
    $network = escapeshellarg("-i origin " . substr($network, 0, 8));
    $match = (\TF\is_ipv6($remote_ip)) ?
        array_slice(explode(":", $remote_ip), 0, 2) :
        array_slice(explode(".", $remote_ip), 0, 3);
    $cmd = "whois -h whois.radb.net -- $network | grep " . escapeshellarg(join('.', $match));
    $result = exec($cmd);
    return stristr($result, "route") !== false;
}

// return false if valid_domains has entries and request['host'] is not in it
// true otherwise
// PURE
function validate_host_header(array $valid_domains, array $request) : bool {
    return (!empty($valid_domains)) ?
        \TF\in_array_ending($valid_domains, $request[REQUEST_HOST]??'') :
        true;
}

/**
 * test if an agent is found in a list of agents
 * $botlist is format "agent match str":reverse ip network:human comment
 * -1 - no UA match, 0 UA match net fail, 1 UA and net match
 */
function agent_in_list(string $a, string $ip, array $list) : int {
    if (empty($a) || strlen($a) <= 1 || count($list) < 1) { return false; }

    foreach ($list as $k => $v) {

        if (strpos($a, $k) === false) { continue; }
        if ($v === "*") { return 1; }

        // reverse lookup, or just return found
        $r = (substr($v, 0, 2) == "AS") ?
            \BitFireBot\fast_verify_bot_as($ip, $v) :
            \BitFireBot\verify_bot_ip($ip, $v);
        return ($r) ? 1 : 0;
    }

    // no match, return false
    return -1;
}

/**
 * check if agent is in whitelist, true if we have whitelist and no match, false if no whitelist, bock if 
 * NOT PURE: depends on external dns and whois
 */
function whitelist_inspection(string $agent, string $ip, array $whitelist) : \TF\Maybe {
    // configured to only allow whitelisted bots, so we can block here 
    // handle whitelisting (the most restrictive)
    // return true(pass) if the agent is in the list of whitelist bots
    if (count($whitelist) > 0) {
        $r = agent_in_list($agent, $ip, $whitelist);
        if ($r < 0) { return BitFire::new_block(FAIL_MISS_WHITELIST, REQUEST_UA, $agent, "user agent whitelist", BLOCK_SHORT); }
        if ($r == 0) { return BitFire::new_block(FAIL_FAKE_WHITELIST, REQUEST_UA, $agent, "user agent whitelist", BLOCK_SHORT); }
    }
    return \TF\Maybe::$FALSE;
}

/**
 * returns true if the useragent / ip is not blacklisted, false otherwise
 * PURE
 */
function blacklist_inspection(array $request, ?array $blacklist) : \TF\Maybe {
    $match = new \BitFire\MatchType(\BitFire\MatchType::CONTAINS, REQUEST_UA, $blacklist, BLOCK_MEDIUM);
    $part = $match->match($request);
    if ($part !== false) {
        return BitFire::new_block(FAIL_IS_BLACKLIST, "user-agent", $request[REQUEST_UA], $part, BLOCK_MEDIUM);
    }
   
    return \TF\Maybe::$FALSE;
}


/**
 * this function takes a useragent and turns it into an array with os, browser, bot and ver
 * return array('os', 'browser', 'ver', 'bot':bool)
 * PURE
 * total: 58 
 * return array("os" => $os, "browser" => $browser[0], "ver" => $browser[1], "bot" => $browser[0] === "bot");
 */
function parse_agent(string $user_agent) : array {

    $user_agent = strtolower($user_agent);
    $agent = array("os" => "bot", "browser" => "bot", "ver" => "x", "bot" => true);
    // return robots...
    if (substr($user_agent, 0, 11) !== "mozilla/5.0") {
        return $agent;
    }

    // cpu: 50, could rewrite as imperative and save here
    $os_list = array("linux", "android", "os x", "windows", "iphone", "ipad");
    $os = array_reduce($os_list, function(string $cry, string $os) use ($user_agent) {
        return (strpos($user_agent, $os) !== false) ? $os : $cry;
    }, "bot");


    // cpu: 50, could rewrite as imperative and save here
    $browser = array_reduce(AGENT_MATCH, function(array $cry, string $browser) use ($user_agent) {
        if ($cry[0] === "bot") {
            preg_match("!$browser!", $user_agent, $matches);
            return (isset($matches[2])) ? array_slice($matches, 1, 2) : $cry;
        }
        return $cry;
    }, array("bot", "1.0"));

    return array("os" => $os, "browser" => $browser[0], "ver" => $browser[1], "bot" => $browser[0] === "bot");
}

/**
 * Calculate a javascript bot response answer
 * returns the result of a random operation 
 * of n1 and n2 with JS code to perform the operation
 * TODO: unit tests
 * PURE
 */
function bot_calc_answer(int $n1, int $n2, int $op) : array {
    $ans = array(0, 0, 0);
    $ans[\BitFire\BOT_ANS_OP_POS] = $op;
    switch($op) {
        case 1:
            $ans[\BitFire\BOT_ANS_ANS_POS] = $n1 * $n2;
            $ans[\BitFire\BOT_ANS_CODE_POS] = "($n1*$n2)";
            break;
        case 2:
            $ans[\BitFire\BOT_ANS_ANS_POS] = $n1 / $n2;
            $ans[\BitFire\BOT_ANS_CODE_POS] = "($n1/$n2)";
            break;
        case 3:
            $ans[\BitFire\BOT_ANS_ANS_POS] = $n1 + $n2;
            $ans[\BitFire\BOT_ANS_CODE_POS] = "($n1+$n2)";
            break;
        default:
            $ans[\BitFire\BOT_ANS_ANS_POS] = $n1 - $n2;
            $ans[\BitFire\BOT_ANS_CODE_POS] = "($n1-$n2)";
            break;
    }
    return $ans;
}

//TODO: make encrypt cookie fun and compose then replace with upper call
// also extract js answer code

/**
 * returns a maybe with tracking data or an empty monad...
 * PURE!
 */
function decrypt_tracking_cookie(?string $cookie_data, string $encrypt_key, string $src_ip) : \TF\Maybe {
    return \TF\decrypt_ssl($encrypt_key, $cookie_data)
        ->then("TF\un_json")
        ->if(function($cookie) use ($src_ip) { 
            return ((($cookie['ip'] ?? '') === $src_ip) && (($cookie['et'] ?? 0) > time()));
        });
}


/**
 * make a new js challenge script and set a cookie
 * NOT PURE, SETS CLIENT COOKIE!
 */
function make_js_challenge(string $ip, string $tracking_param, string $encrypt_key, string $utc_name) : string {
    $n1 = intval(decoct(rand(1000,500000)));
    $n2 = intval(decoct(rand(12,2000)));
    $answer = \BitFireBot\bot_calc_answer($n1, $n2, rand(1,4));

    $js  = "function _0x8bab5c(){var _0x29a513=function(){var _0x4619fc=!![];return function(_0x579b4a,_0x4b417a){var _0x13068=_0x4619fc?function(){if(_0x4b417a){var _0x193a80=_0x4b417a['apply'](_0x579b4a,arguments);_0x4b417a=null;return _0x193a80;}}:function(){};_0x4619fc=![];return _0x13068;};}();var _0x2739c0=_0x29a513(this,function(){var _0x51ace=function(){var _0x5125f4=_0x51ace['constructor']('return\x20/\x22\x20+\x20this\x20+\x20\x22/')()['constructor']('^([^\x20]+(\x20+[^\x20]+)+)+[^\x20]}');return!_0x5125f4['test'](_0x2739c0);};return _0x51ace();});_0x2739c0();return {$answer[\BitFire\BOT_ANS_CODE_POS]};}";
    $js .= '
    function BITB() { var u=new URL(window.location.href); 
var e=document; 
if (!e._bitfire) { 
e._bitfire=1; 
t=screen.width+"_"+screen.height;
n=(new Date).getTimezoneOffset(); 
var p=u.searchParams;
p.append("'.$tracking_param.'", 1);
p.append("_bfa",_0x8bab5c());
p.append("_bfx",t);
p.append("_bfz",n);
window.location.replace(u);
} } BITB(); ';

    $crypt = \TF\encrypt_ssl($encrypt_key, make_challenge_cookie($answer, $ip));


    \TF\cookie($utc_name, $crypt, time() + 60*10, false, true);
    return "<script>{$js}</script>";
}


// make a json encoded challenge cookie that expires in 1 minute
function make_challenge_cookie(array $answer, string $ip) : string {
    assert(count($answer) >= \BitFire\BOT_ANS_ANS_POS, "unable to make challenge cookie with bad answer value");

    return json_encode(
        array(
            'et' => time() + 60*10,
            'v' => 1,
            'a' => $answer[\BitFire\BOT_ANS_ANS_POS],
            'ip' => $ip
        )
    );
}

/**
 * add the page that prompts the browser to add a cookie
 */
function require_browser_or_die(array $request, \TF\Maybe $cookie) {
    if (intval($cookie->extract('v')()) >= 2) { return; }


    $data = \TF\CacheStorage::get_instance()->update_data('metrics-'.date('G'), function($data) { $data['challenge'] = ($data['challenge']??0) + 1; return $data; }, \BitFire\BITFIRE_METRICS_INIT, \TF\DAY);
    http_response_code(202);
    $block = BitFire::new_block(20000, 'n/a', 'n/a', 'check JS/Cookies', 0);
    echo make_js_challenge($request[REQUEST_IP], Config::str(CONFIG_USER_TRACK_PARAM), 
        Config::str(CONFIG_ENCRYPT_KEY), Config::str(CONFIG_USER_TRACK_COOKIE)) . "\n";

    if (Config::str(CONFIG_REQUIRE_BROWSER, "report") === "block") { exit(); }
}

function strip_path_tracking_params(array $request) {
    unset($request['GET']['_bfa']) ;
    unset($request['GET']['_bfx']) ;
    unset($request['GET']['_bfz']) ;
    unset($request['GET'][Config::str(CONFIG_USER_TRACK_PARAM)]) ;
    return($request['PATH'] . '?' . http_build_query($request['GET']));
}

