<?php
namespace BitFire;

use function BitFireBot\bot_calc_answer;
use function TF\parse_ini;

/*
const BOT_ANS_OP2=4;
const BOT_ANS_OP1=3;
const BOT_ANS_CODE_POS=2;
const BOT_ANS_OP_POS=1;
const BOT_ANS_ANS_POS=0;
*/

class JS_Fn {
    public $js_code;
    public $fn_name;
    public function __construct($code, $name) {
        $this->js_code = $code;
        $this->fn_name = $name;
    }
}


const AGENT_MATCH = array(
        "brave" => "(brave)/\s*([\d+\.]+)",
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

class IPData {
    public $rr;
    public $rr_time;
    public $ref;
    public $ip_crc;
    public $ua_crc;
    public $ctr_404 = 0;
    public $ctr_500 = 0;
    public $valid = 0;
    public $op1 = 0;
    public $op2 = 0;
    public $oper = 0;
    public $ans = '';

    public function __construct(int $ip_crc, int $ua_crc) {
        $this->ip_crc = $ip_crc;
        $this->ua_crc = $ua_crc;
    }

    public function make_new(string $ip, string $ua) : IPData {
        $data = new IPData(\BitFireBot\ip_to_int($ip), crc32($ua));
        $data->rr = 0;
        $data->rr_time = time() + 5*60;
        $data->ref = mt_rand(0, mt_getrandmax());
        return $data;
    }
}

/*
$data = IPData::make_new("127.0.0.1", "Mozilla/5.0 chrome 125");
print_r($data);
echo "\n";
die("hit\n");
$j = json_encode($data);
print_r($j);
echo "\n" . strlen($j) . " \n";
$s = serialize($data);
print_r($s);
echo "\n" . strlen($s) . " \n";
//4 4 2 2 1 2 4
//$p = pack("iiSSCSI", $data->ip_crc, $data->ua_crc, $data->ctr_404, $data->ctr_500, $data->valid, $data->rr, $data->rr_time);
var_dump($data->ip_crc);
//$p = pack("L", $data->ip_crc);
$q = 50821;
$t1 = pack("NN", $data->ip_crc, $data->ua_crc);
$a1 = unpack("Nip/Nua", $t1);
echo "($q) ANS: [" . $a1['ip'] . "] ( " . $a1['ua'] . ") \n";
die();

$p = pack("N", $data->ip_crc);
//printf("%d %d %d %d\n", $p[0], $p[1], $p[2], $p[3]);
printf("%d\n", $p);
echo "\n[$p] (" . strlen($p) . ")\n";
$a = unpack("Nip", $p) . "\n\n";
echo "IP: " . $a['ip'] . "\n";
/*
print_r($a['ip']);
var_dump($a);
var_dump($a[0]);
var_dump($a[1]);
var_dump($a[2]);
var_dump($a[3]);
die("hit\n");
*/

class Answer {
    public $op1;
    public $op2;
    public $oper;
    public $ans;
    public $code;
    
    public function __construct(int $op1, int $op2, int $oper) {
        $this->op1 = $op1;
        $this->op2 = $op2;
        $this->oper = $oper;
        switch($oper) {
            case 1:
                $this->ans = $op1 * $op2;
                $this->code = "($op1*$op2)";
                break;
            case 2:
                $this->ans = $op1 / $op2;
                $this->code = "($op1/$op2)";
                break;
            case 3:
                $this->ans = $op1 + $op2;
                $this->code = "($op1+$op2)";
                break;
            default:
                $this->ans = $op1 - $op2;
                $this->code = "($op1-$op2)";
                break;
        }
    }
}

class Challenge {
    public $expire_time;
    public $valid;
    public $answer;
    public $ip;
    public $ua_crc;

    //public function __construct(string $ip, int $valid, int $exp_time, string $ua, $answer) {
    protected function __construct(int $ip_int, int $valid, int $ua_crc, int $exp_time, $answer) {
        $this->ip = $ip_int;
        $this->valid = $valid;
        $this->answer = $answer;
        $this->expire_time = time() + $exp_time;
        $this->ua_crc = $ua_crc;
    }

    public static function new(string $ip_str, int $valid, string $ua_str, int $exp_time, $answer) {
        return new Challenge(\BitFireBot\ip_to_int($ip_str), $valid, crc32($ua_str), $exp_time, $answer);
    }
}


// 2 calls = 29: cpu
function match_fails(int $fail_code, MatchType $type, \BitFire\Request $request) : \TF\MaybeBlock {
    if ($type->match($request)) {
        return BitFire::new_block($fail_code, $type->get_field(), $type->matched_data(), 'static match', FAIL_DURATION[$fail_code]??0);
    }

    return \TF\Maybe::$FALSE;
}

// create a new ip_data local cache entry
function new_ip_data($remote_addr, $agent) : string { 
    $answer = new Answer(mt_rand(1000,500000), mt_rand(12,4000), mt_rand(1,4));
    $data = array('ip' => \BitFireBot\ip_to_int($remote_addr), 'ua' => crc32($agent), 'ctr_404' => 0, 'valid' => 0, 
        'ctr_500' => 0, 'rr' => 0, 'rrtime' => 0, 'op1' => $answer->op1, 'op2' => $answer->op2, 'oper' => $answer->oper);
    return pack_ip_data($data);
}

/**
 * map a locally stored data array into an IPData object
 */
function map_ip_data(string $ip_data) : IPData {
    $data = unpack_ip_data($ip_data);
    $ip = new IPData($data['ip']??0, $data['ua']??0);
    $ip->ctr_404 = $data['ctr_404']??0;
    $ip->ctr_500 = $data['ctr_500']??0;
    $ip->rr = $data['rr']??0;
    $ip->rr_time = $data['rrtime']??0;
    $ip->valid = $data['valid']??0;
    $ip->ans = $data['ans']??0;
    $ip->op1 = $data['op1']??0;
    $ip->op2 = $data['op2']??0;
    $ip->oper = $data['oper']??0;
    return $ip;
}

function unpack_ip_data(string $data) : array {
    $d = unpack("Nip/Nua/Sctr_404/Sctr_500/Srr/Nrrtime/Cvalid/Nop1/Nop2/Coper", $data);
    \TF\debug("x-read-ans: " . $d['op1'] . " . " . $d['op2'] . " . " . $d['oper']);
    return $d;
}

function pack_ip_data(array $ip_data) : string {
    $t1 = pack("NNSSSNCNNC*", $ip_data['ip'], $ip_data['ua'], $ip_data['ctr_404'], $ip_data['ctr_500'], $ip_data['rr'], $ip_data['rrtime'], $ip_data['valid'], $ip_data['op1'], $ip_data['op2'], $ip_data['oper']);
    return $t1;
}

/**
 * load the local data for the remote IP
 */
function get_ip_data(string $remote_addr, string $agent) : IPData {

    $ip_key = "BITFIRE_IP_$remote_addr";
    \TF\debug("x-cache-key: [$ip_key]");
    $data = \TF\CacheStorage::get_instance()->update_data($ip_key, function ($data) {

        $t = time();
        $ip_data = unpack_ip_data($data);

        // update request rate counter
        if ($ip_data['rrtime'] < $t) { $ip_data['rr'] = 0; $ip_data['rrtime'] = $t+(60*5); }
        $ip_data['rr']++;

        return pack_ip_data($ip_data);
    }, function() use ($remote_addr, $agent) { return \BitFire\new_ip_data($remote_addr, $agent); },
    60*10);

    return map_ip_data($data);
}


/**
 * TODO: add blocking for amazon, digital ocean, ms azure, google cloud 
 */
class BotFilter {

    public $browser;
    public $cache;

    public $ip_data = array();

    protected $_constraints;

    public function __construct(\TF\CacheStorage $cache) {
        $this->cache = $cache;
        $this->_constraints = array(
            FAIL_PHPUNIT => new MatchType(MatchType::CONTAINS, "path", '/phpunit', BLOCK_SHORT),
            FAIL_WP_ENUM => new MatchType(MatchType::CONTAINS, "path", '/wp-json/wp/v2/users', BLOCK_SHORT),
            FAIL_HONEYPOT => new MatchType(MatchType::EXACT, "path", Config::str(CONFIG_HONEYPOT, '/nosuchpath'), BLOCK_MEDIUM),
            FAIL_METHOD => new MatchType(MatchType::NOTIN, "method", Config::arr(CONFIG_METHODS), BLOCK_SHORT)
        );

    }

    

    /**
     * inspect the UA, determine human or bot
     * perform human validation, bot white/black listing
     * 
     * CPU: 359
     */
    public function inspect(\BitFire\Request $request) : \TF\MaybeBlock {

        // handle wp-cron and other self requested pages
        if (Config::enabled("skip_local_bots") &&
            (\BitFireBot\is_local_request($request) || \BitFireBot\is_local_wordpress($request))) {
            return \TF\Maybe::$FALSE;
        }

        // ignore urls that receive consistant bot access that may be difficult to identify
        if (in_array($request->path, Config::arr("ignore_bot_urls"))) {
            return \TF\Maybe::$FALSE;
        }

        // request has no host header
        if (Config::enabled(CONFIG_CHECK_DOMAIN)) {
            if (!\BitFireBot\validate_host_header(Config::arr(CONFIG_VALID_DOMAIN_LIST), $request->host)) {
                // allow valid whitelist bots to access the site
                if (!isset($this->browser[AGENT_WHITELIST])) {
                    $maybe = BitFire::new_block(FAIL_INVALID_DOMAIN, "host", $request->host, \TF\en_json(Config::arr(CONFIG_VALID_DOMAIN_LIST)), BLOCK_MEDIUM);
                    if (!$maybe->empty()) { return $maybe; }
                }
            }
        }

        if (strlen($request->host) > 80) {
            $maybe = BitFire::new_block(FAIL_HOST_TOO_LONG, "HTTP_HOST", $request->host, 'len < 80', BLOCK_SHORT);
            if (!$maybe->empty()) { return $maybe; }
        }

        // ugly, impure crap
        $this->ip_data = get_ip_data($request->ip, $request->agent);
    
        //echo Config::str(CONFIG_USER_TRACK_COOKIE) . "\n";
        //echo Config::str(CONFIG_ENCRYPT_KEY) . "\n";
        //print_r($request->ip);

        // get details about the agent
        $this->browser = \BitFireBot\parse_agent($request->agent);
        $this->browser[AGENT_WHITELIST] = false;

        // match constraints
        // TODO: better naming
        // cpu: 52
        $maybe_block = \TF\map_whilenot($this->_constraints, "\BitFire\match_fails", $request);
        $maybe_block->doifnot('\BitFireBot\validate_rr', Config::int(CONFIG_RR_5M), $this->ip_data);

        // bot tracking cookie
        $maybe_botcookie = \BitFireBot\decrypt_tracking_cookie(
            $_COOKIE[Config::str(CONFIG_USER_TRACK_COOKIE)] ?? '',
            Config::str(CONFIG_ENCRYPT_KEY),
            $request->ip);

        // set browser validity to cookie value or server ip data
        $this->browser['valid'] = max($this->ip_data->valid, $maybe_botcookie->extract('v', 0)->value('int'));
        \TF\debug("x-valid: ". $this->browser['valid'] . " ip_data: " . $this->ip_data->valid);

        // check the browser cookie answer matches the request
        // TODO: move to a function
        if ($request->path === "/bitfire_browser_required") {
            exit(include WAF_DIR . "views/browser_required.phtml");
        }
        if (Config::enabled(CONFIG_REQUIRE_BROWSER) && $this->browser['valid'] < 2 && isset($_REQUEST[Config::str(CONFIG_USER_TRACK_PARAM)])) {
            
            \TF\debug("x-valid-check: ". $_REQUEST[Config::str(CONFIG_USER_TRACK_PARAM)]);
            $url = \BitFireBot\strip_path_tracking_params($request);

            $answer = new Answer($this->ip_data->op1, $this->ip_data->op2, $this->ip_data->oper);
            $response = ($answer->ans != 0) ? $answer->ans : $maybe_botcookie->extract('a')->value('int');
            \TF\debug("x-valid-ans: ($response) - ({$answer->ans})");

            // response answer matches cookie
            if (intval($response) === intval($_GET['_bfa'])) {
                \TF\debug("x-challenge: pass");
                \TF\CacheStorage::get_instance()->update_data('metrics-'.\TF\utc_date('G'), function($data) { $data['valid'] = ($data['valid']??0) + 1; return $data; }, function() { return BITFIRE_METRICS_INIT; }, \TF\DAY);
                if (Config::enabled(CONFIG_COOKIES)) {
                    \TF\debug("x-challenge-type: config_cookie");
                    $valid_cookie = \TF\encrypt_ssl(Config::str(CONFIG_ENCRYPT_KEY), 
                        \TF\en_json( array('ip' => $request->ip, 'v' => 2, 'et' => time() + 60*60)));
                    \TF\cookie(Config::str(CONFIG_USER_TRACK_COOKIE), $valid_cookie, time() + \TF\DAY*30, false, true);
                } else {
                    \TF\debug("x-challenge-type: shmop");
                    $ip_key = "BITFIRE_IP_{$request->ip}";
                    $this->cache->update_data($ip_key, function ($data) {
                        $ip_data = unpack_ip_data($data);
                        \TF\debug("x-challenge-type-valid: [{$ip_data['valid']}]");
                        $ip_data['valid'] = 2;
                        return pack_ip_data($ip_data);
                    }, function() use ($remote_addr, $agent) { return \BitFire\new_ip_data($remote_addr, $agent); },
                    60*10);
                }
            } else {
                \TF\debug("x-challenge: fail [$response] - [{$_GET['_bfa']}]");
                $url = "/bitfire_browser_required";
            }
            $request->scheme = \BitFireBot\force_ssl_scheme($request);
            $port = ($request->port == 80 && $request->scheme != 'http') ? '' : ":{$request->port}";
            $foo = "Location: " . $request->scheme . '://' . $request->host . $port . \TF\cache_bust($url);
            header($foo);
            exit();
        }

        // handle robots
        if ($this->browser[AGENT_BOT]) {
            $this->browser[AGENT_WHITELIST] = false;
            if (Config::enabled(CONFIG_WHITELIST_ENABLE) && $maybe_block->empty()) {
                $agents = \parse_ini_file(WAF_DIR."cache/whitelist_agents.ini");
                $maybe_block->doifnot('\BitFireBot\whitelist_inspection',
                    $request->agent,
                    $request->ip,
                    $agents['botwhitelist']);

                // set agent whitelist status
                $this->browser[AGENT_WHITELIST] = ($maybe_block->empty());
            }
            else if (Config::enabled(CONFIG_BLACKLIST_ENABLE)) {
                $maybe_block->doifnot('\BitFireBot\blacklist_inspection', $request, file(WAF_DIR.'cache/bad-agent.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));  
            }
        }
        // handle humans
        else if (Config::enabled(CONFIG_REQUIRE_BROWSER)) {
            if ($request->ajax === false && $this->browser['valid'] < 2) {
                \BitFireBot\require_browser_or_die($request, $maybe_botcookie, $this->ip_data);
            } else {
                \TF\debug("x-bitfire-req: [" . $request->ajax . " - " . $this->browser['valid'] . "]");
            }
        }

        return $maybe_block;
    }
}


namespace BitFireBot;

use BitFire\Answer;
use BitFire\BitFire;
use BitFire\Block;
use BitFire\Challenge;
use BitFire\Config;
use BitFire\JS_Fn;
use BitFire\Request;
use TF\CacheStorage;

use function BitFire\reporting;

use const BitFire\AGENT_MATCH;
use const BitFire\BITFIRE_METRICS_INIT;
use const BitFire\BLOCK_MEDIUM;
use const BitFire\BLOCK_SHORT;
use const BitFire\CONFIG_ENCRYPT_KEY;
use const BitFire\CONFIG_REQUIRE_BROWSER;
use const BitFire\CONFIG_USER_TRACK_COOKIE;
use const BitFire\CONFIG_USER_TRACK_PARAM;
use const BitFire\FAIL_FAKE_WHITELIST;
use const BitFire\FAIL_IS_BLACKLIST;
use const BitFire\FAIL_MISS_WHITELIST;
use const BitFire\FAIL_RR_TOO_HIGH;



/**
 * convert an IP to a 32bit int.  possible collisions for ipv6 addrs.  unlikely to be significant
 */
function ip_to_int(string $ip) : int {
    if (strchr($ip, ":") !== false) { return ip2long($ip); }
    else { return crc32($ip); }
}

/**
 * return true for local wordpress requests (ie: wp-cron, etc)
 */
function is_local_wordpress(\BitFire\Request $request) : bool {
    return (\TF\ends_with($request->path, '/wp-cron.php') && strstr($request->agent, 'wordpress/') != false);
}

/**
 * return true if the request is from the local server
 */
function is_local_request(\BitFire\Request $request) {
    return ($_SERVER['REMOTE_ADDR'] === $_SERVER['SERVER_ADDR']);
}
/**
 * force ssl scheme if host is unwrapping SSL for us, could be faked, but then
 */
function force_ssl_scheme(\BitFire\Request $request) : string {
    // only allow http or https for forwarded_proto
    $r = (isset($_SERVER['HTTP_X_FORWARDED_PROTO'])) ? $_SERVER['HTTP_X_FORWARDED_PROTO'] : $request->scheme;
    return (in_array($r, array('http', 'https'))) ? $r : $request->scheme;
}

/**
 * test if the ipdata exceeds request rate
 * PURE
 */
function validate_rr(int $rr_5m, \BitFire\IPData $ip_data) : \TF\MaybeBlock {
    if ($ip_data->rr > $rr_5m) {
        return BitFire::new_block(FAIL_RR_TOO_HIGH, 'REQUEST_RATE', $ip_data->rr, "$rr_5m", BLOCK_MEDIUM);
    }
    return \TF\Maybe::$FALSE;
}

/**
 * do a reverse lookup and return true if remote_ip matches network_regex
 * depends on ip lookup 
 */
function verify_bot_ip(string $remote_ip, string $network_regex) : bool {
    // check if the remote IP is in an allowed list of IPs
    $ip_checks = (strpos($network_regex, ',') > 0) ? explode(',', $network_regex) : array($network_regex);
    $ip_matches = array_reduce($ip_checks, \TF\is_regex_reduced($remote_ip), false);
    if ($ip_matches) { return true; }

    // fwd and reverse lookup
    $ip = \TF\reverse_ip_lookup($remote_ip)
        ->then(function($value) use ($ip_checks) {
            return array_reduce($ip_checks, \TF\find_regex_reduced($value), false);
        })->then('TF\\fast_ip_lookup');

    return $ip() === $remote_ip;
}

function fast_verify_bot_as(string $remote_ip, string $network) : bool {
    return \TF\memoize('\BitFireBot\verify_bot_as', "_bf_as_{$network}_{$remote_ip}", 3600)($remote_ip, $network);
}

// verify that $remote ip is part of the AS network number $network
function verify_bot_as(string $remote_ip, string $network) : bool {
    $x = \TF\MaybeA::of(fsockopen("whois.radb.net", 43, $no, $str, 1))
        ->effect(\TF\partial_right('\fputs', "$remote_ip\r\n"))
        ->then('\TF\read_stream')
        ->if(\TF\partial_right('stristr', $network));
        return $x->empty() ? false : true;
}

function is_ip_in_cidr_list(string $remote_ip, array $routes) : bool {

    if (\TF\is_ipv6($remote_ip)) {
        $ip_bytes = unpack('n*', inet_pton($remote_ip));
        return array_reduce($routes, function($carry, string $route) use ($ip_bytes, $remote_ip) {
            [$route_ip, $netmask] = explode('/', $route, 2);
            $netmask = intval($netmask);
            $route_bytes = unpack('n*', @inet_pton($route_ip));

            for ($i = 1, $ceil = ceil($netmask / 16); $i <= $ceil; ++$i) {
                $left = $netmask - 16 * ($i - 1);
                $left = ($left <= 16) ? $left : 16;
                $mask = ~(0xffff >> $left) & 0xffff;
                if (($ip_bytes[$i] & $mask) != ($route_bytes[$i] & $mask)) {
                    return false;
                }
            }
            return true;
        }, false);
    } else {
        $s1 = sprintf('%032b', ip2long($remote_ip));
        return array_reduce($routes, function($carry, string $route) use ($s1) {
            if ($carry === 0) { return $carry; }
            [$ip, $netmask] = explode('/', $route, 2);
            return substr_compare($s1, sprintf('%032b', ip2long($ip)), 0, intval($netmask));
        }, 1) === 0;
    }
}

/**
 * parse all lines of whois route lookup 
 */
function parse_whois_route(string $output) : ?array {
    return array_map('\BitFireBot\parse_whois_line', explode("\n", $output));
}

/**
 * parse 'route    : 1.2.3.4/24' into '1.2.3.4/24'
 */
function parse_whois_line(string $line) : string {
    $parts = explode(": ", $line);
    return trim($parts[1]??'');
}

// return false if valid_domains has entries and request['host'] is not in it
// true otherwise
// PURE
function validate_host_header(array $valid_domains, string $host) : bool {
    return (!empty($valid_domains)) ?
        \TF\in_array_ending($valid_domains, $host) :
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
function whitelist_inspection(string $agent, string $ip, ?array $whitelist) : \TF\MaybeBlock {
    // configured to only allow whitelisted bots, so we can block here 
    // handle whitelisting (the most restrictive)
    // return true(pass) if the agent is in the list of whitelist bots
    if (count($whitelist) > 0) {
        $r = agent_in_list($agent, $ip, $whitelist);
        if ($r < 0) { return BitFire::new_block(FAIL_MISS_WHITELIST, "user_agent", $agent, "user agent whitelist", BLOCK_SHORT); }
        if ($r == 0) { return BitFire::new_block(FAIL_FAKE_WHITELIST, "user_agent", $agent, "user agent whitelist", BLOCK_SHORT); }
    }
    return \TF\Maybe::$FALSE;
}

/**
 * returns true if the useragent / ip is not blacklisted, false otherwise
 * PURE
 */
function blacklist_inspection(\BitFire\Request $request, ?array $blacklist) : \TF\MaybeBlock {
    $match = new \BitFire\MatchType(\BitFire\MatchType::CONTAINS, "agent", $blacklist, BLOCK_MEDIUM);
    $part = $match->match($request);
    if ($part !== false) {
        return BitFire::new_block(FAIL_IS_BLACKLIST, "user_agent", $request->agent, $part, BLOCK_MEDIUM);
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
    $browser = array_reduce(array_keys(AGENT_MATCH), function(array $cry, string $match_key) use ($user_agent) {
        if ($cry[0] === "bot") {
            $pattern = AGENT_MATCH[$match_key];
            preg_match("!$pattern!", $user_agent, $matches);
            return (isset($matches[2])) ? [$match_key, $matches[1], $matches[2]] : $cry;
        }
        return $cry;
    }, array("bot", "bot", "1.0"));

    return array("os" => $os, "whitelist" => false, "browser" => $browser[1], "ver" => $browser[2], "bot" => $browser[0] === "bot");
}


//TODO: make encrypt cookie fun and compose then replace with upper call
// also extract js answer code

/**
 * returns a maybe with tracking data or an empty monad...
 * PURE!
 */
function decrypt_tracking_cookie(?string $cookie_data, string $encrypt_key, string $src_ip) : \TF\MaybeStr {
    $f = \TF\decrypt_ssl($encrypt_key, $cookie_data)
        ->then("TF\\un_json")
        ->if(function($cookie) use ($src_ip) {
            return ((($cookie['ip'] ?? '') === $src_ip) && (($cookie['et'] ?? 0) > time()));
        });
    return $f;
}

function js_fn(string $fn_name) : callable {
    return function($arg) use ($fn_name) { return "{$fn_name}($arg)"; };
}

function js_int_obfuscate(int $number) : JS_Fn {
    // convert ascii printable character range (32-126) to actual char values, shuffle the result array and turn into string
    $z = join('', \TF\array_shuffle(array_map(function($x) { return chr($x); }, range(32, 126))));
    // dictionary name, function name, 
    $num_str = strval($number);
    $dict_name = 'z' . \TF\random_str(5);
    $fn_name = 'x' . \TF\random_str(5);

    $char_fn = js_fn("+{$dict_name}.charAt");
    $js_code = "function $fn_name() { return " .
        "let {$dict_name}='".addslashes($z)."';" . 
        \TF\each_character($num_str, function (string $c, int $idx) use ($z, $num_str, $char_fn) : string {
            $idx = strpos($z, $num_str[$idx]);
            return $char_fn($idx);
        });
    return new JS_Fn($js_code, $fn_name);
}

/**
 * make a new js challenge script and set a cookie
 * NOT PURE, SETS CLIENT COOKIE!
 */
function make_js_challenge(\BitFire\IPData $ip) : string { // }, string $tracking_param, string $encrypt_key, string $utc_name) : string {
    \TF\debug("x-challenge: sent " . $ip->op1 . " [{$ip->oper}] " . $ip->op2);
    //$n1 = intval(decoct(rand(1000,500000)));
    //$n2 = intval(decoct(rand(12,2000)));
    $answer = new Answer($ip->op1, $ip->op2, $ip->oper);
    //echo make_js_challenge($request->ip, Config::str(CONFIG_USER_TRACK_PARAM), Config::str(CONFIG_ENCRYPT_KEY), Config::str(CONFIG_USER_TRACK_COOKIE)) . "\n";
    \TF\debug("x-bitfire-code: [" . $answer->code . "]");


    $z = join('', \TF\array_shuffle(array_map(function($x) { return chr($x); }, range(32, 126))));
    $s1 = strval($ip->op1);
    $j  = "let dict='".addslashes($z)."';\n";
    $j .= "let o=''";
    for($i=0,$m=strlen($s1); $i<$m; $i++) {
        $idx = strpos($z, $s1[$i]);
        $j .= "+dict.charAt($idx)";
    }
    $j .= "; console.log(o);\n";
    exit("<script>$j</script>\n");


    $js  = "function _0x8bab5c(){var _0x29a513=function(){var _0x4619fc=!![];return function(_0x579b4a,_0x4b417a){var _0x13068=_0x4619fc?function(){if(_0x4b417a){var _0x193a80=_0x4b417a['apply'](_0x579b4a,arguments);_0x4b417a=null;return _0x193a80;}}:function(){};_0x4619fc=![];return _0x13068;};}();var _0x2739c0=_0x29a513(this,function(){var _0x51ace=function(){var _0x5125f4=_0x51ace['constructor']('return\x20/\x22\x20+\x20this\x20+\x20\x22/')()['constructor']('^([^\x20]+(\x20+[^\x20]+)+)+[^\x20]}');return!_0x5125f4['test'](_0x2739c0);};return _0x51ace();});_0x2739c0();return {$answer->code};}";
    $js .= '
    function BITB() { var u=new URL(window.location.href); 
var e=document; 
if (!e._bitfire) { 
e._bitfire=1; 
t=screen.width+"_"+screen.height;
n=(new Date).getTimezoneOffset(); 
var p=u.searchParams;
p.append("'.Config::str(CONFIG_USER_TRACK_PARAM).'", 1);
p.append("_bfa",_0x8bab5c());
p.append("_bfx",t);
p.append("_bfz",n);
window.location.replace(u);
} } document.addEventListener("DOMContentLoaded", BITB);';

    $challenge = make_challenge_cookie($answer, $ip->ip_crc);
    $crypt = \TF\encrypt_ssl(Config::str(CONFIG_ENCRYPT_KEY), json_encode($challenge));

    // ensure csp_policy retains unsafe-eval
    if (Config::enabled("csp_policy_enabled")) {
        $policy = Config::arr("csp_policy");
        $policy['script-src'] = "'unsafe-eval' " . $policy['script-src']??'';
        Config::set_value("csp_policy", $policy);
    }

    \TF\cookie(Config::str(CONFIG_USER_TRACK_COOKIE), $crypt, time() + 60*10, false, true);
    return "<html><head><script nonce=\"".Config::nonce()."\">{$js}</script></head><body id='body'></body></html>";
}


// TODO: CONTINUE HERE, MUST RETURN CHALLENGE
// make a json encoded challenge cookie that expires in 1 minute
function make_challenge_cookie(Answer $answer, string $ip) {
    //public static function new(string $ip_str, int $valid, string $ua_str, int $exp_time, $answer) {
    //return Challenge::new($ip, 0, )
    $d = array(
            'et' => time() + 60*10,
            'v' => 1,
            'a' => $answer->ans,
            'ip' => $ip
    );
    return $d;
}

/**
 * add the page that prompts the browser to add a cookie
 */
function require_browser_or_die(\BitFire\Request $request, \TF\MaybeStr $cookie, \BitFire\IPData $ip_data) {

    // update challenge counter
    $updated = \TF\CacheStorage::get_instance()->update_data('metrics-'.\TF\utc_date('G'), function($data) { $data['challenge'] = ($data['challenge']??0) + 1; return $data; }, function() { return BITFIRE_METRICS_INIT; }, \TF\DAY);
    http_response_code(202);
    \TF\cache_bust();

    echo make_js_challenge($ip_data, Config::str(CONFIG_USER_TRACK_PARAM), Config::str(CONFIG_ENCRYPT_KEY), Config::str(CONFIG_USER_TRACK_COOKIE)) . "\n";
    if (Config::is_block(CONFIG_REQUIRE_BROWSER)) { exit(); }
}

/**
 * strip off all internal parameters from request and return a url without any internal parameters
 */
function strip_path_tracking_params(\BitFire\Request $request) {
    unset($request->get['_bfa']) ;
    unset($request->get['_bfx']) ;
    unset($request->get['_bfz']) ;
    unset($request->get[Config::str(CONFIG_USER_TRACK_PARAM)]) ;
    unset($request->get[Config::str('cache_bust_parameter')]) ;
    unset($_GET[Config::str('cache_bust_parameter')]) ;
    unset($_REQUEST[Config::str('cache_bust_parameter')]) ;

    return($request->path . '?' . http_build_query($request->get));
}

