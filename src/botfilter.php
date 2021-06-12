<?php
namespace BitFire;

use TF\CacheItem;

use function BitFireBot\send_browser_verification;

const MAX_HOST_HEADER_LEN = 80;

const AGENT_MATCH = array(
    "brave" => "(brave)/\s*(\d+\.\d+)",
    "opera" => "(opr)/\s*(\d+.\d+)",
    "chrome" => "(chrome)/\s*(\d+\.\d+)",
    "firefox" => "(firefox)/?\s*(\d+\.\d+)",
    "android" => "(android)/?\s*(\d+\.d+)",
    "safari" => "(safari)/\s*(\d+\.\d+)",
    "edge" => "(edge)/\s*(\d+\.\d+)",
    "explorer" => "(msie\s*|trident/)\s*([\d+\.]+)",
    "msie" => "(msie\s*|trident/[\d+\.]+;\s+rv:)\s*([\d+\.]+)",
    "vivaldi" => "(vivaldi)/\s*([\d+\.]+)",
    "bot" => "(\w+)\s*([\d+\.]+)"
);

class UserAgent {
    public $os;
    public $whitelist;
    public $browser;
    public $ver;
    public $bot;
    public $valid = 0;

    public function __construct(?string $os, ?string $browser, ?string $ver, bool $whitelist, bool $bot) {
        $this->os = $os;
        $this->browser = $browser;
        $this->ver = $ver;
        $this->whitelist = $whitelist;
        $this->bot = $bot;
    }
}

class JS_Fn {
    public $js_code;
    public $fn_name;
    public function __construct($code, $name) {
        $this->js_code = $code;
        $this->fn_name = $name;
    }
}

const IPData = '\BitFire\IPData';

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

    public static function make_new(string $ip, string $ua) : IPData {
        $data = new IPData(\BitFireBot\ip_to_int($ip), crc32($ua));
        $data->rr = 0;
        $data->rr_time = time() + 5*60;
        $data->ref = mt_rand(0, mt_getrandmax());
        return $data;
    }
}

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

    public function __toString() : string { return strval($this->ans); }
}

class Challenge {
    public $expire_time;
    public $valid;
    public $answer;
    public $ip;
    public $ua_crc;

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
/**
 * compare the request against the match
 * PURE(ish) depends on Config and Exceptions to create the block
 */
function constraint_check(int $fail_code, MatchType $type, \BitFire\Request $request) : \TF\MaybeBlock {
    if ($type->match($request)) {
        return BitFire::new_block($fail_code, $type->get_field(), $type->matched_data(), $type->match_pattern(), FAIL_DURATION[$fail_code]??0);
    }

    return \TF\Maybe::$FALSE;
}

// create a new ip_data local cache entry
function new_ip_data(string $remote_addr, string $agent) : string {
    $answer = new Answer(mt_rand(1000,500000), mt_rand(12,4000), mt_rand(1,4));
    $data = array('ip' => \BitFireBot\ip_to_int($remote_addr), 'ua' => crc32($agent), 'ctr_404' => 0, 'valid' => 0, 
        'ctr_500' => 0, 'rr' => 0, 'rrtime' => 0, 'op1' => $answer->op1, 'op2' => $answer->op2, 'oper' => $answer->oper);
    return pack_ip_data($data);
}

/**
 * map a locally stored data array into an IPData object
 * PURE!
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
    return $d;
}

function pack_ip_data(array $ip_data) : string {
    $t1 = pack("NNSSSNCNNC*", $ip_data['ip'], $ip_data['ua'], $ip_data['ctr_404'], $ip_data['ctr_500'], $ip_data['rr'], $ip_data['rrtime'], $ip_data['valid'], $ip_data['op1'], $ip_data['op2'], $ip_data['oper']);
    return $t1;
}

/**
 * load the local data for the remote IP
 */
function get_server_ip_data(string $remote_addr, string $agent) : IPData {

    $ip_key = "BITFIRE_IP_$remote_addr";
    // \TF\debug("x-cache-key: [$ip_key]");
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

    public $ip_data = NULL;

    protected $_constraints;

    public function __construct(\TF\CacheStorage $cache) {
        $this->cache = $cache;
        $this->_constraints = array(
            FAIL_PHPUNIT => new MatchType(MatchType::CONTAINS, "path", '/phpunit', BLOCK_SHORT),
            FAIL_WP_ENUM => new MatchType(MatchType::REGEX, "post_raw", '/td_optin_webhook.*?kraked_url/', BLOCK_MEDIUM),
            FAIL_THRIVE_KRAKEN => new MatchType(MatchType::CONTAINS, "path", '/wp-json/wp/v2/users', BLOCK_SHORT),
            FAIL_HONEYPOT => new MatchType(MatchType::EXACT, "path", Config::str(CONFIG_HONEYPOT, '/nosuchpath'), BLOCK_MEDIUM),
            FAIL_METHOD => new MatchType(MatchType::NOTIN, "method", Config::arr(CONFIG_METHODS), BLOCK_SHORT)
        );
    }

    /**
     * inspect the UA, determine human or bot
     * perform human validation, bot white/black listing
     * 
     * CPU: 359
     * NOT PURE!
     */
    public function inspect(\BitFire\Request $request) : \TF\MaybeBlock {
        $block = \TF\Maybe::$FALSE;
        // EARLY BAIL OUTS...
        // ignore urls that receive consistant bot access that may be difficult to identify
        if (in_array($request->path, Config::arr("ignore_bot_urls"))) {
            return $block;
        }

        // handle wp-cron and other self requested pages
        if (Config::enabled("skip_local_bots", true) && (\BitFireBot\is_local_request($request))) {
            return $block;
        }

        // check host header is not garbage
        $block->doifnot('\BitFireBot\header_check', $request);

        // ugly, impure crap
        $this->ip_data = get_server_ip_data($request->ip, $request->agent);
    
        // block constraints
        // cpu: 52
        $block->doifnot('\TF\map_whilenot', $this->_constraints, "\BitFire\constraint_check", $request);
        $block->doifnot('\BitFireBot\validate_rr', Config::int(CONFIG_RR_5M), $this->ip_data);

        // get details about the agent
        $this->browser = \BitFireBot\parse_agent($request->agent);

        // bot tracking cookie
        $maybe_botcookie = \BitFireBot\decrypt_tracking_cookie(
            $_COOKIE[Config::str(CONFIG_USER_TRACK_COOKIE)] ?? '',
            Config::str(CONFIG_ENCRYPT_KEY),
            $request->ip, $request->agent);

        // handle bots
        if ($block->empty() && $this->browser->bot) {
            // bot whitelist
            if (Config::enabled(CONFIG_WHITELIST_ENABLE) && $block->empty()) {
                $agents = \parse_ini_file(WAF_DIR."cache/whitelist_agents.ini");
                $block->doifnot('\BitFireBot\whitelist_inspection',
                    $request->agent,
                    $request->ip,
                    $agents['botwhitelist']);

                // set agent whitelist status
                $this->browser->whitelist = ($block->empty());
            }
            // bot blacklist
            else if (Config::enabled(CONFIG_BLACKLIST_ENABLE)) {
                $block->doifnot('\BitFireBot\blacklist_inspection', $request, file(WAF_DIR.'cache/bad-agent.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));  
            }
        }

        // request has no host header
        if (Config::enabled(CONFIG_CHECK_DOMAIN)) {
            if (!\BitFireBot\validate_host_header(Config::arr(CONFIG_VALID_DOMAIN_LIST), $request->host)) {
                // allow valid whitelist bots to access the site
                if (!isset($this->browser->whitelist)) {
                    $maybe = BitFire::new_block(FAIL_INVALID_DOMAIN, "host", $request->host, \TF\en_json(Config::arr(CONFIG_VALID_DOMAIN_LIST)), BLOCK_MEDIUM);
                    if (!$maybe->empty()) { return $maybe; }
                }
            }
        }

        // lastly verify, real browsers
        // set browser validity to cookie value or server ip data
        $this->browser->valid = max($this->ip_data->valid, $maybe_botcookie->extract('v', 0)->value('int'));
        \TF\debug("x-valid: " . $this->browser->valid . " ip_data_valid [" . $this->ip_data->valid . "]");

        $this->verify_browser($request, $maybe_botcookie); 
        return $block;
    }

    protected function verify_browser(\BitFire\Request $request, \TF\MaybeStr $maybe_botcookie) {
        // javascript browser challenges
        if ($this->browser->valid < 2 && Config::enabled(CONFIG_REQUIRE_BROWSER)) {
            if (isset($_POST['_bfxa'])) {
                $effect = verify_browser($request, $this->ip_data, $maybe_botcookie);
                // IMPORTANT, even though we have a POST, we are going to impersonate the original request!
                // UGLY, move this to function
                if ($effect->read_status() == STATUS_OK) {
                    // reset the get, post and request method with the original page request
                    $_SERVER['REQUEST_METHOD'] = $maybe_botcookie->extract('m', $_POST['_bfm'])();
                    $_GET = \TF\un_json($maybe_botcookie->extract('g', $_POST['_bfg'])());
                    $_POST = \TF\un_json($maybe_botcookie->extract('p', $_POST['_bfp'])());
                    // remove any possible cache busting from the browser required reload script
                    unset($_GET['_rqw']);
                    $_SERVER['REQUEST_URI'] = str_replace('_rqw=xpr', '', $_SERVER['REQUEST_URI']);
                }
                $effect->run();
            } else {
                send_browser_verification($this->ip_data, $request->agent)->run();
            }
        }

    }
}

/**
 * return a cache item for metrics that increments the stat: $stat
 * @test test_bot_metric_inc
 * PURE !
 */
function bot_metric_inc(string $stat) : \TF\CacheItem {
    return new \TF\CacheItem(
        'metrics-'.\TF\utc_date('G'), 
        function($data) use ($stat) { $data[$stat] = ($data[$stat]??0) + 1; return $data; },
        function() { return BITFIRE_METRICS_INIT; },
        \TF\DAY);
}


/**
 * try to clear all server and client state and re-load the page
 */
function browser_clear(\BitFire\Request $request) : \TF\Effect {
    $key = "BITFIRE_IP_".$request->ip;
    \TF\debug("browser clear");
    return \TF\Effect::new()->cookie('')
    ->update(new \TF\CacheItem($key, function($x) { return ''; }, function() { return ''; }, -\TF\DAY))
    ->update(bot_metric_inc('broken'))
    ->header("Location", $request->path)
    ->status(STATUS_SERVER_STATE_FAIL)
    ->exit(true);
}

/**
 * verifies the response matches the expected bot verification code
 * @test test_verify_browser
 * PURE! 
 */
function verify_browser(\BitFire\Request $request, IPData $ip_data, \TF\MaybeStr $cookie) : \TF\Effect {

    $effect = \TF\Effect::new();
    // user manually refreshed the page, lets clear as much server state as we can and try to reload the original page
    if ($request->get['_rqw']??'' === 'xpr') {
        return browser_clear($request);
    }

    $answer = new Answer($ip_data->op1, $ip_data->op2, $ip_data->oper);
    $correct_answer = $cookie->extract('a')->extract('ans');
    \TF\debug("x-valid-answer 1: ($correct_answer)");
    $correct_answer->set_if_empty($answer->ans);
    \TF\debug("x-valid-answer 2: ($correct_answer)");

    // unable to read correct answer from ip_data or cookie, increment broken counter, 
    // lets clear as much server state as we can and try to reload the original page
    if ($correct_answer->value('int') == 0) {
        return browser_clear($request);
    }

    // correct answer
    if ($correct_answer->value('int') === intval($_POST['_bfa']??-1) || $correct_answer->value('int') === intval($request->post['_bfa']??-1)) {
        \TF\debug("x-challenge: pass");
        // increase metric counter
        $effect->update(bot_metric_inc('valid'))
            ->status(STATUS_OK)
            // set the response valid cookie
            ->cookie(\TF\en_json(array('ip' => crc32($request->ip), 'v' => 2, 'ua' => crc32($request->agent), 'et' => time() + 3600)))
            // update the ip_data valid state for 60 minutes, TODO: make this real func, not anon-func
            ->update(new CacheItem('BITFIRE_IP_'.$request->ip, function ($data) {
                        $ip_data = unpack_ip_data($data); $ip_data['valid'] = 2; return pack_ip_data($ip_data);
                    },
                    function() use ($request) { return \BitFire\new_ip_data($request->ip, $request->agent); },
                    60*60));
    }
    // incorrect answer: TODO: if this is a POST, then we need to redirect BACK to a GET so that if the user
    // refreshes the page, they don't POST again the wrong data...
    else {
        \TF\debug("x-challenge: fail [%d] / [%d]", $correct_answer->value('int'), intval($_POST['_bfa']));
        $effect->out(file_get_contents(WAF_DIR . "views/browser_required.html"))
            ->status(STATUS_FAIL)
            ->exit(true);
    }

    return $effect;
}

namespace BitFireBot;

use BitFire\Answer;
use BitFire\BitFire;
use BitFire\Block;
use BitFire\Challenge;
use BitFire\Config;
use BitFire\JS_Fn;
use BitFire\Request;
use BitFire\UserAgent;
use TF\CacheStorage;

use function BitFire\reporting;

use const BitFire\AGENT_MATCH;
use const BitFire\BITFIRE_METRICS_INIT;
use const BitFire\BLOCK_MEDIUM;
use const BitFire\BLOCK_SHORT;
use const BitFire\CONFIG_ENCRYPT_KEY;
use const BitFire\CONFIG_REQUIRE_BROWSER;
use const BitFire\CONFIG_USER_TRACK_COOKIE;
use const BitFire\FAIL_FAKE_WHITELIST;
use const BitFire\FAIL_IS_BLACKLIST;
use const BitFire\FAIL_MISS_WHITELIST;
use const BitFire\FAIL_RR_TOO_HIGH;

/**
 * check bad bots that send crap in the host header
 * @test test_bot.php test_header_check
 * PURE!
 */
function header_check(\BitFire\Request $request) : \TF\MaybeBlock {
    if (strlen($request->host) > \BitFire\MAX_HOST_HEADER_LEN) {
        return BitFire::new_block(\BitFire\FAIL_HOST_TOO_LONG, "HTTP_HOST", $request->host, 'len < 80', \BitFire\BLOCK_SHORT);
    }
    return \TF\Maybe::$FALSE;
}


/**
 * convert an IP to a 32bit int.  possible collisions for ipv6 addrs.  unlikely to be significant
 * @test test_bot.php test_ip_to_int
 * PURE!
 */
function ip_to_int(string $ip) : int {
    return crc32($ip);
}

/**
 * return true if the request is from the local server
 * NOT PURE! depends in $_SERVER variable
 */
function is_local_request(\BitFire\Request $request) : bool {
    if ($_SERVER['REMOTE_ADDR'] === $_SERVER['SERVER_ADDR']) {
        return true;
    }
    if (\TF\ends_with($request->path, '/wp-cron.php') && strstr($request->agent, 'wordpress/') != false) {
        return true;
    }
    return false;
}

/**
 * test if the ipdata exceeds request rate
 * @test test_bot.php test_validate_rr
 * PURE!
 */
function validate_rr(int $rr_5m_limit, \BitFire\IPData $ip_data) : \TF\MaybeBlock {
    if ($ip_data->rr > $rr_5m_limit) {
        return BitFire::new_block(FAIL_RR_TOO_HIGH, 'REQUEST_RATE', $ip_data->rr, "$rr_5m_limit", BLOCK_MEDIUM);
    }
    return \TF\Maybe::$FALSE;
}

/**
 * do a reverse lookup and return true if remote_ip matches network_regex
 * depends on ip lookup 
 * 
 * NOT PURE!
 */
function verify_bot_ip(string $remote_ip, string $network_regex) : bool {
    // check if the remote IP is in an allowed list of IPs
    $ip_checks = (strpos($network_regex, ',') > 0) ? explode(',', $network_regex) : array($network_regex);
    $ip_matches = array_reduce($ip_checks, \TF\is_regex_reduced($remote_ip), false);
    if ($ip_matches) { return true; }

    // fwd and reverse lookup
    $ip = \TF\reverse_ip_lookup($remote_ip)
        ->then(function($value) use ($ip_checks) {
            return array_reduce($ip_checks, \TF\find_regex_reduced($value), NULL);
        })->then('TF\\fast_ip_lookup');

    return $ip() === $remote_ip;
}

/**
 * connect to whois and verify IP AS number, with cacheing
 * @test test_bot.php test_memoization_verify_bot_as
 * NOT PURE!
 */
function fast_verify_bot_as(string $remote_ip, string $network) : bool {
    return \TF\memoize('\BitFireBot\verify_bot_as', "_bf_as_{$network}_{$remote_ip}", 3600)($remote_ip, $network);
}

/**
 * connect to whois and verify IP AS number
 * @test test_bot.php test__verify_bot_as
 * NOT PURE!
 */
function verify_bot_as(string $remote_ip, string $network) : bool {
    $x = \TF\MaybeA::of(fsockopen("whois.radb.net", 43, $no, $str, 1))
        ->effect(\TF\partial_right('\fputs', "$remote_ip\r\n"))
        ->then('\TF\read_stream')
        ->if(\TF\partial_right('stristr', $network));
        return ! $x->empty();
}


/**
 * DEAD CODE...
 */
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
 * PURE!
 */
function parse_whois_route(string $output) : ?array {
    return array_map('\BitFireBot\parse_whois_line', explode("\n", $output));
}

/**
 * parse 'route    : 1.2.3.4/24' into '1.2.3.4/24'
 * PURE!
 */
function parse_whois_line(string $line) : string {
    $parts = explode(": ", $line);
    return trim($parts[1]??'');
}

// return false if valid_domains has entries and request['host'] is not in it, true otherwise
// PURE!
function validate_host_header(array $valid_domains, string $host) : bool {
    return (!empty($valid_domains)) ?  \TF\in_array_ending($valid_domains, $host) : true;
}

/**
 * test if an agent is found in a list of agents
 * $botlist is format "agent match str":reverse ip network:human comment
 * -1 - no UA match, 0 UA match net fail, 1 UA and net match
 * NOT PURE! depends on DNS and WHOIS
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
 * 
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
 * @test test_bot.php test_blacklist_inspection
 * PURE!
 */
function blacklist_inspection(\BitFire\Request $request, ?array $blacklist) : \TF\MaybeBlock {
    $match = new \BitFire\MatchType(\BitFire\MatchType::CONTAINS, "agent", $blacklist, BLOCK_MEDIUM);
    if ($match->match($request) !== false) {
        return BitFire::new_block(FAIL_IS_BLACKLIST, "user_agent", $request->agent, $match->match_pattern(), BLOCK_MEDIUM);
    }
   
    return \TF\Maybe::$FALSE;
}


/**
 * this function takes a useragent and turns it into an array with os, browser, bot and ver
 * return array('os', 'browser', 'ver', 'bot':bool)
 * total: 58 
 * return UserAgent
 * @test test_bot.php test_parse_agent
 * PURE!
 */
function parse_agent(string $user_agent) : UserAgent {

    $agent = new UserAgent(NULL, $user_agent, "1.0", false, true);

    // return robots immediately...
    if (substr($user_agent, 0, 11) !== "mozilla/5.0") {
        return $agent;
    }

    // cpu: 50, could rewrite as imperative and save here
    $os_list = array("linux", "android", "os x", "windows", "iphone", "ipad");
    $agent->os = array_reduce($os_list, function(string $carry, string $os) use ($user_agent) {
        return (strpos($user_agent, $os) !== false) ? $os : $carry;
    }, "bot");


    // cpu: 50, could rewrite as imperative and save here
    return array_reduce(array_keys(AGENT_MATCH), function(\BitFire\UserAgent $carry, string $match_key) use ($user_agent) {
        if ($carry->bot) {
            $pattern = AGENT_MATCH[$match_key];
            preg_match("!$pattern!", $user_agent, $matches);
            if (isset($matches[2])) {
                $carry->browser = $match_key;
                $carry->ver = $matches[2];
                $carry->bot = false;
            }
        }
        return $carry;
    }, $agent);
}


/**
 * returns a maybe with tracking data or an empty monad...
 * TODO: create test function
 * PURE!
 */
function decrypt_tracking_cookie(?string $cookie_data, string $encrypt_key, string $src_ip, string $agent) : \TF\MaybeStr {
    //untaint($cookie_data);
    //\TF\debug("encrypted cookie [%s] [%s]", $encrypt_key, $cookie_data);
    $r = \TF\decrypt_ssl($encrypt_key, $cookie_data)
        ->then("TF\\un_json")
        ->if(function($cookie) use ($src_ip, $agent) {
            if (!isset($cookie['ip'])) {
                \TF\debug("invalid decrypted cookie [%s] ", var_export($cookie, true));
                return false;
            } else {
                $src_ip_crc = \BitFireBot\ip_to_int($src_ip);
                $cookie_match = (is_array($cookie) && (intval($cookie['ip']??0) == intval($src_ip_crc)));
                $time_good = ((intval($cookie['et']??0)) > time());
                $agent_good = crc32($agent) == $cookie['ua'];
                if (!$cookie_match) { \TF\debug("cookie ip does not match"); }
                if (!$time_good) { \TF\debug("cookie expired"); }
                if (!$agent_good) { \TF\debug("agent mismatch live: [%s] [%d] cookie:[%d]", $agent, crc32($agent), $cookie['ua']??0); }
                return ($cookie_match && $time_good && $agent_good);
            }
        });
    return $r;
}

/**
 * return a function that returns a string to call $fn_name with the argument 
 * @test test_bot.php test_js_fn
 * PURE !
 */
function js_fn(string $fn_name) : callable {
    return function($arg) use ($fn_name) { return "{$fn_name}($arg)"; };
}

/**
 * create obfuscated JavaScript for $number
 * @test test_bot.php test_js_int_obfuscate
 * PURE !
 */
function js_int_obfuscate(int $number) : JS_Fn {
    // convert ascii printable character range (32-126) to actual char values, shuffle the result array and turn into string
    $z = join('', \TF\array_shuffle(array_map(function($x) { return chr($x); }, range(32, 126))));
    // integer to string, set dictionary name, function name, 
    $num_str = strval($number);
    $dict_name = 'z' . \TF\random_str(3);
    $fn_name = 'x' . \TF\random_str(3);
    // js function call on param
    $char_fn = js_fn("+{$dict_name}.charAt");

    // create an index into the dictionary for each integer position
    $code = \TF\each_character($num_str, function (string $c, int $idx) use ($z, $num_str, $char_fn) : string {
        $idx = strpos($z, $num_str[$idx]);
        return $char_fn($idx);
    });

    // the actual js function
    $js_code = sprintf("function %s(){let %s='%s';return parseInt(''%s);}", $fn_name, $dict_name, addslashes($z), $code);
    return new JS_Fn($js_code, $fn_name);
}


/**
 * make the html javascript challenge
 * PURE!
 */
function make_js_script(int $op1, int $op2, int $oper, string $nonce="_rand_") : string {
    $fn1_name = '_0x' . \TF\random_str(4);
    $fn2_name = '_0x' . \TF\random_str(4);
    $fn3 = js_int_obfuscate($op1);
    $fn4 = js_int_obfuscate($op2);
    $fn5 = js_int_obfuscate(mt_rand(1000,500000));
    $fn6 = js_int_obfuscate(mt_rand(1000,500000));
    
    $js  = "function $fn1_name(){var _0x29a513=function(){var _0x4619fc=!![];return function(_0x579b4a,_0x4b417a){var _0x13068=_0x4619fc?function(){if(_0x4b417a){var _0x193a80=_0x4b417a['apply'](_0x579b4a,arguments);_0x4b417a=null;return _0x193a80;}}:function(){};_0x4619fc=![];return _0x13068;};}();var _0x2739c0=_0x29a513(this,function(){var _0x51ace=function(){var _0x5125f4=_0x51ace['constructor']('return\x20/\x22\x20+\x20this\x20+\x20\x22/')()['constructor']('^([^\x20]+(\x20+[^\x20]+)+)+[^\x20]}');return!_0x5125f4['test'](_0x2739c0);};return _0x51ace();});_0x2739c0();return {$fn3->fn_name}() ".oper_char($oper)." {$fn4->fn_name}();}";
    $js .= $fn5->js_code . "\n" .$fn4->js_code . "\n" . $fn3->js_code . "\n" . $fn6->js_code . "\n";
    $js .= "_0x2264=['body','name','716898irJcQR','input','type','1JyCSgW','458938jhQaDj','submit','appendChild','12521RCnfSZ','731620bsLeul','60978tKMbmi','38yNhlJk','method','action','value','865714LjSURW','createElement','679754RgBBzH','17JXalWl'];(function(_0x82ed12,_0x26c7d9){const _0x429c60=_0x4a61;while(!![]){try{const _0x150118=-parseInt(_0x429c60(0x10e))*parseInt(_0x429c60(0x106))+parseInt(_0x429c60(0x107))*parseInt(_0x429c60(0x118))+-parseInt(_0x429c60(0x115))+parseInt(_0x429c60(0x111))+-parseInt(_0x429c60(0x114))*-parseInt(_0x429c60(0x119))+-parseInt(_0x429c60(0x10d))+parseInt(_0x429c60(0x10b));if(_0x150118===_0x26c7d9)break;else _0x82ed12['push'](_0x82ed12['shift']());}catch(_0x14d3d5){_0x82ed12['push'](_0x82ed12['shift']());}}}(_0x2264,0x96138));function _0x4a61(_0x19d3b3,_0x4d8bcc){_0x19d3b3=_0x19d3b3-0x106;let _0x22646a=_0x2264[_0x19d3b3];return _0x22646a;}function post(_0xfddbd3,_0x1e23f1,_0x5af7a2='post'){const _0x244f79=_0x4a61,_0x370c95=document['createElement']('form');_0x370c95[_0x244f79(0x108)]=_0x5af7a2,_0x370c95[_0x244f79(0x109)]=_0xfddbd3;for(const _0x1d3b01 in _0x1e23f1){if(_0x1e23f1['hasOwnProperty'](_0x1d3b01)){const _0x3d2f26=document[_0x244f79(0x10c)](_0x244f79(0x112));_0x3d2f26[_0x244f79(0x113)]='hidden',_0x3d2f26[_0x244f79(0x110)]=_0x1d3b01,_0x3d2f26[_0x244f79(0x10a)]=_0x1e23f1[_0x1d3b01],_0x370c95[_0x244f79(0x117)](_0x3d2f26);}}document[_0x244f79(0x10f)][_0x244f79(0x117)](_0x370c95),_0x370c95[_0x244f79(0x116)]();}";
    $js .= "function $fn2_name() { ".'var e=document;if(!e._bitfire){e._bitfire=1;n=(new Date).getTimezoneOffset(); 
post(window.location.href,{"_bfa":'.$fn1_name.'(),"_bfg":\''.json_encode($_GET).'\',"_bfp":\''.json_encode($_POST).'\',"_bfm":"'.$_SERVER['REQUEST_METHOD'].'","_bfx":n,"_bfxa":1,"_gen":"'.date('H:i:s').'"}); } } document.addEventListener("DOMContentLoaded", '.$fn2_name.');';

    return "<html><head><script nonce=\"$nonce\">{$js}</script></head><body id='body'></body></html>";
}


/**
 * return the challenge cookie values
 * @test test_bot.php test_make_challenge_cookie
 * PURE!
 */
function make_challenge_cookie($answer, string $ip, string $agent) : array {
    $d = array(
            'et' => time() + 60*10,
            'v' => 1,
            'a' => $answer,
            'ua' => crc32($agent),
            'ip' => $ip,
            'm' => $_SERVER['REQUEST_METHOD'],
            'g' => json_encode($_GET),
            'p' => json_encode($_POST)
    );
    return $d;
}


/**
 * send the browser verification challenge
 * @test test_bot.php send_test_browser_verification
 * PURE-ish, required Config! 
 */
function send_browser_verification(\BitFire\IPData $ip_data, string $agent) : \TF\Effect {

    if (Config::str('cache_type') !== 'nop' && Config::disabled("cookies_enabled")) {
        \TF\debug("browser verify disabled, required cache_type or cookies");
        return \TF\Effect::new();
    }

    $answer = new Answer($ip_data->op1, $ip_data->op2, $ip_data->oper);
    \TF\debug("send verify answer: $answer");

    $effect = \TF\Effect::new()
        ->response_code(303)
        ->update(new \TF\CacheItem(
            'metrics-'.\TF\utc_date('G'),
            function($data) { $data['challenge'] = ($data['challenge']??0) + 1; return $data; },
            function() { return BITFIRE_METRICS_INIT; },
            \TF\DAY
        ))
        ->exit(true)
        ->out(make_js_script($ip_data->op1, $ip_data->op2, $ip_data->oper))
        ->cookie(json_encode(make_challenge_cookie($answer, $ip_data->ip_crc, $agent)));

    return \TF\cache_prevent($effect);
}

/**
 * convert operation int to operation character
 * @test test_bot.php test_open_char
 * PURE!
 */
function oper_char(int $oper) : string {
    switch($oper) {
        case 1:
            return "*";
        case 2:
            return "/";
        case 3:
            return "+";
        case 4:
            return "-";
        default:
            \TF\debug("unknown operation [$oper]");
            return "+";
    }
}
