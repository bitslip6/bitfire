<?php declare(strict_types=1);
namespace BitFire;

use TF\CacheStorage;
use TF\Maybe;

if (defined('BITFIRE_VER')) { return; }
 

define("BITFIRE_CONFIG", dirname(__FILE__) . "/config.ini");
const FEATURE_CLASS = array(0 => 'require_full_browser', 10000 => 'xss_block', 11000 => 'web_block', 12000 => 'web_block', 13000 => 'web_block', 14000 => 'sql_block', 15000 => 'web_block', 16000 => 'web_block', 17000 => 'web_block', 18000 => 'spam_filter_enabled', 20000 => 'require_full_browser', 21000 => 'file_block', 22000 => 'web_block', 23000 => 'check_domain', 24000 => 'whitelist_enable', 25000 => 'blacklist_enable', 26000 => 'rate_limit', 50000 => '');

const BITFIRE_API_FN = array('\\BitFire\\get_block_types', '\\BitFire\\get_ip_data', '\\BitFire\\get_hr_data', '\\BitFire\\make_code');
const BITFIRE_METRICS_INIT = array(10000 => 0, 11000 => 0, 12000 => 0, 13000 => 0, 14000 => 0, 15000 => 0, 16000 => 0, 17000 => 0, 18000 => 0, 19000 => 0, 20000 => 0, 21000 => 0, 22000 => 0, 23000 => 0, 24000 => 0, 25000 => 0, 26000 => 0, 70000 => 0);
const BITFIRE_VER = 123;
const BITFIRE_DOMAIN = "http://api.bitslip6.com";
const BITFIRE_COMMAND = "BITFIRE_API";

const BITFIRE_MAX_HASH_COUNT = 20;
const BITFIRE_MAX_AUDIT = 20;
const BITFIRE_MAX_PAGES = 200;
const WAF_MIN_HIT = 25;
const WAF_MIN_PERCENT = 10;

const CONFIG_REPORT_FILE='report_file';
const CONFIG_WHITELIST_ENABLE='whitelist_enable';
const CONFIG_BLACKLIST_ENABLE='blacklist_enable';
const CONFIG_REQUIRE_BROWSER = 'require_full_browser';
const CONFIG_USER_TRACK_COOKIE = 'browser_cookie';
const CONFIG_MAX_CACHE_AGE = 'max_cache_age';
const CONFIG_USER_TRACK_PARAM = 'bitfire_param';
const CONFIG_ENCRYPT_KEY = 'encryption_key';
const CONFIG_SECRET = 'secret';
const CONFIG_VALID_DOMAIN_LIST = 'valid_domains';
const CONFIG_ENABLED = 'bitfire_enabled';
const CONFIG_WEB_FILTER_ENABLED = 'web_filter_enabled';
const CONFIG_SECURITY_HEADERS = 'security_headers_enabled';
const CONFIG_XSS_FILTER="xss_block";
const CONFIG_SQL_FILTER="sql_block";
const CONFIG_FILE_FILTER="file_block";
const CONFIG_SPAM_FILTER="spam_filter_enabled";
const CONFIG_CACHE_TYPE = 'cache_type';
const CONFIG_LOG_FILE = 'log_file';
const CONFIG_RR_1M = 'rr_1m';
const CONFIG_RR_5M = 'rr_5m';
const CONFIG_PROFANITY = 'profanity_filter';
const CONFIG_CHECK_DOMAIN = 'check_domain';

const REQUEST_UA = 'USER_AGENT';
const REQUEST_IP = 'IP';
const REQUEST_HOST = 'HOST';
const REQUEST_COOKIE = 'COOKIE';
const REQUEST_ACCEPT = 'ACCEPT';
const REQUEST_SCHEME = 'SCHEME';
const REQUEST_PATH = 'PATH';
const REQUEST_METHOD = 'METHOD';

const BITFIRE_INPUT = '_bitfire';

const THROTTLE_LOCK_TIME = 600;
const THROTTLE_LOCK_FILE = ".bitfire.lock";

const FAIL_NOT = 0;

const PROFANITY = "anal|anus|arse|ass|asss|bastard|bitch|cock|cocksuck|coon|crap|cunt|cyberfuck|damn|dick|douche|fag|faggot|fuck|fuck\s+you|fuckhole|god damn|gook|homoerotic|hore|lesbian|mother|fucker|motherfuck|motherfucker|negro|nigger|penis|penisfucker|piss|porn|pussy|retard|sex|shit|slut|son\s+of\s+a\s+bitch|tits|viagra|whore";

require_once WAF_DIR."storage.php";
require_once WAF_DIR."util.php";
require_once WAF_DIR."english.php";


/**
 * send an error code back to the server so we know there is a configuration problem
 * 1001 - unable to blacklist ips because shmop is not available
 * 1002 - unable to blacklist ips because ftok is not available 
 * 1003 - zend op cache path is not writable
 * 1004 - cache type is not set, or config doesn't parse
 * 1005 - shmop not available
 * 1006 - shmop error
 * 1007 - shmop_write failed to write 1/2 meg of data
 * 1008 - invalid ini configuration
 * 1009 - ini file not found
 * 1010 - WAF dir is not writable/upgradable
 * 1011 - API command is not callable
 * 1012 - unable to download new waf software
 */
function throttle_error($code) {
    $path = sys_get_temp_dir() . DS . THROTTLE_LOCK_FILE;
    $stat_data = stat($path);
    if (($stat_data['mtime'] < time() + 600)) {
        \TF\apidata("error", array("error_code" => $code));
        touch($path);
    }
}


class Request
{
    public $get;
    public $post;
    public $full;
    public $ip;
    public $agent;
    public $referer;
    public $cookies;
    public $host;
    public $method;
}


class MatchType
{
    protected $_type;
    protected $_key;
    protected $_value;
    protected $_matched;
    protected $_block_time;

    const EXACT = 0;
    const CONTAINS = 1;
    const IN = 2;
    const NOTIN = 3;
    const REGEX = 4;

    public function __construct(int $type, string $key, $value, int $block_time) {
        $this->_type = $type;
        $this->_key = $key;
        $this->_value = $value;
        $this->_matched = 'none';
        $this->_block_time = $block_time;
    }

    public function match(array $request) {
        $this->_matched = $request[$this->_key] ?? '';
        switch ($this->_type) {
            case MatchType::EXACT: 
                return $this->_matched === $this->_value;
            case MatchType::CONTAINS: 
                if (is_array($this->_value)) {
                    foreach ($this->_value as $v) {
                        $m = strstr($this->_matched, $v);
                        if ($m !== false) { 
                            return $m;
                        }
                    }
                    return false;
                }
                return strpos($this->_matched, $this->_value) !== false;
            case MatchType::IN: 
                return in_array($this->_matched, $this->_value);
            case MatchType::NOTIN: 
                return !in_array($this->_matched, $this->_value);
            case MatchType::REGEX:
                return preg_match($this->_value, $this->_matched) > 0;
            break;
        }
        return false;
    }

    public function matched_data() : string {
        return $this->_matched;
    }

    public function get_field() : string {
        return $this->_key;
    }
}



class Block {

    public $code;
    public $parameter;
    public $value;
    public $pattern;
    public $block_time; // set to -1 for warning, 0 = block this request, 1 = short, 2 = medium 3 = long

    public function __construct(int $code, string $parameter, string $value, string $pattern, int $block_time = 0) {
        $this->code = $code;
        $this->parameter = $parameter;
        $this->value = $value;
        $this->pattern = $pattern;
        $this->block_time = $block_time;
    }
}

class Config {
    public static $_options = null;

    public static function set(array $options) {
        Config::$_options = $options;
    }

    public static function set_value(string $option_name, $value) {
        Config::$_options[$option_name] = $value;
    }

    public static function str(string $name, string $default = '') {
        return Config::$_options[$name] ?? $default;
    }

    public static function int(string $name, int $default = 0) {
        return intval(Config::$_options[$name] ?? $default);
    }

    public static function arr(string $name, array $default = array()) : array {
        return Config::$_options[$name] ?? $default;
    }

    public static function enabled(string $name, bool $default = false) : bool {
        if (!isset(Config::$_options[$name])) { return $default; }
        if (Config::$_options[$name] === "block" || Config::$_options[$name] === "report") { return true; }
        return (bool)Config::$_options[$name];
    }
}


/**
 * 
 */
class BitFire
{
    const CACHE_PAGE = WAF_DIR . "cache/root";

    // data storage
    protected $_ip_key;

    public $cache;
    // request unique id
    public $uid;
    public static $_exceptions = array();
    public static $_reporting = array();

    public static $_fail_reasons = array();
    protected $_ip_data = null;

    public $_request = null;

    /** @var BitFire $_instance */
    protected static $_instance = null;

    /** @var BotFilter $bot_filter */
    public $bot_filter = null;

    /**
     * WAF is a singleton
     * @return BitFire the bitfire singleton;
     */
    public static function get_instance() {
        if (BitFire::$_instance == null) {
            BitFire::$_instance = new BitFire();
        }
        return BitFire::$_instance;
    }

    /**
     * Create a new instance of the BitFire
     */
    protected function __construct() {

        if (Config::enabled(CONFIG_ENABLED)) {
            $this->uid = substr(\uniqid(), 5, 8);

            // process _SERVER _GET _POST variables into this->_request
            $this->_request = process_request($_GET, $_POST, $_SERVER, $_COOKIE);
            
            // we will need cache storage and secure cookies
            $this->cache = \TF\CacheStorage::get_instance();

            $this->api_call();
            
            //$exception_file = WAF_DIR . "cache/exceptions.json";
            //self::$_exceptions = (file_exists($exception_file)) ? \TF\un_json(file_get_contents($exception_file)) : array();
        }
    }
    
    /**
     * write report data after script execution 
     */
    public function __destruct() {
        $opts = (strpos(Config::str(CONFIG_REPORT_FILE), 'pretty') > 0) ? JSON_PRETTY_PRINT : 0;
        $out = "";
        foreach (self::$_reporting as $report) {
            $out .= json_encode($report, $opts) . "\n";
        }
        file_put_contents(Config::str(CONFIG_REPORT_FILE), $out, FILE_APPEND);
    }

    protected function api_call() {
        if ($this->_request['GET']['_secret']??'no' === Config::str(CONFIG_SECRET)) {
            require WAF_DIR."api.php";

            $fn = '\\BitFire\\' . $this->_request['GET'][BITFIRE_COMMAND];
            
            if (!in_array($fn, BITFIRE_API_FN)) { exit("unknown function [$fn]"); }
            $result = $fn($this->_request);
            exit ($result);
        }
        
    }

    /**
     * append an exception to the list of exceptions
     */
    public function add_exception(array $exception) {
        self::$_exceptions[] = $exception;
    }

    /**
     * create a new block, returns a maybe of a block, empty if there is an exception for it
     */
    public static function new_block(int $code, string $parameter, string $value, string $pattern, int $block_time = 0) : \TF\Maybe {
        if ($code === FAIL_NOT) { return \TF\Maybe::of(false); }
        $block = new Block($code, $parameter, $value, $pattern, $block_time);
        if (is_report($block)) {
            self::reporting($block, BitFire::get_instance()->_request);
            return \TF\Maybe::of(false);
        }
        return filter_block_exceptions($block, self::$_exceptions);
    }
    
    protected static function reporting(Block $block, array $request) {
        $data = array('time' => date('r'),
            'exec' => number_format(microtime(true) - $GLOBALS['m0'], 6). ' sec',
            'block' => $block,
            'request' => $request);
        $bf = BitFire::get_instance()->bot_filter;
        if ($bf != null) {
            $data['browser'] = $bf->browser;
            $data['rate'] = $bf->ip_data;
        }
        
        self::$_reporting[] = $data;
    }
    

    
    /**
     * TODO: MOVE TO CACHE.php
     */
    // update the cache behind page
    public static function update_cache_behind() {
        if (strlen($_SERVER['SERVER_NAME']??'') < 1) { return; }
        $secret = Config::str(CONFIG_SECRET, 'bitfiresekret');
        $u = $_SERVER['REQUEST_SCHEME'] . "://" . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'] . "?" . BITFIRE_INPUT . "=$secret";
        $d = \TF\bit_http_request("GET", $u, "");
        file_put_contents(WAF_DIR . '/cache/root:'. cache_unique(), $d);
    }


    // TODO: move this to "pure function"
    // display the cache behind page
    // FIX: replace fail reasons here!
    public function cache_behind() {
        // don't cache internal requests... (infinate loop)
        if (isset($_GET[BITFIRE_INPUT])) { return; }

        // if the request is to the homepage with no parameters, its possible to cache
        $tracking_cookie = Config::str(CONFIG_USER_TRACK_COOKIE, '_bitf');
        $site_cookies = array_filter(array_keys($_COOKIE), function($name) use ($tracking_cookie) { return stripos($name, $tracking_cookie) === false; });

        if (Config::int(CONFIG_MAX_CACHE_AGE, 0) > 0 &&
            $this->_request[REQUEST_PATH] === '/' && 
            $this->_request[REQUEST_METHOD] === "GET" &&
            count($_GET) === 0 && 
            count($site_cookies) === 0) {
                // update the cache after this request
                register_shutdown_function([$this, 'update_cache_behind']);
                $page = 'root:' . cache_unique();
                // we have a cached page that is not too old
                if ($this->cached_page_is_valid()) {
                    // add a js challenge if the request is not to a bot
                    if ($this->bot_filter != null && $this->bot_filter->browser['bot'] == false) {
                        echo \BitFireBot\make_js_challenge(
                            $this->_request[REQUEST_IP],
                            Config::str(CONFIG_USER_TRACK_PARAM),
                            Config::str(CONFIG_ENCRYPT_KEY),
                            Config::str(CONFIG_USER_TRACK_COOKIE));
                    }
                    // serve the static page!
                    echo file_get_contents(WAF_DIR . "cache/$page");
                    echo "<!-- cache -->\n";
                    exit();
                }
        }
    }

    /**
     * test if BitFire::CACHE_PAGE is a valid cached page (exists and is not stale)
     */
    public function cached_page_is_valid() {
        $stat_data = @stat(BitFire::CACHE_PAGE);
        return ($stat_data != false && ($stat_data['ctime'] + $this->_config[CONFIG_MAX_CACHE_AGE]) > time());
    }


    /**
     * inspect a request and block failed requests
     * return false if inspection failed...
     */
    public function inspect() : \TF\Maybe {
        // dashboard requests, TODO: MOVE TO api.php
        if ($this->_request[REQUEST_PATH] === "/bitfire") {

            if (!isset($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW'] !== Config::str('password', 'default_password')) {
                header('WWW-Authenticate: Basic realm="BitFire", charset="UTF-8"');
                header('HTTP/1.0 401 Unauthorized');
                exit;
            }

            $x = @file(Config::str(CONFIG_REPORT_FILE));
            $report_count = (is_array($x)) ? count($x) : 0;
            $config = \TF\map_mapvalue(Config::$_options, '\BitFire\alert_or_block');
            $reporting = array_reverse(add_country(json_decode('['. join(",", \TF\read_last_lines(Config::str(CONFIG_REPORT_FILE), 20, 2500)) . ']', true)), true);
            $blocks = array_reverse(add_country(CacheStorage::get_instance()->load_data("log_data")), true);
            $send = CacheStorage::get_instance()->load_data("send_js", 0);
            $good = CacheStorage::get_instance()->load_data("good_js", 0);
            exit(require WAF_DIR . "views/dashboard.html");
        }



        $block = \TF\Maybe::of(false);
        if (!Config::enabled(CONFIG_ENABLED)) { return $block; }

        // don't inspect local commands
        if (!isset($_SERVER['REQUEST_URI'])) { return $block; }

		if (Config::enabled(CONFIG_SECURITY_HEADERS)) {
            include WAF_DIR."headers.php";
			\BitFireHeader\send_security_headers($this->_request);
		}
        
        // bot filtering
        if ($this->bot_filter_enabled()) {
            require WAF_DIR . 'botfilter.php';
            $this->bot_filter = new BotFilter($this->cache);
            $block = $this->bot_filter->inspect($this->_request);
        }

        $block->doifnot(array($this, "cache_behind"));
        
        // perform cache behind after bot filtering (don't want to cache bot requests)
        /*
        if ($block->empty()) {
            $this->cache_behind();
        }
        */

        // generic filtering
        if ($block->empty() && Config::enabled(CONFIG_WEB_FILTER_ENABLED)) {
            require WAF_DIR . 'webfilter.php';
            $this->_web_filter = new \BitFire\WebFilter($this->cache);
            $block = $this->_web_filter->inspect($this->_request);
        }

        return $block;
    }

    /**
     * @return bool true if any bot blocking features are enabled
     */
    protected function bot_filter_enabled() : bool {
        // disable bot filtering for internal requests
        $bf = $_GET[BITFIRE_INPUT] ?? '';
        if ($bf === trim(Config::str(CONFIG_SECRET, 'bitfiresekret'))) { return false; }

        return (
            Config::enabled(CONFIG_CHECK_DOMAIN) ||
            Config::enabled(CONFIG_BLACKLIST_ENABLE) ||
            Config::enabled(CONFIG_WHITELIST_ENABLE) ||
            Config::enabled(CONFIG_REQUIRE_BROWSER) ||
            Config::enabled(CONFIG_HONEYPOT) ||
            Config::str(CONFIG_RATE_LIMIT_ACTION) !== '');
    }
}

function to_meta(array $line) {
    return "5m:".$line['rate']['rr_5m'].", 1m:".$line['rate']['rr_1m']." ,v:".$line['browser']['valid'].", ref:".$line['rate']['ref'];
}

/**
 * returns true if the block should be reported and not blocked...
 */
function is_report(Block $block) : bool {
    $class = floor(($block->code / 1000)) * 1000;
    $feature_name =  FEATURE_CLASS[$class] ?? 'bitfire_enabled';

    return (Config::str($feature_name) === "report");
}

/**
 * filter reporting features
 */
function reporting(Block $block, array $request) {
    $data = array('time' => date('r'),
        'exec' => number_format(microtime(true) - $GLOBALS['m0'], 6). ' sec',
        'ip' => BitFire::get_instance()->_request[REQUEST_IP],
        'block' => $block,
        'request' => $request);
    $bf = BitFire::get_instance()->bot_filter;
    if ($bf != null) {
        $data['browser'] = $bf->browser;
        $data['rate'] = $bf->ip_data;
    }
    $opts = (strpos(Config::str(CONFIG_REPORT_FILE), 'pretty') > 0) ? JSON_PRETTY_PRINT : 0;
    file_put_contents(Config::str(CONFIG_REPORT_FILE), json_encode($data, $opts) . "\n", FILE_APPEND);
}

/**
 * helper function for api dashboard
 */
function alert_or_block($config) : string {
    if ($config === 'report' || $config === 'alert') { return 'report'; }
    if (!$config) { return 'off'; }
    return 'block';
}

/**
 * returns a maybe of the block if no exception exists
 */
function filter_block_exceptions(Block $block, array $exceptions) : \TF\Maybe {
    return \TF\Maybe::of(array_reduce($exceptions, '\BitFire\match_block_exception', $block));
}

// parse the request into a single passable object
// PURE
function process_request(array $get, array $post, array $server, array $cookie = array()) : array {

    $url = parse_url($server['REQUEST_URI'] ?? '//localhost/');
    $request = array(
        REQUEST_HOST => parse_host_header($server['HTTP_HOST'] ?? ''),
        "PATH" => $url['path'] ?? '/',
        "PORT" => $server['SERVER_PORT'] ?? 8080,
        "GET" => \TF\map_mapvalue($get, '\\BitFire\\each_input_param'),
        "POST" => \TF\map_mapvalue($post, '\\BitFire\\each_input_param'),
        REQUEST_METHOD => $server['REQUEST_METHOD'] ?? 'GET');

    $request['FULL']  = http_build_query($request['GET']);
    $request['FULL'] .= " POST " .http_build_query($request['POST']);

        
    $get_counts = array();
    // count character frequencies
    foreach($get as $key => $value) {
        $get_counts[$key] = (is_array($value)) ? 
            array_reduce($value, '\\BitFire\\get_counts_reduce', array()) :
            get_counts($value);
    }
    $request['GETC'] = $get_counts;
    
    $post_counts = array();
    // count character frequencies
    foreach($post as $key => $value) {
        $post_counts[$key] = (is_array($value)) ? 
            array_reduce($value, 'BitFire\\get_counts_reduce', array()) :
            get_counts($value);
    }
    $request['POSTC'] = $post_counts;

    // add canonical header values
    $request['REQUESTED_WITH'] = $server['HTTP_X_REQUESTED_WITH'] ?? null;
    $request['FETCH_MODE'] = $server['HTTP_SEC_FETCH_MODE'] ?? null;
    $request[REQUEST_UA] = strtolower($server['HTTP_USER_AGENT']) ?? '';
    $request[REQUEST_SCHEME] = $server['REQUEST_SCHEME'] ?? 'http';
    $request['UPGRADE_INSECURE'] = ($request[REQUEST_SCHEME] == 'http') ? $server['HTTP_UPGRADE_INSECURE_REQUESTS'] ?? null : null;
    $request['ACCEPT'] = $server['HTTP_ACCEPT'] ?? '';
    $request['CONTENT_TYPE'] = $server['HTTP_CONTENT_TYPE'] ?? 'text/html';
    $request[REQUEST_COOKIE] = $cookie;
    $request[REQUEST_ACCEPT] = (stripos($server['HTTP_ACCEPT_ENCODING']??'', 'gzip') === false) ? 'no_encode' : $server['HTTP_ACCEPT_ENCODING'];
    $header_name = strtoupper(Config::str('ip_header', 'REMOTE_ADDR'));
    switch ($header_name) {
        case "X-FORWARDED-FOR":
            $request[REQUEST_IP] = get_fwd_for($server[$header_name] ?? '127.0.0.1');
            break;
        case "REMOTE_ADDR":
        case "X-FORWARDED-FOR":
        default:
            $request[REQUEST_IP] = getIP($server[$header_name] ?? '127.0.0.1');
            break;
    }

    // set the ajax flag
    $request['ajax'] = is_ajax($request);

    return $request;
}

function each_input_param($in) : string {
    if (is_array($in)) {
        $in = implode("^", $in);
    }
    if (strlen($in) > 0) {
        $value = strtolower(urldecode($in));
        if (Config::enabled("block_profanity")) {
            $value = \BitFire\replace_profanity($value);
        }
        return (Config::enabled('decode_html')) ? html_entity_decode($value) : $value;
    }
    return strval($in);
}


// remove port numbers from http host headers, always returns a string of some length
// PURE
function parse_host_header(string $header) : string {
    // strip off everything after the first port
    $header .= ':'; // ensure we have one :
    return \strtolower(\substr($header, 0, \strpos($header, ':')));
}

// count characters, but not latin unicode characters with umlots, etc
// PURE
function get_counts(string $input) : array {
    // match any unicode character in the letter or digit category, 
    // and count the remaining characters 
    if (empty($input)) { return array(); }
    $input2 = \preg_replace('/[\p{L}\d]/iu', '', $input, -1, $count);
    if (empty($input2)) { return array(); }
    return \count_chars($input2, 1);
}

function get_counts_reduce(array $carry, string $input) : array {
    // match any unicode character in the letter or digit category, 
    // and count the remaining characters 
    $counts = get_counts($input);
    foreach (\array_keys($counts) as $key) {
        $carry[$key] = (isset($carry[$key])) ?
            $carry[$key] + $counts[$key] :
            $counts[$key];
    }
    return $carry;
}


/**
 * returns true if the request is an ajax request
 * looks for an 'ajax' parameter to $request with the cached value of this call
 * if not found, inspects the request and returns the inspection result
 * TODO: add testing for some file download types? (*cough WF *cough)
 * PURE
 */
function is_ajax(array $request) : bool {
    if (isset($request['ajax'])) { return $request['ajax']; }
    
    $ajax = false;
    if ($request[REQUEST_METHOD] !== 'GET') { return true; }
    // path is a  wordpress ajax request
    if (\stripos($request['PATH'], "ajax.php") !== false) { return true; }
    
    // accept || content type is requested as javascript
    // if the client is looking for something other than html, it's ajax
    if (\stripos($request['ACCEPT'], 'text/html') === false &&
        \stripos($request['CONTENT_TYPE'], 'text/html') === false) { return true; }

    // often these are set on fetch or xmlhttp requests
    if ($request['REQUESTED_WITH'] || $request['FETCH_MODE'] === 'cors' ||  $request['FETCH_MODE'] === 'websocket') {
        return true;
    }

    // fall back to using upgrade insecure (should only come on main http requests), this should work for all major browsers
    $upgrade_insecure = ($request[REQUEST_SCHEME] == "http" && ($request['UPGRADE_INSECURE'] === null || \strlen($request['UPGRADE_INSECURE']) < 1)) ? true : false;
    return $upgrade_insecure;
}

// opposite of is_ajax
function is_not_ajax(array $request) {
    return !is_ajax($request);
}

/**
 * parse out the forwarded
 */
function get_fwd_for(string $header) {
    if (preg_match('/for\s*=\s*["\[]*([0-9\.\:])+/i', $header, $matches)) {
        return $matches[1];
    }
    return $header;
}

// return leftmost forwarded for header
// converts a remote_addr into an ipv4 address if at all possible
// handles ipv6 as well 
// PURE
function getIP(string $remote_addr = '127.0.0.2') : string {
    
    $parts = explode(",", $remote_addr);
    return trim($parts[0]??$remote_addr);
    
    // Known prefix
    $v4mapped_prefix_bin = hex2bin('00000000000000000000ffff');

    // Parse
    $addr_bin = inet_pton($remote_addr);
    if ($addr_bin === FALSE ) {
        return $remote_addr;
    }

    // Check prefix, and map ipv4 inside ipv6 address
    if(substr($addr_bin, 0, strlen($v4mapped_prefix_bin)) == $v4mapped_prefix_bin) {
        $addr_bin = substr($addr_bin, strlen($v4mapped_prefix_bin));
    }

    // Convert back to printable address in canonical form
    $x = inet_ntop($addr_bin);
    return ($x == "::1") ? '127.0.0.1' : $x;
}

// return true if  request[path] contains url_match
function url_contains(array $request, string $url_match) : bool {
    return stristr($request['PATH'], $url_match) !== false;
}


/**
 * returns $block if it doesn't match the block exception
 */
function match_block_exception(Block $block, array $exception) : Block {
    return $block;
}

// TODO: add override for additional uniqueness 
function cache_unique() {
    $lang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ',';
    $parts = explode(',', $lang);
    return $parts[0];
}

/**
 * returns filtered profanity 
 * pure
 */
function replace_profanity(string $data) : string {
    return preg_replace('/('.PROFANITY.')/', '@#$!%', $data);
}

function add_country($data) {
    if (!is_array($data) || count($data) < 1) { return $data; }
    $map = json_decode(file_get_contents(WAF_DIR . "cache/country.json"), true);
    $result = array();
    foreach ($data as $report) {
        $code = \TF\ip_to_country($report['ip'] ?? '');
        $report['country'] = $map[$code];
        $result[] = $report; 
    }
    return $result;
}


function post_request(array $request, ?Block $block, ?array $ip_data) {
    $response_code = http_response_code();
    if ($block === null && $response_code < 300) { return; } 

    // add browser data if available
    $bot = $whitelist = false;
    $bot_filter = BitFire::get_instance()->bot_filter;
    $valid = -1;
    if ($bot_filter !== null) {
        $bot = $bot_filter->browser['bot'] ?? false;
        $valid = $bot_filter->browser['valid'] ?? -1;
        $whitelist = $bot_filter->browser[AGENT_WHITELIST] ?? false;
    }

    if ($block === null && !$bot) { return; }
    if ($block === null && !$whitelist) { $block = new Block(31000, "n/a", "unknown bot", $request[REQUEST_UA], 0); }


    $class = intval($block->code / 1000) * 1000;
    $data = array(
        "ip" => $request[REQUEST_IP],
        "scheme" => $request[REQUEST_SCHEME],
        "ua" => $request[REQUEST_UA] ?? '',
        "url" => $request[REQUEST_HOST] . ':' . $request['PORT'] . $request[REQUEST_PATH],
        "params" => param_to_str($request['GET'], true),
        "post" => param_to_str($request['POST'], true),
        "verb" => $request[REQUEST_METHOD],
        "ts" => microtime(true),
        "tv" => date("D H:i:s ") . date('P'),
        "referer" => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
        "eventId" => $block->code,
        "classId" => $class,
        "item" => $block->parameter,
        "name" => $block->pattern,
        "match" => $block->value,
        "ver" => BITFIRE_VER,
        "pass" => $block->code === 0 ? true : false,
        "bot" => $bot,
        "response" => $response_code,
        "whitelist" => $whitelist,
        "valid" => $valid,
        "offset" => 0
    );
    
    // add ip data to the log
    if (isset($ip_data['rr1m'])) {
        $data['rr1m'] = $ip_data['rr_1m'];
        $data['rr5m'] = $ip_data['rr_5m'];
        $data['ref'] = $ip_data['ref'];
        $data['404'] = $ip_data['404'];
        $data['500'] = $ip_data['500'];
    }


    
    // cache the last 15 blocks
    $cache = CacheStorage::get_instance();
    $cache->rotate_data("log_data", $data, 15);
    $ip = ip2long($request[REQUEST_IP]);
    $cache->update_data("metrics-".date('G'), function ($metrics) use ($class, $ip) {
        $metrics[$class]++;
        $ip = ($ip < 100000) ? ip2long('127.0.0.1') : $ip; 
        $metrics[$ip] = ($metrics[$ip] ?? 0) + 1;
        return $metrics;
    }, BITFIRE_METRICS_INIT, 86400);


    $content = json_encode($data)."\n";
    if (Config::enabled('block_file')) {
        file_put_contents(Config::str('block_file'), $content, FILE_APPEND);
    }
    \TF\bit_http_request("POST", "https://www.bitslip6.com/botmatch/_doc",
    $content, 2, array("Content-Type" => "application/json"));
}

/**
 * pure param to string with name filtering and sub array support
 */
function param_to_str(array $params, $filter = false) {
    $post_params = array();
    $filtered_names = Config::arr("filtered_logging");
    foreach ($params as $key => &$val) {
        if ($filtered_names[$key] ?? false) {
            $val = "**FILTERED**";
        } else if (is_array($val) === true) {
            $val = implode(',', $val);
        }
        $post_params[] = $key.'='.$val;
    }
    return implode('&', $post_params);
}



function block_ip($block, array $ip_data) : void {
    if (!Config::enabled('allow_ip_block') || !$block) { return; }
    $exp = time();
    if ($block->block_time == 1) {
        $exp += Config::int('short_block_time', 600);
    } else if ($block->block_time == 2) {
        $exp += Config::int('medium_block_time', 3600);
    } else if ($block->block_time >= 3) {
        $exp += Config::int('long_block_time', 86400);
    } else {
        return;
    }

    $blockfile = BLOCK_DIR . $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    @file_put_contents($blockfile, $ip_data['ref'] ?? \substr(\uniqid(), 5, 8));
    \touch($blockfile, $exp);
    
    \http_response_code(Config::int('response_code', 500));
    include WAF_DIR . DS . "views/block.php";
}
