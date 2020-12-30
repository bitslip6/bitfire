<?php declare(strict_types=1);
namespace BitFire;
use TF\Maybe;

// TODO: remove $_cache

if (defined('BITFIRE_VER')) { return; }

const BITFIRE_VER = 1.04;
const BITFIRE_DOMAIN = "http://api.bitslip6.com";
const BITFIRE_COMMAND = "BITFIRE_API";
define("BITFIRE_CONFIG", dirname(__FILE__) . "/bitconfig.ini");

const BITFIRE_MAX_HASH_COUNT = 20;
const BITFIRE_MAX_AUDIT = 20;
const BITFIRE_MAX_PAGES = 200;
const WAF_MIN_HIT = 25;
const WAF_MIN_PERCENT = 10;

const CONFIG_REQUIRE_BROWSER = 'require_full_browser';
const CONFIG_USER_TRACK_COOKIE = 'user_tracking_cookie';
const CONFIG_MAX_CACHE_AGE = 'max_cache_age';
const CONFIG_USER_TRACK_PARAM = 'user_tracking_param';
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
const REQUEST_PATH = 'PATH';
const REQUEST_METHOD = 'METHOD';

const BITFIRE_INPUT = '_bitfire';

const THROTTLE_LOCK_TIME = 600;
const THROTTLE_LOCK_FILE = ".bitfire.lock";

const FAIL_NOT = 0;

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

    public function match(array $request) : bool {
        $this->_matched = $request[$this->_key] ?? '';
        switch ($this->_type) {
            case MatchType::EXACT: 
                return $this->_matched === $this->_value;
            case MatchType::CONTAINS: 
                return strstr($this->_matched, $this->_value) !== false;
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
    private static $_options = null;

    public static function set(array $options) {
        Config::$_options = $options;
    }

    public static function set_value(string $option_name, $value) {
        Config::$_options[$option_name] = $value;
    }

    /**
     * returns true if Config contains all named parameters
     */
    public static function contains(...$names) {
        return array_reduce($names, function($result, $name) { return $result & isset(Config::$_options[$name]); }, true);
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

    public static $_fail_reasons = array();
    protected $_ip_data = null;

    public $_request = null;
    private $_page = null;

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
            $this->cache = new \TF\CacheStorage(Config::str(CONFIG_CACHE_TYPE, 'shm'));
            
            $exception_file = WAF_DIR . "cache/exceptions.json";
            self::$_exceptions = (file_exists($exception_file)) ? \TF\un_json(file_get_contents($exception_file)) : array();
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
        return filter_block_exceptions($block, self::$_exceptions);
    }

    
    /**
     * TODO: MOVE TO CACHE.php
     */
    // update the cache behind page
    public static function update_cache_behind() {
        if (strlen($_SERVER['SERVER_NAME']??'') < 1) { return; }
        $secret = Config::str('secret', 'bitfiresekret');
        $u = $_SERVER['REQUEST_SCHEME'] . "://" . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'] . "?" . BITFIRE_INPUT . "=$secret";
        $d = \TF\bit_http_request("GET", $u, "");
        file_put_contents(WAF_DIR . '/cache/root:'. cache_unique(), $d);
    }


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
                    echo file_get_contents(WAF_DIR . "cache/$page");
                    echo "<!-- cache -->\n";
                    exit;
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
        $block = \TF\Maybe::of(false);
        if (!Config::enabled(CONFIG_ENABLED)) { return $block; }

        // don't inspect local commands
        if (!isset($_SERVER['REQUEST_URI'])) { return $block; }

		if (Config::enabled(CONFIG_SECURITY_HEADERS)) {
			\BitFireHeader\send_security_headers($this->_request);
		}
        
        // bot filtering
        if ($this->bot_filter_enabled()) {
            require WAF_DIR . 'botfilter.php';
            $this->bot_filter = new BotFilter($this->cache);
            $block = $this->bot_filter->inspect($this->_request);
        }
        
        // perform cache behind after bot filtering (don't want to cache bot requests)
        if ($block->empty()) {
            $this->cache_behind();
        }

        // generic filtering
        if ($block->empty() && Config::enabled(CONFIG_WEB_FILTER_ENABLED)) {
            require WAF_DIR . 'webfilter.php';
            $this->_web_filter = new \BitFire\WebFilter($this->cache);
            $block = $this->_web_filter->inspect($this->_request);
        }

        // if wordpress is enabled, and we are not an ajax url and a wp-admin page
        /*
        if (Config::enabled("wordpress") &&
            \TF\and_pipe(
                \TF\partial_right("BitFire\\url_contains", "wp-admin"),
                "BitFire\is_not_ajax")($this->_request)
        ) {
            add_word_press_admin_scripts();
        }
        */
        
        if (!$block->empty()) {
            $ip_data = ($this->bot_filter !== null) ? $this->bot_filter->ip_data : array();
            \BitFire\block_ip($block->value(), $ip_data);
            //register_shutdown_function('\\BitFire\\log_request', $this->_request, $block->value(), $ip_data);
            //\BitFire\log_request($this->_request, $block->value(), $ip_data);
        }

        return $block;
    }

    /**
     * @return bool true if any bot blocking features are enabled
     */
    protected function bot_filter_enabled() : bool {
        // disable bot filtering for internal requests
        $bf = $_GET[BITFIRE_INPUT] ?? '';
        if ($bf === trim(Config::str(CONFIG_SECRET, 'bitfire_secret'))) { return false; }

        return (
            Config::enabled(CONFIG_CHECK_DOMAIN) ||
            Config::enabled(CONFIG_BLACKLIST_ENABLE) ||
            Config::enabled(CONFIG_WHITELIST_ENABLE) ||
            Config::enabled(CONFIG_REQUIRE_BROWSER) ||
            Config::enabled(CONFIG_HONEYPOT) ||
            Config::str(CONFIG_RATE_LIMIT_ACTION) !== '');
    }
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
        "HOST" => parse_host_header($server['HTTP_HOST'] ?? ''),
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
    $request['USER_AGENT'] = $server['HTTP_USER_AGENT'] ?? '';
    $request['SCHEME'] = $server['REQUEST_SCHEME'] ?? 'http';
    $request['UPGRADE_INSECURE'] = ($request['SCHEME'] == 'http') ? $server['HTTP_UPGRADE_INSECURE_REQUESTS'] ?? null : null;
    $request['ACCEPT'] = $server['HTTP_ACCEPT'] ?? 'text/html';
    $request['CONTENT_TYPE'] = $server['HTTP_CONTENT_TYPE'] ?? 'text/html';
    $request[REQUEST_COOKIE] = $cookie;

    $request[REQUEST_IP] = getIP($server['REMOTE_ADDR'] ?? '127.0.0.1');

    // set the ajax flag
    $request['ajax'] = is_ajax($request);

    //\TF\dbg($request);
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
    return \count_chars(\preg_replace('/[\p{L}\d]/iu', '', $input, -1, $count), 1);
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
    $upgrade_insecure = ($request['SCHEME'] == "http" && ($request['UPGRADE_INSECURE'] === null || \strlen($request['UPGRADE_INSECURE']) < 1)) ? true : false;
    return $upgrade_insecure;
}

// opposite of is_ajax
function is_not_ajax(array $request) {
    return !is_ajax($request);
}

// converts a remote_addr into an ipv4 address if at all possible
// handles ipv6 as well 
// PURE
function getIP(string $remote_addr = '127.0.0.2') : string {
    // Known prefix
    $v4mapped_prefix_bin = hex2bin('00000000000000000000ffff');

    // Parse
    $addr_bin = inet_pton($remote_addr);
    if ($addr_bin === FALSE ) {
        return $remote_addr;
    }

    // Check prefix, and map ipv4 inside ipv6 address
    if( substr($addr_bin, 0, strlen($v4mapped_prefix_bin)) == $v4mapped_prefix_bin) {
        $addr_bin = substr($addr_bin, strlen($v4mapped_prefix_bin));
    }

    // Convert back to printable address in canonical form
    return inet_ntop($addr_bin);
}

// return true if  request[path] contains url_match
function url_contains(array $request, string $url_match) : bool {
    return stristr($request['PATH'], $url_match) !== false;
}


/**
 * returns $block if it doesn't match the block exception
 */
function match_block_exception(Block $block, array $exception) : Block {
    if ($block === null) { return $block; }

    switch ($exception['type']) {
        case "allcode":
            if ($block->code === $exception['code'])
                if ($exception['warn']??false) {
                    $block->block_time = BLOCK_WARN;
                }
                return null;
        break;
    }
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
    return preg_replace('/('.Config::str(CONFIG_PROFANITY).')/', '@#$!%', $data);
}


function log_request(array $request, Block $block, array $ip_data) {
    $class = ($block->code / 1000) * 1000;

    $data = array(
        "ip" => $request[REQUEST_IP],
        "ua" => $request[REQUEST_UA] ?? '',
        "url" => $request[REQUEST_HOST] . $request['PORT'] . $request[REQUEST_PATH],
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
        "pass" => $block->code === 0 ? true : false,
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


    // add browser data if available
    $bot_filter = BitFire::get_instance()->bot_filter;
    if ($bot_filter !== null) {
        $data["bot"] = $bot_filter->browser['bot'] ?? 'unknown';
        $data["whitelist"] = $bot_filter->browser[AGENT_WHITELIST] ?? false;
    }

    $content = json_encode($data)."\n";

    \TF\bit_http_request("POST", "https://search-bitwaf-jadw3humgpe6ima6hbf6jpffwq.us-west-2.es.amazonaws.com/filtered/_doc",
    $content, 2, array("Content-Type" => "application/json"));
}

/**
 * pure param to string with name filtering and sub array support
 */
function param_to_str(array $params, $filter = false) {
    $post_params = array();
    $filtered_names = Config::arr("filtered_logging");
    foreach ($params as $key => &$val) {
        if ($filter && in_array($key, $filtered_names)) {
            $val = "**FILTERED**";
        } else if (is_array($val) === true) {
            $val = implode(',', $val);
        }
        $post_params[] = $key.'='.$val;
    }
    return implode('&', $post_params);
}



function block_ip($block, array $ip_data) : void {
    if (Config::enabled('no_ip_block') || !$block) { return; }
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