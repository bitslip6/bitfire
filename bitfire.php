<?php declare(strict_types=1);
namespace BitFire;
use TF\CacheStorage;
require WAF_DIR . "bitfire_pure.php";

if (defined('BITFIRE_VER')) { return; }
 

define("BITFIRE_CONFIG", dirname(__FILE__) . "/config.ini");
const FEATURE_CLASS = array(0 => 'require_full_browser', 10000 => 'xss_block', 11000 => 'web_block', 12000 => 'web_block', 13000 => 'web_block', 14000 => 'sql_block', 15000 => 'web_block', 16000 => 'web_block', 17000 => 'web_block', 18000 => 'spam_filter_enabled', 20000 => 'require_full_browser', 21000 => 'file_block', 22000 => 'web_block', 23000 => 'check_domain', 24000 => 'whitelist_enable', 25000 => 'blacklist_enable', 26000 => 'rate_limit', 50000 => '');

const BITFIRE_API_FN = array('\\BitFire\\get_block_types', '\\BitFire\\get_valid_data', '\\BitFire\\get_ip_data', '\\BitFire\\get_hr_data', '\\BitFire\\make_code');
const BITFIRE_METRICS_INIT = array('challenge' => 0, 'valid' => 0, 10000 => 0, 11000 => 0, 12000 => 0, 13000 => 0, 14000 => 0, 15000 => 0, 16000 => 0, 17000 => 0, 18000 => 0, 19000 => 0, 20000 => 0, 21000 => 0, 22000 => 0, 23000 => 0, 24000 => 0, 25000 => 0, 26000 => 0, 70000 => 0);
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
        $result = false;
        switch ($this->_type) {
            case MatchType::EXACT: 
                $result = ($this->_matched === $this->_value);
                break;
            case MatchType::CONTAINS: 
                if (is_array($this->_value)) {
                    foreach ($this->_value as $v) {
                        $m = strstr($this->_matched, $v);
                        if ($m !== false) { $result = true; }
                    }
                } else { $result = strpos($this->_matched, $this->_value) !== false; }
                break;
            case MatchType::IN: 
                $result = in_array($this->_matched, $this->_value);
                break;
            case MatchType::NOTIN: 
                $result = !in_array($this->_matched, $this->_value);
                break;
            case MatchType::REGEX:
                $result = preg_match($this->_value, $this->_matched) > 0;
                break;
            default:
        }
        return $result;
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
        if ($code === FAIL_NOT) { return \TF\Maybe::$FALSE; }
        $block = new Block($code, $parameter, $value, $pattern, $block_time);
        if (is_report($block)) {
            self::reporting($block, BitFire::get_instance()->_request);
            return \TF\Maybe::$FALSE;
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
        require_once WAF_DIR."dashboard.php";
        serve_dashboard($this->_request[REQUEST_PATH]);
        

        $block = \TF\Maybe::$FALSE;
        if (!Config::enabled(CONFIG_ENABLED)) { return $block; }

        // don't inspect local commands
        if (!isset($_SERVER['REQUEST_URI'])) { return $block; }

		if (Config::enabled(CONFIG_SECURITY_HEADERS)) {
            require_once WAF_DIR."headers.php";
			\BitFireHeader\send_security_headers($this->_request);
		}
        
        // bot filtering
        if ($this->bot_filter_enabled()) {
            require_once WAF_DIR . 'botfilter.php';
            $this->bot_filter = new BotFilter($this->cache);
            $block = $this->bot_filter->inspect($this->_request);
        }


        // generic filtering
        if ($block->empty() && Config::enabled(CONFIG_WEB_FILTER_ENABLED)) {
            require_once WAF_DIR . 'webfilter.php';
            $this->_web_filter = new \BitFire\WebFilter($this->cache);
            $block = $this->_web_filter->inspect($this->_request);
        }

        $block->doifnot(array($this, "cache_behind"));

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
