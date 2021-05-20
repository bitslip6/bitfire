<?php declare(strict_types=1);
namespace BitFire;
use TF\CacheStorage;
require WAF_DIR . "bitfire_pure.php";


define("BITFIRE_CONFIG", dirname(__FILE__) . "/config.ini");
require_once WAF_DIR."const.php";
require_once WAF_DIR."storage.php";
require_once WAF_DIR."util.php";
require_once WAF_DIR."english.php";


class Headers
{
    public $requested_with = '';
    public $fetch_mode = '';
    public $accept;
    public $content;
    public $encoding;
    public $dnt;
    public $upgrade_insecure;
}

class Request
{
    public $headers;
    public $host;
    public $path;
    public $ip;
    public $method;
    public $port;
    public $scheme;


    public $get;
    public $get_freq = array();
    public $post;
    public $post_freq = array();
    public $cookies;

    public $agent;
    public $referer;
    public $ajax = false;
}


class MatchType
{
    protected $_type;
    protected $_key;
    protected $_value;
    protected $_matched;
    protected $_block_time;
    protected $_match_str;

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
        $this->_match_str = '';
    }

    public function match(\BitFire\Request $request) : bool {
        $key = $this->_key;
        $this->_matched = $request->$key ?? '';
        $result = false;
        switch ($this->_type) {
            case MatchType::EXACT: 
                $result = ($this->_matched === $this->_value);
                break;
            case MatchType::CONTAINS: 
                if (is_array($this->_value)) {
                    foreach ($this->_value as $v) {
                        $m = strpos($this->_matched, $v);

                        if ($m !== false) { 
                            $result = true;
                            $this->_match_str = $v;
                            break;
                        }
                    }
                } else {  $result = strpos($this->_matched, $this->_value) !== false; }
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

        if ($result && $this->_match_str === '') { $this->_match_str = $this->_value; }
        return $result;
    }

    public function match_pattern() : string {
        return $this->_match_str;
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

class Exception {
    public $code;
    public $parameter;
    public $url;
    public $host;
    public $uuid;

    public function __construct(int $code = 0, string $uuid = 'x', ?string $parameter = NULL, ?string $url = NULL, ?string $host = NULL) {
        $this->code = $code;
        $this->parameter = $parameter;
        $this->url = $url;
        $this->host = $host;
        $this->uuid = $uuid;
    }
}


class Config {
    public static $_options = null;
    private static $_nonce = null;

    public static function nonce() : string {
        if (self::$_nonce == null) {
            self::$_nonce = str_replace(array('-','+','/'), "", \TF\random_str(10));
        }
        return self::$_nonce;
    }

    // set the full list of configuration options
    public static function set(array $options) : void {
        Config::$_options = $options;
    }

    // execute $fn if option enabled
    public static function if_en(string $option_name, $fn) {
        if (Config::$_options[$option_name]) { $fn(); }
    }

    // set a single value
    public static function set_value(string $option_name, $value) {
        Config::$_options[$option_name] = $value;
    }

    // return true if value is set to true or "block"
    public static function is_block(string $name) : bool {
        return (Config::$_options[$name]??'' == 'block' || Config::$_options[$name]??'' == true) ? true : false;
    }

    // get a string value with a default
    public static function str(string $name, string $default = '') : string {
        return (string) Config::$_options[$name] ?? $default;
    }

    // get an integer value with a default
    public static function int(string $name, int $default = 0) : int {
        return intval(Config::$_options[$name] ?? $default);
    }

    public static function arr(string $name, array $default = array()) : array {
        return (isset(Config::$_options[$name]) && is_array(Config::$_options[$name])) ? Config::$_options[$name] : $default;
    }

    public static function enabled(string $name, bool $default = false) : bool {
        if (!isset(Config::$_options[$name])) { return $default; }
        if (Config::$_options[$name] === "block" || Config::$_options[$name] === "report" || Config::$_options[$name] == true) { return true; }
        return (bool)Config::$_options[$name];
    }

    public static function disabled(string $name, bool $default = true) : bool {
        return !Config::enabled($name, $default);
    }

    public static function file(string $name) : string {
        if (!isset(Config::$_options[$name])) { return ''; }
        if (Config::$_options[$name][0] === '/') { return (string)Config::$_options[$name]; }
        return WAF_DIR . (string)Config::$_options[$name];
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
    public static $_exceptions = NULL;
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
            $this->_request = process_request2($_GET, $_POST, $_SERVER, $_COOKIE);
            
            // we will need cache storage and secure cookies
            $this->cache = \TF\CacheStorage::get_instance();

            $exception_file = WAF_DIR . "cache/exceptions.json";

            if (function_exists('\BitFirePRO\send_pro_headers')) {
                \BitFirePRO\send_pro_mfa($this->_request);
            }
        }
        $this->api_call();
    }
    
    /**
     * write report data after script execution 
     */
    public function __destruct() {
        if (!Config::enabled(CONFIG_REPORT_FILE) || count(self::$_reporting) < 1) { return; }
        // encoder is json_encode with pretty printing if file has word "pretty" in it
        $encoder = \TF\partial_right('json_encode', (strpos(Config::str(CONFIG_REPORT_FILE), 'pretty') > 0) ? JSON_PRETTY_PRINT : 0);
        @file_put_contents(Config::file(CONFIG_REPORT_FILE), join(",", array_map($encoder, self::$_reporting)) . "\n", FILE_APPEND);
/*
        $out = "";
        foreach (self::$_reporting as $report) {
            $out .= json_encode($report, $opts) . "\n";
        }
*/
    }

    protected function api_call() {
        if ($_GET[BITFIRE_INTERNAL_PARAM]??'' === Config::str(CONFIG_SECRET)) {
            require_once WAF_DIR."api.php";

            $fn = '\\BitFire\\' . htmlentities($_GET[BITFIRE_COMMAND]??'nop');
            if (!in_array($fn, BITFIRE_API_FN)) { exit("unknown function [$fn]"); }

            $result = $fn($this->_request);
            exit ($result);
        } else if ($_GET[BITFIRE_INTERNAL_PARAM]??'' === 'report') {
            require_once WAF_DIR."headers.php";
            exit (\BitFireHeader\header_report($this->_request));
        }
    }

    /**
     * append an exception to the list of exceptions
     */
    public function add_exception(Exception $exception) {
        self::$_exceptions[] = $exception;
    }

    /**
     * create a new block, returns a maybe of a block, empty if there is an exception for it
     */
    public static function new_block(int $code, string $parameter, string $value, string $pattern, int $block_time = 0) : \TF\MaybeBlock {
        if ($code === FAIL_NOT) { return \TF\Maybe::$FALSE; }
        $block = new Block($code, $parameter, $value, $pattern, $block_time);
        $req = BitFire::get_instance()->_request;
        if (is_report($block)) {
            self::reporting($block, $req);
            return \TF\Maybe::$FALSE;
        }
        self::$_exceptions = (self::$_exceptions === NULL) ? load_exceptions() : self::$_exceptions;
        return filter_block_exceptions($block, self::$_exceptions, $req);
    }
    
    /**
     * TODO: format blocks the same way as reports
     */
    protected static function reporting(Block $block, \BitFire\Request $request) {
        $data = array('time' => \TF\utc_date('r'), 'tv' => \TF\utc_time(),
            'exec' => @number_format(microtime(true) - $GLOBALS['start_time']??0, 6). ' sec',
            'block' => $block,
            'request' => $request);
        $bf = BitFire::get_instance()->bot_filter;
        if ($bf != null) {
            $data['browser'] = (array) $bf->browser;
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

        // if the request is to the homepage with no parameters, it is possible to cache
        $tracking_cookie = Config::str(CONFIG_USER_TRACK_COOKIE, '_bitf');
        $site_cookies = array_filter(array_keys($_COOKIE), function($name) use ($tracking_cookie) { return stripos($name, $tracking_cookie) === false; });

        if (Config::int(CONFIG_MAX_CACHE_AGE, 0) > 0 &&
            $this->_request->path === '/' && 
            $this->_request->method === "GET" &&
            count($_GET) === 0 && 
            count($site_cookies) === 0) {
                // update the cache after this request
                register_shutdown_function([$this, 'update_cache_behind']);
                $page = WAF_DIR . 'cache/root:' . cache_unique();
                // we have a cached page that is not too old
                if ($this->cached_page_is_valid($page)) {
                    header("x-cached: 1");
                    // add a js challenge if the request is not to a bot
                    if (Config::enabled(CONFIG_REQUIRE_BROWSER) && $this->bot_filter != null && $this->bot_filter->browser->bot == false) {
                        echo \BitFireBot\make_js_challenge(
                            $this->_request->ip,
                            Config::str(CONFIG_ENCRYPT_KEY),
                            Config::str(CONFIG_USER_TRACK_COOKIE));
                    }
                    // serve the static page!
                    echo file_get_contents($page);
                    echo "<!-- cache -->\n";
                    exit();
                }
        }
    }

    /**
     * test if BitFire::CACHE_PAGE is a valid cached page (exists and is not stale)
     */
    public function cached_page_is_valid(string $page) {
        $stat_data = @stat($page);
        $exp_time = $stat_data['ctime'] + Config::int(CONFIG_MAX_CACHE_AGE);
        //echo "<!-- [$page]\n" . time() . "\n$exp_time\n"; print_r($stat_data); echo "-->\n";
        $cache_valid = ($stat_data != false && $exp_time > time());
        $h = "x-cache-valid: false";
        if ($cache_valid) { $h = "x-cache-valid: true"; }
        header($h);
        //return false;
        return $cache_valid;
    }


    /**
     * inspect a request and block failed requests
     * return false if inspection failed...
     */
    public function inspect() : \TF\MaybeBlock {

        // block from the htaccess file
        if (isset($this->_request->get['_block'])) {
            return BitFire::new_block(28001, "_block", "url", $this->_request->get['_block'], 0);
        }

        // if we are disabled, just return
        if ($this->_request === NULL || Config::disabled(CONFIG_ENABLED)) {
            return \TF\MaybeBlock::of(NULL);
        }

        // dashboard requests, TODO: MOVE TO api.php
        if ($this->_request->path === Config::str(CONFIG_DASHBOARD_PATH)) {
            require_once WAF_DIR."dashboard.php";
            serve_dashboard($this->_request->path);
        }
        

        // make sure that the default empty block is actually empty, hard code here because this data is MUTABLE for performance *sigh*
        \TF\Maybe::$FALSE = \TF\MaybeBlock::of(NULL);
        $block = \TF\MaybeBlock::of(NULL);

        if (!Config::enabled(CONFIG_ENABLED)) { return $block; }

        // don't inspect local commands
        if (!isset($_SERVER['REQUEST_URI'])) { return $block; }

        // bot filtering
        if ($this->bot_filter_enabled()) {
            require_once WAF_DIR . 'botfilter.php';
            $this->bot_filter = new BotFilter($this->cache);
            $block = $this->bot_filter->inspect($this->_request);
        }

        if (Config::enabled(CONFIG_SECURITY_HEADERS)) {
            require_once WAF_DIR."headers.php";
			\BitFireHeader\send_security_headers($this->_request);
		}


        // generic filtering
        if ($block->empty() && Config::enabled(CONFIG_WEB_FILTER_ENABLED)) {
            require_once WAF_DIR . 'webfilter.php';
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
