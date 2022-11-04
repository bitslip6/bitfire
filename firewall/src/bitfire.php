<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * main firewall.  holds core data references.
 */

namespace BitFire;

use BitFire\Config as CFG;
use ThreadFin\CacheStorage;
use ThreadFin\Effect;
use ThreadFin\FileMod;
use ThreadFin\Maybe;
use ThreadFin\MaybeBlock;

use const ThreadFin\DAY;

use function BitFire\Pure\json_to_file_effect;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\decrypt_tracking_cookie;
use function ThreadFin\en_json;
use function ThreadFin\httpp;
use function ThreadFin\random_str;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\partial_right;
use function ThreadFin\un_json;
use function ThreadFin\utc_date;
use function ThreadFin\utc_time;

require_once \BitFire\WAF_SRC."bitfire_pure.php";
require_once \BitFire\WAF_SRC."const.php";
require_once \BitFire\WAF_SRC."util.php";
require_once \BitFire\WAF_SRC."storage.php";
require_once \BitFire\WAF_SRC."english.php";
require_once \BitFire\WAF_SRC."botfilter.php";


/**
 * http header abstraction 
 * @package BitFire
 */
class Headers
{
    /** @var string $requested_with  set to XMLHttpRequest for xml http request */
    public $requested_with = '';
    /** @var string $fetch_mode set to sec-fetch-mode (cors, navigate, no-cors, same-origin, websocket) */
    public $fetch_mode = '';
    /** @var string $accept http accept header */
    public $accept;
    /** @var string $content http content type */
    public $content;
    /** @var string $encoding http accept encoding */
    public $encoding;
    /** @var string $dnt do not track header */
    public $dnt;
    /** @var string $upgrade_insecure upgrade insecure request header */
    public $upgrade_insecure;
    /** @var string $referer the referring html page */
    public $referer;
}

/**
 * http request abstraction
 * @package BitFire
 */
class Request
{
    public $host;
    public $path;
    public $ip;
    public $method;
    public $port;
    public $scheme;

    public $get;
    public $get_freq = array();
    public $post;
    public $post_len;
    public $post_raw;
    public $post_freq = array();
    public $cookies;

    public $agent;
    /** @var Headers $headers the request headers */
    public Headers $headers;
}


/**
 * Match class used for matching mapping request match DATA to Request DATA
 * @package BitFire
 */
class MatchType
{
    protected $_type;
    protected $_key;
    protected $_value;
    protected $_matched;
    protected $_block_time;
    protected $_match_str;
    protected $_chained;

    const EXACT = 0;
    const CONTAINS = 1;
    const IN = 2;
    const NOTIN = 3;
    const REGEX = 4;

    public function __construct(int $type, string $key, $value, int $block_time, MatchType $chain = null) {
        $this->_type = $type;
        $this->_key = $key;
        $this->_value = $value;
        $this->_matched = 'none';
        $this->_block_time = $block_time;
        $this->_match_str = '';
        $this->_chained = $chain;
    }

    /**
     * Test if the request matches the MatchType
     * 
     * @param Request $request 
     * @return bool 
     */
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
                }
                else { $result = strpos($this->_matched, $this->_value) !== false; }
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

        // chain additional match types
        if ($result) {
            $result = $this->_chained->match($request);
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
    public $skip_reporting = false;

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
    public $date;

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
            self::$_nonce = str_replace(array('-','+','/'), "", random_str(10));
        }
        return self::$_nonce;
    }

    // set the full list of configuration options
    public static function set(array $options) : void {
        if (empty($options)) {
            trace("no cfg");
            CacheStorage::get_instance()->save_data("parse_ini2", null, -86400); 
        } else {
            trace("cfg");
            Config::$_options = $options;
        }
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

    // return true if value is set to "report" or "alert"
    public static function is_report(string $name) : bool {
        return (Config::$_options[$name]??'' == 'report' || Config::$_options[$name]??'' == 'alert') ? true : false;
    }

    // get a string value with a default
    public static function str(string $name, string $default = '') : string {
        if (isset(Config::$_options[$name])) { return (string) Config::$_options[$name]; }
        if ($name == "auto_start") { // UGLY HACK for settings.html
            $ini = ini_get("auto_prepend_file");
            $found = false;
            if (!empty($ini)) {
                if ($_SERVER['IS_WPE']??false || CFG::enabled("emulate_wordfence")) {
                    $file = CFG::str("wp_root")."/wordfence-waf.php";
                    if (file_exists($file)) {
                        $s = @stat($file); // cant read this file on WPE, check the size
                        $found = ($s['size']??9999 < 256);
                    }
                }
                else if (contains($ini, "bitfire")) { $found = true; }
            }
            return ($found) ? "on" : "";
        }
        return (string) $default;
    }

    public static function str_up(string $name, string $default = '') : string {
        return strtoupper(Config::str($name, $default));
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
        return \BitFire\WAF_ROOT . (string)Config::$_options[$name];
    }
}

/**
 * NOT PURE.  depends on: SERVER['PHP_AUTH_PW'], Config['password']
 */
function verify_admin_password() : Effect {
    $effect = Effect::new();

    // allow initial password set without auth
    if (CFG::str("password") == "configure") { return $effect; }
    if (CFG::str("password") == "disabled") {
        require_once \BitFire\WAF_ROOT . "/bitfire-plugin.php";
        if (\BitFirePlugin\is_admin()) { return $effect; }
    }

    $auth = $_SERVER["PHP_AUTH_PW"]??"";
    if (!$auth ||
        ((hash("sha3-256", $auth) !== CFG::str('password')) &&
        (hash("sha3-256", $auth) !== hash('sha3-256', CFG::str('password'))))) {

        $effect->header('WWW-Authenticate', 'Basic realm="BitFire Dashboard", charset="UTF-8"')
            ->response_code(401)
            ->exit(true);
    }
    return $effect;
}

/**
 * 
 */
class BitFire
{
    // data storage
    protected $_ip_key;

    // request unique id
    public $uid;
    public static $_exceptions = NULL;
    public static $_reporting = array();
    public static $_blocks = array();
    /** @var MaybeStr $cookie */
    public $cookie = NULL;

    public static $_fail_reasons = array();

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

        $this->_request = process_request2($_GET, $_POST, $_SERVER, $_COOKIE); // filter out all request data for parsed use

       
        // handle a common case urls we never care about
        if (in_array($this->_request->path, CFG::arr("urls_not_found"))) {
            http_response_code(404); die();
        }
       
        if (Config::enabled(CONFIG_ENABLED)) {
            $this->uid = substr(\uniqid(), 5, 8);

            if (function_exists('\BitFirePRO\send_pro_mfa')) {
                \BitFirePRO\send_pro_mfa($this->_request);
            }
        }
    }
    
    /**
     * write report data after script execution 
     */
    public function __destruct() {
        if (!empty(CFG::enabled(CONFIG_REPORT_FILE)) && count(self::$_reporting) > 0) {
            $coded = array_map(function (array $x):array {
                $x['http_code'] = http_response_code();
                $x['request']->cookies = "**redacted**";
                return $x; }, self::$_reporting);
            json_to_file_effect(CFG::file(CONFIG_REPORT_FILE), $coded)->run();
        }
        if (!empty(CFG::str(CONFIG_BLOCK_FILE)) && count(self::$_blocks) > 0) {
            $coded = array_map(function (array $x):array { 
                $x['http_code'] = http_response_code();
                $x['request']->cookies = "**redacted**";
                //$x['request']['headers'] = array_filter($x['request']['headers'], 'array_filter');
                return $x; }, self::$_blocks);
            json_to_file_effect(CFG::file(CONFIG_BLOCK_FILE), $coded)->run();
        }
    }

    /**
     * handle API calls.
     */
    
    /**
     * append an exception to the list of exceptions
     */
    public function add_exception(Exception $exception) {
        self::$_exceptions[] = $exception;
    }

    /**
     * create a new block, returns a maybe of a block, empty if there is an exception for it
     */
    public static function new_block(int $code, string $parameter, string $value, string $pattern, int $block_time = 0, ?Request $req = null) : MaybeBlock {
        if ($code === FAIL_NOT) { return Maybe::$FALSE; }
        if ($req == null) { trace("DEFREQ"); $req = BitFire::get_instance()->_request; }
        trace("BL:[$code]");


        $block = new Block($code, $parameter, substr($value, 0, 2048), $pattern, $block_time);
        if (is_report($block)) {
            if (!$block->skip_reporting) {
                self::reporting($block, $req, false);
            }
            trace("RPT[$code]");
            return Maybe::$FALSE;
        }
        self::$_exceptions = (self::$_exceptions === NULL) ? load_exceptions() : self::$_exceptions;
        $filtered_block = filter_block_exceptions($block, self::$_exceptions, $req);

        // do the logging
        if (!$filtered_block->empty()) {
            if (!$block->skip_reporting) {
                self::reporting($filtered_block(), $req, true);
            }
            trace("BLOCK[$code]");
        }
        return $filtered_block;
    }
    
    /**
     * report a block
     * @param bool $report_or_block true if this is a block, false if it is a report
     */
    protected static function reporting(Block $block, \BitFire\Request $request, bool $report_or_block = false) {

        $mt = microtime(true);
        $time_diff = $mt - $GLOBALS['start_time']??($mt-0.001);
        $data = array('time' => utc_date('r'), 'tv' => utc_time(),
            'exec' => @number_format($time_diff, 6). ' sec',
            'block' => $block,
            'request' => $request);
        $bf = BitFire::get_instance()->bot_filter;
        if ($bf != null) {
            $data['browser'] = (array) $bf->browser;
            $data['rate'] = $bf->ip_data;
        }
        
        if ($report_or_block) {
            self::$_blocks[] = $data;
        } else {
            self::$_reporting[] = $data;
        }
    }
    

    

    


    /**
     * inspect a request and block failed requests
     * return false if inspection failed...
     */
    public function inspect() : MaybeBlock {
        trace("ins");
        // HATE TO PUT THIS HERE, BUT WE NEED CFG LOADED SO WE CAN INCLUDE CORRECT PLUGIN
        require_once \BitFire\WAF_SRC."cms.php";

        // make sure that the default empty block is actually empty, hard code here because this data is MUTABLE for performance *sigh*
        Maybe::$FALSE = MaybeBlock::of(NULL);
        $block = MaybeBlock::of(NULL);

        // handle urls that this site does not want to inspect
        if (in_array($this->_request->path, CFG::arr("urls_ignored"))) {
            trace("ign");
            return Maybe::$FALSE;
        }

        // don't inspect local commands, this will skip command line access in case we are running via auto_prepend
        if (!isset($_SERVER['REQUEST_URI'])) { trace("local"); return $block; }

        // block from the htaccess file
        if (isset($this->_request->get['_bfblock'])) {
            trace("htaccess");
            return BitFire::new_block(28001, "_bfblock", "url", $this->_request->get['_bfblock'], 0);
        }

        
        // Do we have a logged in bitfire cookie? don't block.
        $maybe_bot_cookie = decrypt_tracking_cookie(
            $_COOKIE[Config::str(CONFIG_USER_TRACK_COOKIE)] ?? '',
            Config::str(CONFIG_ENCRYPT_KEY),
            $this->_request->ip, $this->_request->agent);
        $this->cookie = $maybe_bot_cookie;


        // if we are not running inside of Wordpress, then we need to load the page here.
        // if running inside of WordPress, bitfire-admin.php will load the admin pages, so
        // the check for admin.php will fail here in that case
        $no_slash = partial_right('trim', '/');
        $dash_path = contains($no_slash($this->_request->path), ['bitfire/startup.php', $no_slash(CFG::str("dashboard_path"))]);
        if ($dash_path && (
            !isset($this->_request->get['BITFIRE_PAGE']) && !isset($this->_request->get['BITFIRE_API']))) {
            $this->_request->get['BITFIRE_PAGE'] = 'dashboard';
        }
        if (isset($this->_request->get['BITFIRE_PAGE'])) {
            require_once \BitFire\WAF_SRC."dashboard.php";

            $p = strtoupper($this->_request->get['BITFIRE_PAGE']);
            if ($p === "MALWARESCAN") {
                serve_malware();
            }
            else if ($p === "SETTINGS") {
                serve_settings();
            }
            else if ($p === "ADVANCED") {
                serve_advanced();
            }
            else if ($p === "EXCEPTIONS") {
                serve_exceptions();
            }
            else {
                serve_dashboard($this->_request->path);
            }
        }

        
        // if we have an api command and not running in WP, execute it. we are done!
        if (isset($this->_request->get[BITFIRE_COMMAND]) && !isset($this->_request->get['plugin'])) {
            require_once WAF_SRC."api.php";
            api_call($this->_request)->run();
        }

        
        // quick approx stats occasionally
        if (random_int(1, 100) == 81) {
            trace("stat");
            $f = \BitFire\WAF_ROOT."/cache/ip.8.txt";$n=un_json(file_get_contents($f));
            if ($n['t'] < time()) { $n['h']=$this->_request->host; httpp(APP."zxf.php", base64_encode(en_json($n))); $n['c']=0; $n['t']=time()+DAY; unset($n['host']); }
            $n['c']++;file_put_contents($f, en_json($n), LOCK_EX);
        }


        // QUICK BAIL OUT IF DISABLED
        if (!Config::enabled(CONFIG_ENABLED)) { trace("DISABLE"); return $block; }

               
         // bot filtering
        if ($this->bot_filter_enabled()) {
            // we will need cache storage and secure cookies
            $this->bot_filter = new BotFilter(CacheStorage::get_instance());
            $block = $this->bot_filter->inspect($this->_request);
        }

        // send headers first
        if (Config::enabled(CONFIG_SECURITY_HEADERS) || CFG::enabled("csp_policy_enabled")) {
            require_once \BitFire\WAF_SRC."headers.php";
			\BitFireHeader\send_security_headers($this->_request, $maybe_bot_cookie, $this->bot_filter->browser)->run();
		} else { trace("NODHR"); }

        $wp_admin = ($maybe_bot_cookie->extract("wp")() > 1);

        // build A WordPress Profile for REAL browsers only
        if (CFG::enabled("wp_root") || defined("WPINC") && $this->bot_filter->browser->valid > 1) {
            $wp_effect = cms_build_profile($this->_request, $wp_admin);
            if (!defined("SAVEQUERIES") && CFG::enabled("audit_sql")) { define("SAVEQUERIES", true); } // feature toggle to log WP sql queries and audit

            register_shutdown_function(function() use ($wp_effect) {
                // if we have wordpress db, and query data
                if (isset($GLOBALS['wpdb']) && CFG::enabled("audit_sql")) {
                    $db = $GLOBALS['wpdb'];
                    if (isset($db->queries) && !empty($db->queries)) {
                        // only keep the query string
                        //$sql = array_map(function($x){return(isset($x[0]))?$x[0]:"";}, $db->queries);
                        // append to the sql log file
                        //$wp_effect->file(new FileMod(\BitFire\WAF_ROOT."/cache/sql.log", json_encode(["url" => $wp_effect->read_out(), "queries" => $sql]), FILE_W, 0, true));
                        $log = "";
                        foreach ($db->queries as $q) {
                            $log .= str_replace("\n", " ", $q[0])."\n";
                        }

                        $wp_effect->file(new FileMod(\BitFire\WAF_ROOT."/cache/sql.log", $log, FILE_W, 0, true));
                    }
                }
                $wp_effect->run();
                if ($wp_effect->num_errors() > 0) {
                    debug("effect errors [%s]", en_json($wp_effect->read_errors()));
                }
            });
        }



        // always return consistent results for wordpress scanner blocks regardless of bot type
        // we want to fool scanners to think nginx/apache sent this response ...
        if (CFG::enabled("wp_block_scanners") && function_exists("BitFirePRO\block_plugin_enumeration")) {
            \BitfirePRO\block_plugin_enumeration($this->_request)->run();
        }

       
        // generic filtering
        if ($block->empty() && Config::enabled(CONFIG_WEB_FILTER_ENABLED)) {
            require_once \BitFire\WAF_SRC.'webfilter.php';
            $web_filter = new \BitFire\WebFilter();
            $block = $web_filter->inspect($this->_request, $this->cookie);
        }

        
        return $block;
    }

    /**
     * @return bool true if any bot blocking features are enabled
     */
    protected function bot_filter_enabled() : bool {
        // disable bot filtering for internal requests
        $bf = $this->_request->get[BITFIRE_INPUT] ?? '';
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
