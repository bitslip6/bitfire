<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * all functions are called via api_call() from bitfire.php and all authentication 
 * is done there before calling any of these methods.
 */

namespace BitFireSvr;

use BitFire\Config;
use BitFire\Config as CFG;
use BitFire\ScanConfig;
use Exception;
use SodiumException;
use ThreadFin\Effect as EF;
use ThreadFin\CacheItem;
use ThreadFin\CacheStorage;
use ThreadFin\FileData;
use ThreadFin\FileMod;
use ThreadFin\Effect;
use ThreadFin\Maybe;
use ThreadFin\MaybeStr;

use const BitFire\APP;
use const BitFire\BITFIRE_SYM_VER;
use const BitFire\FILE_RW;
use const BitFire\FILE_W;
use const BitFire\STATUS_EACCES;
use const BitFire\STATUS_EEXIST;
use const BitFire\STATUS_ENOENT;
use const BitFire\STATUS_OK;
use const BitFire\STATUS_FAIL;
use const BitFire\WAF_INI;
use const BitFire\WAF_ROOT;
use const ThreadFin\DAY;
use const ThreadFin\DS;

use function BitFirePlugin\find_cms_root;
use function ThreadFin\contains;
use function ThreadFin\do_for_each;
use function ThreadFin\file_recurse;
use function ThreadFin\file_replace;
use function ThreadFin\HTTP\http2;
use function ThreadFin\partial as BINDL;
use function ThreadFin\random_str;
use function ThreadFin\debug;
use function ThreadFin\en_json;
use function ThreadFin\get_hidden_file;
use function ThreadFin\make_config_loader;
use function ThreadFin\recursive_copy;
use function ThreadFin\trace;
use function ThreadFin\take_nth;
use function ThreadFin\utc_date;
use function ThreadFin\utc_time;

const ACCESS_URL = 5;
const ACCESS_CODE = 6;
const ACCESS_ADDR = 0;
const ACCESS_REFERER = 8;
const ACCESS_AGENT = 9;
const ACCESS_URL_PROTO = 2;
const ACCESS_QUERY = 10;
const ACCESS_HOST = 11;
const ACCESS_URL_METHOD = 12;
const ACCESS_URL_URI = 13;

const CONFIG_KEY_NAMES = [ "bitfire_enabled","allow_ip_block","security_headers_enabled","enforce_ssl_1year","csp_policy_enabled","csp_default","csp_policy","csp_uri","pro_key","rasp_filesystem","max_cache_age","web_filter_enabled","spam_filter_enabled","xss_block","sql_block","file_block","block_profanity","filtered_logging","allowed_methods","whitelist_enable","blacklist_enable","require_full_browser","honeypot_url","check_domain","valid_domains","valid_domains[]","ignore_bot_urls","rate_limit","rr_5m","cache_type","cookies_enabled","wordfence_emulation","report_file","block_file","debug_file","debug_header","send_errors","dashboard_usage","browser_cookie","dashboard_path","encryption_key","secret","password","cms_root","cms_content_url","cms_content_dir","debug","skip_local_bots","response_code","ip_header","dns_service","short_block_time","medium_block_time","long_block_time","cache_ini_files","root_restrict","configured" ];


// helpers
// trim off everything after $trim_char
function trim_off(string $input, string $trim_char) : string { $idx = strpos($input, $trim_char); $x = substr($input, 0, ($idx) ? $idx : strlen($input)); return $x; }

class FileHash {
    public $file_path;
    public $rel_path;
    public $size;
    public $crc_path;
    public $crc_trim;
    public $unique;
    public $crc_expected;
    public $type;
    public $name;
    public $version;
    public $ctime;
    public $ver;
    public $skip;
}

/**
 * special handling of WordPress DOCUMENT_ROOT - requested by WP team
 */
function doc_root() : string {
    static $root = "/";
    if ($root === "/") { 
        $root = $_SERVER['DOCUMENT_ROOT'];
    }
    return $root;
}

/**
 * find the cms root path.  abstracted to cms plugin helper, config file
 * fallback to doc_root()
 * @return string 
 */
function cms_root() : string {
    trace("R1");
    $root = doc_root();
    if (function_exists("\BitFirePlugin\\find_cms_root")) {
        $root = \BitFirePlugin\find_cms_root();
    }
    else if (CFG::enabled("cms_root")) {
        $root = CFG::str("cms_root");
    }
    else if (CFG::enabled("cms_root")) { // backward compatibility
        $root = CFG::str("cms_root");
    }
    if (strlen($root) < strlen(doc_root())) { 
        debug("error finding doc_root [%s]", $root);
        $root = doc_root();
    }

    return realpath($root);
}


// helper function.  determines if ini value should be quoted (return false for boolean and numbers)
function need_quote(string $data) : bool {
    return ($data === "true" || $data === "false" || ctype_digit($data)) ? false : true;
}


/** 
 * take an array of strings and convert to ini array format
 */
function array_to_ini(string $value_name, array $data) : string {
    $result = "\n";
    foreach ($data as $item) {
        if (is_numeric($item)) {
            $result .= "{$value_name}[] = $item\n";
        } else if (is_bool($item)) {
            $result .= "{$value_name}[] = " . ($item ? "true" : "false") . "\n";
        } else {
            $result .= "{$value_name}[] = '$item'\n";
        }
    }
    return "$result\n";
}

/**
 * map $filename with $fn, return effect to write updated $filename   
 * @param callable $fn 
 * @param string $filename 
 */
function update_ini_fn(callable $fn, string $filename = "", bool $append = false) : EF {
    if (empty($filename)) {
        if (defined("\BitFire\WAF_INI")) {
            $filename = \BitFire\WAF_INI;
        } else {
            $filename = make_config_loader()->run()->read_out();
        }
    }
    assert(file_exists($filename), "[$filename] does not exist.  please create it.");

    $effect = EF::new();

    // UPDATE THE FILE
    $file = FileData::new($filename)->read(false);
    $x1 = count($file->lines);
    if ($append) {
        $file->append($fn());
    } else {
        $file->map($fn);
    }

    $x2 = count($file->lines);
    $raw = join("\n", $file->lines);
    $new_config = parse_ini_string($raw, false, INI_SCANNER_TYPED);


    $is = is_array($new_config);
    if ($new_config != false && $is) {
        // set status to success if the file has a reasonable size still...
        if ($new_config != false && $x1 > 10 && $x2 >= $x1) {
            // update the file abstraction with the edit, this will allow us 
            // to update the file multiple times, and not read from the FS multiple times
            FileData::mask_file($filename, $raw);

            $ini_code = "{$filename}.php";
            $effect->status(STATUS_OK)
            // write the raw ini content
            ->file(new FileMod($filename, $raw, FILE_W))
            // write the parsed config php file
            ->file(new FileMod($ini_code, '<?'.'php $config = ' . var_export($new_config, true) . ";\n", FILE_RW, time() + 5))
            // clear the config cache entry
            ->update(new CacheItem("parse_ini", "\ThreadFin\\nop", "\ThreadFin\\nop", -DAY));
        }
    }
    if (!$is || $new_config == false) {
        $effect->exit(false, STATUS_FAIL, "an error occurred updating $filename, [$x1/$x2] (is: $is) please repair with original file");
    }

    return $effect;
}



/**
 * if $value === "!" then config line is removed
 * @param string $param ini parameter name to change
 * @param string $value the value to set the parameter to
 */
function update_ini_value(string $param, string $value, ?string $default = NULL) : Effect {
    $param = htmlspecialchars(strtolower($param));
    $value = htmlspecialchars($value);
    // normalize values
    switch($value) {
        case "off":
            $value = "false";
        case "alert":
            $value = "report";
        case "block":
        case "on":
            $value = "true";
        default:
    }

    $quote_value = (need_quote($value) && !contains($value, '"')) ? "\"$value\"" : "$value";
    $param_esc = str_replace(["[", "]"], ["\[", "\]"], $param);
    $search = (!empty($default)) ? "/\s*[\#\;]*\s*{$param_esc}\s*\=.*[\"']?{$default}[\"']?/" : "/\s*[\#\;]*\s*{$param_esc}\s*\=.*/";
    $replace = "$param = $quote_value";

    debug("update ini value [%s] [%s]", $search, $replace);

    if ($value === "!") { $replace = ""; }
    $fn = (BINDL("preg_replace", $search, $replace));

    $effect = update_ini_fn($fn);
    if ($effect->read_status() == STATUS_OK) {
        debug("updated %s -> %s", $param, $value);
    } else {
        debug("config failed to update %s -> %s", $param, $value);
    }
    return $effect;
}

/**
 * if $value === "!" then config line is removed
 * @param string $param ini parameter name to change
 * @param string $value the value to set the parameter to
 */
function add_ini_value(string $param, string $value, ?string $default = NULL, string $filename = \BitFire\WAF_INI) : Effect {
    assert(in_array($param, CONFIG_KEY_NAMES), "unknown config key $param");

    $param = htmlspecialchars(strtolower($param));
    $value = htmlspecialchars(strtolower($value));
    // normalize values
    switch($value) {
        case "off":
            $value = "false";
        case "alert":
            $value = "report";
        case "block":
        case "on":
            $value = "true";
        default:
    }

    $found = false;
    $added = false;

    $fn = function(string $line) use ($param, $value, &$found, &$added) {
        if (!$added) {
            if ($found && strlen($line) < 2) {
                $added = true;
                $line = "{$param} = \"{$value}\"\n\n";
            }
            if (contains($line, $param)) {
                $found = true;
            }
        }
        return $line;
    };

    $effect = update_ini_fn($fn);
    if ($effect->read_status() == STATUS_OK) {
        $effect->api(true, "added list $param -> $value");
    } else {
        $effect->api(false, "unable to add list $param -> $value");
    }
    return $effect;
}



/**
 * update all system config values from defaults
 */
function update_config(string $ini_src) : Effect
{
    // ugly af, but it works
    $configured = $GLOBALS["bitfire_update_config"]??false;
    $e = Effect::new();
    if ($configured) { debug("update config 2x skipped"); }
    $GLOBALS["bitfire_update_config"] = true;
    debug("update config");

    $ini_test = FileData::new($ini_src);
    // FILESYSTEM GUARDS
    if (! $ini_test->exists) { return $e->exit(false, STATUS_EEXIST, "$ini_src does not exist!"); }
    if (! $ini_test->readable || ! $ini_test->writeable) { 
        if (!@chmod($ini_src, FILE_RW)) {
            return $e->exit(false, STATUS_EACCES, "$ini_src permissions error!");
        }
    }

    
    $info = $_SERVER;
    $info["action"] = "update_config";
    $info["assert"] = @ini_get("zend.assertions");
    $info["assert.exception"] = @ini_get("assert.exception");
    $info["writeable"] = true;
    $info["cookie"] = 0;
    $info["HTTP_COOKIE"] = "**redacted**";
    $info["REQUEST_URI"] = preg_replace("/_wpnonce=[0-9a-hA-H]{8,24}/", "_wpnonce=**redacted**", $info["REQUEST_URI"]);
    $info["QUERY_STRING"] = preg_replace("/_wpnonce=[0-9a-hA-H]{8,24}/", "_wpnonce=**redacted**", $info["REQUEST_URI"]);
    $info["robot"] = false;

    $e = update_ini_value("encryption_key", random_str(32), "default");
    $e->chain(update_ini_value("secret", random_str(32)), "default");
    $e->chain(update_ini_value("browser_cookie", "_" . random_str(4)), "_bitfire");
 
    // configure wordpress root path
    // TODO: move all of WordPress settings into the wordpress-plugin/bitfire-admin.php
    $root = cms_root();
    $content_path = "/wp-content"; // default fallback
    $scheme = $_SERVER["REQUEST_SCHEME"];
    $host = trim($_SERVER["HTTP_HOST"], "/");

    $content_url = "$scheme://$host/$content_path";
    if (!empty($root)) {
        $info["cms_root_path"] = $root;
        $content_dir = $root . $content_path;
        $wp_version = get_wordpress_version($root);

        // defaults if loading outside WordPress (example WordPress is corrupted)
        if (function_exists("content_url")) {
            $content_url = \content_url();
        } else if (defined("WP_CONTENT_URL")) { $content_url = \WP_CONTENT_URL; }

        $e->chain(update_ini_value("cms_root", $root, ""));
        $e->chain(update_ini_value("cms_content_dir", $content_dir, ""));
        $e->chain(update_ini_value("cms_content_url", $content_url, ""));
        $e->chain(update_ini_value("wp_version", $wp_version, ""));
        $info['assets'] = $content_url;
        // we won't be using passwords since we will check WordPress admin credentials
        if (defined("WPINC")) {
            $e->chain(update_ini_value("password", "disabled"));
        }
    } else {
        $info["cms_root"] = "WordPress not found.";
    }

    // WPEngine fixes
    if (isset($_SERVER['IS_WPE'])) {
        // can only auto_load wordfence-waf due to hardcoding auto_prepend_file setting
        $e->chain(update_ini_value("wordfence_emulation", "true"));
        // WPEngine does not respect cache headers well, so we must bust with a parameter
        //$info["cache_param"] = random_str(4);
        //$e->chain(update_ini_value("cache_bust_parameter", $info["cache_param"]));
        // WPEngine prevents writing to php files, so we disable ini file cache here
        $e->chain(update_ini_value("cache_ini_files", "false"));
    }

    // configure caching
    if (function_exists('shmop_open')) {
        $e->chain(update_ini_value("cache_type", "shmop", "nop"));
        $e->chain(update_ini_value("cache_token", mt_rand(32768,1300000))); // new cache entry
        $info["cache_type"] = "shmop";
    } else if (function_exists('apcu')) {
        $e->chain(update_ini_value("cache_type", "apcu", "nop"));
        $info["cache_type"] = "apcu";
    } else {
        $e->chain(update_ini_value("cache_type", "opcache", "nop"));
        $info["cache_type"] = "opcache";
    }


    // X forwarded for header, WPE sends the wrong header there...
    if (isset($_SERVER['HTTP_CF_TRUE_CLIENT_IP'])) {
        $e->chain(update_ini_value("ip_header", "HTTP_CF_TRUE_CLIENT_IP", "remote_addr"));
    } else if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $e->chain(update_ini_value("ip_header", "HTTP_CF_CONNECTING_IP", "remote_addr"));
    } else if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && !isset($_SERVER['IS_WPE'])) {
        $e->chain(update_ini_value("ip_header", "HTTP_X_FORWARDED_FOR", "remote_addr"));
    } else if (isset($_SERVER['HTTP_FORWARDED'])) {
        $e->chain(update_ini_value("ip_header", "HTTP_FORWARDED", "REMOTE_ADDR"));
    } else if (isset($_SERVER['HTTP_X_REAL_IP'])) {
        $e->chain(update_ini_value("ip_header", "HTTP_X_REAL_IP", "REMOTE_ADDR"));
    } else {
        $info["forward"] = "no";
    }

    // are any cookies set?
    if (count($_COOKIE) > 1) {
        $info["cookies"] = count($_COOKIE);
        $e->chain(update_ini_value("cookies_enabled", "true", "false"));
    } else {
        $info["cookies"] = "not enabled.  none found. <= 1";
    }

    $host = $_SERVER["HTTP_HOST"];
    $domain = take_nth($host, ":", 0);
    $info["domain_value"] = $domain;
    $domain = join(".", array_slice(explode(".", $domain), -2));

    $e->chain(update_ini_value("valid_domains[]", $domain, "default"));

    // TODO: refactor with install_file
    // TODO: add to uninstall
    // TODO: update robots.txt on honeypot_url change
    $url = CFG::str("honeypot_url");
    if (!empty($url)) {
        $robot_file = doc_root() . "/robots.txt";  // robot file should only exist in server root, not CMS root
        $robot_content =  "User-agent: *\nDisallow: " . CFG::str("honeypot_url", "/supreme/contact") . "\n";
        $e->chain(alter_settings($robot_file, $robot_content));
    } else {
        $info["robot"] = "no path";
    }

    // configure dynamic exceptions
    if (CFG::enabled("dynamic_exceptions")) {
        // dynamic exceptions are enabled, but un-configured (true, not time).  Set for 5 days
        $e->chain(update_ini_value("dynamic_exceptions", time() + (DAY * 5), "true"));
    }

    require_once \BitFire\WAF_SRC . "bitfire.php";

    // use WordPress or hosted content if not WordPress
    if (function_exists("plugin_dir_url")) {
        $assets = \plugin_dir_url(dirname(__FILE__, 1)) . "public/";
    } else if (!empty($root)) {
        $assets = CFG::str("cms_content_url") . "/plugins/bitfire/public";
    } else {
        $assets = "https://bitfire.co/assets";
    }
    $info['assets'] = $assets;
    $info['version'] = BITFIRE_SYM_VER;

    debug("replacing assets (%s)", $assets);
    $z = file_replace(\BitFire\WAF_ROOT . "public/theme.bundle.css", "/url\(([a-z\.-]+)\)/", "url({$assets}$1)")->run();
    if ($z->num_errors() > 0) { debug("ERROR [%s]", en_json($z->read_errors())); }

    $alert = '{"time":"'.utc_date('r').'","tv":'.utc_time().',"exec":"0.001557 sec","block":{"code":26001,"parameter":"REQUEST_RATE","value":"41","pattern":"40","block_time":2},"request":{"headers":{"requested_with":"","fetch_mode":"","accept":"","content":"","encoding":"","dnt":"","upgrade_insecure":"","content_type":"text\/html"},"host":"unit_test","path":"\/","ip":"127.0.0.1","method":"GET","port":8080,"scheme":"http","get":[],"get_freq":[],"post":[],"post_raw":"","post_freq":[],"cookies":[],"agent":"test request rate alert","referer":null},"http_code":404},';
    $block = '{"time":"'.utc_date('r').'","tv":'.utc_time().',"exec":"0.001865 sec","block":{"code":10020,"parameter":"bitfire_block_test","value":"event.path","pattern":"static match","block_time":0},"request":{"headers":{"requested_with":"","fetch_mode":"","accept":"*\/*","content":"","encoding":"","dnt":"","upgrade_insecure":"","content_type":"text\/html"},"host":"localhost","path":"\/","ip":"127.0.0.1","method":"GET","port":80,"scheme":"http","get":{"test_block":"event.path"},"get_freq":{"test_block":{"46":1}},"post":[],"post_raw":"","post_freq":[],"cookies":[],"agent":"curl\/7.74.0"},"browser":{"os":"bot","whitelist":true,"browser":"curl\/7.74.0","ver":"x","bot":true,"valid":0},"rate":{"rr":1,"rr_time":1651697370,"ref":null,"ip_crc":3619153832,"ua_crc":3606776447,"ctr_404":0,"ctr_500":0,"valid":0,"op1":293995,"op2":2607,"oper":4,"ans":0},"http_code":403}';
    $e->file(new FileMod(get_hidden_file("alerts.json"), $alert, 0, 0, true));
    $e->file(new FileMod(get_hidden_file("blocks.json"), $block, 0, 0, true));

    $e->chain(Effect::new()->file(new FileMod(get_hidden_file("install.log"), "\n".json_encode($info, JSON_PRETTY_PRINT), FILE_W, 0, true)));
    http2("POST", APP."zxf.php", base64_encode(json_encode($info)));

    return $e;
}

/**
 * parse an array of scan config strings into a ScanConfig object
 * @param array $config 
 * @return ScanConfig 
 */
function parse_scan_config(array $config) : ScanConfig {
    $scan_config = new ScanConfig();

    foreach ($config as $line) {
        $parts = explode(":", $line);
        $key = $parts[0];
        $val = $parts[1];
        $scan_config->$key = $val;
    }

    return $scan_config;
}


/**
 * alter a file appending with $content with #hash BitFire comments
 * make a backup and remove any old backups
 * NOT PURE: uses glob(dirname($filename)) to remove backups, Effect is PURE
 * @return Effect 
 */
function alter_settings(string $filename, string $content) : EF {
    $e = EF::new();
    $content = FileData::new($filename)->raw();

    // remove old backups
    do_for_each(glob(dirname($filename)."/$filename.bitfire_bak*", GLOB_NOSORT), [$e, 'unlink']);

    // create new backup with random extension and make unreadable to prevent hackers from accessing
    $backup_filename = "$filename.bitfire_bak." . mt_rand(10000, 99999);
    $e->file(new FileMod($backup_filename, $content, FILE_W));

    // strip any previous changes
    if (strstr($content, "BEGIN BitFire") !== false) {
        $content = preg_replace('/\n?\#BEGIN BitFire.*END BitFire\n?/ism', '', $content);
    }

    // write the new modified file
    $e->file(new FileMod($filename, $content));

    return $e;
}




// add firewall startup to .user.ini
//$ini =  "$root/".ini_get("user_ini.filename");
//"\n# BEGIN BitFire\n
//auto_prepend_file = \"%s\"\n
//# END BitFire\n";
// TODO: refactor with effects and FileData
function install_file(string $file, string $format): bool
{
    $d = dirname(__FILE__, 2);
    $self = realpath($d . "/startup.php");
    debug("install file: %s - [%s]", $file, $d);

    if ((file_exists($file) && is_writeable($file)) || is_writable(dirname($file))) {
        $ini_content = (!empty($format)) ? sprintf("\n#BEGIN BitFire\n{$format}\n#END BitFire\n", $self, $self) : "";
        debug("install content: (%s) [%s]", $self, $ini_content);

        // remove any previous content, capture the current content
        $c = "";
        if (file_exists($file)) {
            $c = file_get_contents($file);
            if ($c !== false) {
                if (strstr($c, "BEGIN BitFire") !== false) {
                    $c = preg_replace('/\n?\#BEGIN BitFire.*END BitFire\n?/ism', '', $c);
                }
            }
        }

        // remove old backups
        do_for_each(glob(dirname($file).'/.*.bitfire.*'), 'unlink');
        do_for_each(glob(dirname($file).'/*.bitfire.*'), 'unlink');

        // create new backup with random extension and make unreadable to prevent hackers from accessing
        if (file_exists($file) && is_readable($file)) {
            $backup_filename = "$file.bitfire_bak." . mt_rand(10000, 99999);
            if (copy($file, $backup_filename)) {
                @chmod($backup_filename, FILE_W);
            }
        }

        $full_content = $c . $ini_content;
        if (file_put_contents($file, $full_content, LOCK_EX) == strlen($full_content)) {
            return true;
        }
    }

    return false;
}

// install always on protection (auto_prepend_file)
// TODO refactor install_file to use effects 
function install() : Effect {
    $effect = Effect::new();
    $software = $_SERVER["SERVER_SOFTWARE"];
    $apache = stripos($software, "apache") !== false;

    $root = cms_root(); // prefer CMS root over doc root
    if (empty($root)) {
        $root = doc_root();
    }
    $ini = "$root/".ini_get("user_ini.filename");
    $hta = "$root/.htaccess";
    $extra = "";
    $note = "";
    $status = false;


    // if the system has not been configured, configure it now
    // AND RETURN HERE IMMEDIATELY
    if (CFG::disabled("configured")) {
        debug("install before configured?");
        $ip = $_SERVER[CFG::str_up("ip_header", "REMOTE_ADDR")];
        $block_file = \BitFire\BLOCK_DIR . DS . $ip;
        $effect->chain(update_config(\BitFire\WAF_INI));
        $effect->chain(update_ini_value("configured", "true")); // MUST SYNC WITH UPDATE_CONFIG CALLS (WP)
        $effect->chain(Effect::new()->file(new FileMod(\BitFire\WAF_ROOT."install.log", "configured server settings. rare condition.",  FILE_W, 0, true)));
        // add allow rule for this IP, if it doesn't exist
        if (!file_exists($block_file)) {
            $effect->chain(Effect::new()->file(new FileMod($block_file, "allow", FILE_W, 0, false)));
        }
        return $effect;
    }


    // ONLY HIT HERE AFTER CONFIGURATION.
    // FOR WORDPRESS THIS IS SECOND ACTIVATION

    // force WordFence compatibility mode if running on WP ENGINE and WordFence is not installed, emulate WordFence
    // don't run this check if we are being run from the activation page (request will be null)
    if (CFG::enabled("wordfence_emulation")) {
        $cms_root = cms_root();
        $waf_load = "$cms_root/wordfence-waf.php";
        $effect->exit(false, STATUS_EEXIST, "WPEngine hosting. UNINSTALL WordFence before enabling always on.");
        // we are on wordpress, found the dir and it exists
        if (!empty($cms_root) && file_exists($cms_root)) {
            // wordfence is not installed, and the autoload file does not exist, lets inject ours
            if (!file_exists(CFG::str("cms_content_dir")."plugins/wordfence") && !file_exists($waf_load)) {
                $self = dirname(__DIR__) . "/startup.php";
                if (file_exists($self)) {
                    $effect->file(new FileMod($waf_load, "<?"."php include_once '$self'; ?>\n"))
                        ->status(STATUS_OK)
                        ->out("WPEngine hosting. WordFence WAF emulation enabled. Always on protected.");
                } else {
                    $effect->exit(false, STATUS_ENOENT, "Critical error, unable to locate BitFire startup script. Please re-install.");
                }
            }
        } else {
            $effect->exit(false, STATUS_ENOENT, "Critical error, unable to locate WordPress root directory.");
        }
    }

    // NOT WPE
    else {
        // handle Apache
        /*
        if ($apache) {
            $preamble = '
            # block directory listing
            Options All -Indexes
            # block access to plugin/theme version numbers
            <filesmatch "^(readme.txt|readme.md|readme\.html|license\.txt)">
                # Apache < 2.3
                <IfModule !mod_authz_core.c>
                    Order allow,deny
                    Deny from all
                    Satisfy All
                </ifmodule>
                # Apache ≥ 2.3
                <ifmodule mod_authz_core.c>
                    Require all denied
                </ifmodule>
            </filesmatch>';
            $status = (\BitFireSvr\install_file($hta, "$preamble\n<IfModule mod_php.c>\n  php_value auto_prepend_file \"%s\"\n</IfModule>\n<IfModule mod_php7.c>\n  php_value auto_prepend_file \"%s\"</IfModule>\n") ? true : false);
            $file = $hta;
        }
        */
        // handle NGINX and other cases
        $root_path = dirname(__DIR__) . DS;
        $content = "auto_prepend_file = \"{$root_path}startup.php\"";
        $status = (\BitFireSvr\install_file($ini, $content) ? true : false);
        $file = $ini;
        $extra = "This may take up to " . ini_get("user_ini.cache_ttl") . " seconds to take effect (cache clear time)";
        $note = ($status == "success") ?
            "BitFire was added to auto start in [$ini]. $extra" :
            "Unable to add BitFire to auto start.  check permissions on file [$file]";
    }

    $effect->chain(Effect::new()->file(new FileMod(\BitFire\WAF_ROOT."install.log", join(", ", debug(null))."\n$note\n", FILE_W, 0, true)));
    return $effect->exit(false)->api($status, $note)->status((($status) ? STATUS_OK : STATUS_FAIL));
}


// uninstall always on protection (auto_prepend_file)
// TODO: refactor to api response
function uninstall() : \ThreadFin\Effect {
    $apache = stripos($_SERVER['SERVER_SOFTWARE'], "apache") !== false;
    $root = doc_root(); // SERVER DOCUMENT ROOT, NOT CMS ROOT!
    $ini = "$root/".ini_get("user_ini.filename");
    $hta = "$root/.htaccess";
    $extra = "";
    $effect = \ThreadFin\Effect::new();
    $status = "success";

    // attempt to uninstall emulated wordfence if found
    $is_wpe = isset($_SERVER['IS_WPE']);
    if (Config::enabled("wordfence_emulation") || $is_wpe) {
        $cms_root = cms_root();
        $waf_load = "$cms_root/wordfence-waf.php";
        // auto load file exists
        if (file_exists($waf_load)) {
            $c = file_get_contents($waf_load);
            // only remove it if this is a bitfire emulation
            if (stristr($c, "bitfire")) {
                $effect->unlink($waf_load);
                $method = "wordfence";
            }
        }
    }
    else {
        $file = $ini;
        $extra = "This may take up to " . ini_get("user_ini.cache_ttl") . " seconds to take effect (cache clear time)";
        $method = "user.ini";

        $status = ((\BitFireSvr\install_file($file, "")) ? "success" : "error");
        // install a lock file to prevent auto_prepend from being uninstalled for ?5 min
        $effect->file(new FileMod(\BitFire\WAF_ROOT . "uninstall_lock", "locked", 0, time() + intval(ini_get("user_ini.cache_ttl"))));
    }
    $path = realpath(\BitFire\WAF_ROOT."startup.php"); // duplicated from install_file. TODO: make this a function

    // remove all stored cache data
    CacheStorage::get_instance()->delete();

    // remove all backup config files
    do_for_each(glob("$root/.*bitfire_bak*", GLOB_NOSORT), [$effect, 'unlink']);
    do_for_each(glob("$root/*bitfire_bak*", GLOB_NOSORT), [$effect, 'unlink']);

    $note = ($status == "success") ?
        "BitFire was removed from auto start. $extra" :
        "Unable to remove BitFire from auto start.  check permissions on file [$file]";
    $effect->status(($status == "success") ? STATUS_OK : STATUS_FAIL);
    $effect->out(json_encode(array('status' => $status, 'note' => $note, 'method' => $method, 'path' => $path)));
    return $effect;
}




/**
 * convert string version number to unsigned 32bit int
 */
function text_to_int(string $ver)
{
    $result = 0;
    $ctr = 1;
    $parts = array_reverse(explode(".", $ver));
    foreach ($parts as $part) {
        $p2 = intval($part) * ($ctr);
        $result += $p2;
        $ctr *= 100;
    }
    return $result;
}

/**
 * recursively reduce list by fn, result is an array of output of fn for each list item
 * fn should output an array list for each list item, the result will be all items appended
 */
function append_reduce(callable $fn, array $list): array
{
    return array_reduce($list, function ($carry, $x) use ($fn) {
        return array_reduce($fn($x), function ($carry, $x) {
            $carry[] = $x;
            return $carry;
        }, $carry);
    }, array());
}

function hash_file3(string $path, callable $type_fn, callable $ver_fn, string $root_dir = ""): ?FileHash {
    $name = "root";
    /*
    if (stristr($path, "wp-admin") !== false) {
        xdebug_break();
    }
    */

    if (preg_match("/^.*\\".DS."wp-content\\".DS."(?:plugins|themes)\\".DS."([^\\".DS."]*)/", $path, $matches)) {
        $root_dir = $matches[0];

        $name = $matches[1]; 
    } else if (preg_match("/^.*(\\".DS."wp-(?:includes|admin))\\".DS.".*/", $path, $matches)) {
        if (empty($root_dir)) { $root_dir = cms_root(); }
        $root_dir .= $matches[1];
    }
    $hash = hash_file2($path, $root_dir, $name, $type_fn);
    if (!empty($hash)) {
        $hash->ver = $ver_fn($path);
    }
    return $hash;
}

// run the hash functions on a file
// TODO: move unique to data enrichment, not needed on server call
function hash_file2(string $path, string $root_dir, string $name, callable $type_fn): ?FileHash
{
    $root_dir = rtrim($root_dir, '/');
    // GUARDS
    $realpath = realpath($path);
    $extension = pathinfo($realpath, PATHINFO_EXTENSION);
    if (!$realpath) { return null; }
    if (is_dir($realpath)) { return null; }
    if (!is_readable($realpath)) { return null; }

    $input = join('', FileData::new($realpath)->read()->map('trim')->lines);
    // if the extension is not php, check for php code anyway...
    if ($extension != "php") { 
        if (strpos($input, "<?php") === false) { return null; }
    }

    


    $hash = new FileHash();
    $hash->file_path = $realpath;
    $hash->rel_path = str_replace("//", "/", str_replace($root_dir, "", $realpath));

    if ($hash->file_path == $hash->rel_path) {
        xdebug_break();

    }
    $hash->crc_trim = crc32($input);
    $hash->type = $type_fn($realpath);
    $hash->name = $name;
    $hash->size = filesize($realpath);
    $hash->unique = strtolower(random_str(10));
    $hash->ctime = filectime($realpath);

    // we don't even need to scan it if we are missing important functions
    /*
    $req_fn = '/(?:header|\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*|mail|fwrite|file_put_contents|create_function|call_user_func|call_user_func_array|uudecode|hebrev|hex2bin|str_rot13|eval|proc_open|pcntl_exec|exec|shell_exec|system|passthru%s*)\s*\(?/mi';
    if (!preg_match($req_fn, $input)) {//} && !preg_match("/(include|require)(_once)?[^=]+?;/", $input)) {
        $hash->skip = true;
    }
    */

    // HACKS AND FIXES
    if ($hash->type != "wp_plugin") {
        if (stripos($realpath, "/wp-includes/") !== false) { $hash->rel_path = "/wp-includes".$hash->rel_path; }
        else if (stripos($realpath, "/wp-admin/") !== false) { $hash->rel_path = "/wp-admin".$hash->rel_path; }
    }

    $hash->crc_path = crc32($hash->rel_path);
    return $hash;
}




// run the hash functions on a file
function hash_file(string $filename, string $root_dir, string $plugin_id, string $plugin_name): ?array
{
    if (is_dir($filename)) {
        return null;
    }
    if (!is_readable($filename)) {
        return null;
    }
    $root_dir = rtrim($root_dir, '/');
    $filename = str_replace("//", "/", $filename);
    $i = pathinfo($filename);
    $input = @file($filename);
    if (!isset($i['extension']) || $i['extension'] !== "php" || empty($input)) {
        return null;
    }

    $shortname = str_replace($root_dir, "", $filename);
    $shortname = str_replace("//", "/", $shortname);
    if (strpos($filename, "/plugins/") !== false) {
        $shortname = '/'.str_replace("$root_dir", "", $filename);
    } else if (strpos($filename, "/themes/") !== false) {
        $shortname = '/'.str_replace("$root_dir", "", $filename);
    }


    $result = array();
    $result['crc_trim'] = crc32(join('', array_map('trim', $input)));
    $result['crc_path'] = crc32($shortname);
    $result['path'] = substr($shortname, 0, 255);
    $result['name'] = $plugin_name;
    $result['plugin_id'] = $plugin_id;
    $result['size'] = filesize($filename);


    /*
    if (function_exists('BitFirePRO\find_malware')) {
        $result['malware'] = \BitFirePRO\find_malware($input);
    }
    */

    return $result;
}




function hash_dir(string $dir): array
{
    return file_recurse($dir, function ($file) use ($dir): ?array {

        if (is_link($file)) {
            return NULL;
        }
        $wp_base = basename(CFG::str("cms_content_dir"));
        if (strpos($file, $wp_base) !== false) {
            if (preg_match('#$wp_base/(plugins|themes)/([^\/]+)#', $file, $matches)) {
                $type = strpos($file, '/plugins/') !== false ? 1 : 2;
                return hash_file($file, $dir, $type, $matches[2]);
            }
            return NULL;
        }

        return hash_file($file, $dir, 0, "");
    }, "/.*\.php$/");
}


/**
 * get the wordpress version from a word press root directory
 */
function get_wordpress_version(string $root_dir): string
{
    $full_path = "$root_dir/wp-includes/version.php";
    $wp_version = "1.0";
    if (file_exists($full_path)) {
        include $full_path;
    }
    return trim_off($wp_version, "-");
}



/**
 * return an array of ('filename', size, crc32(path), crc32(space_trim_content))
 */
function get_wordpress_hashes(string $root_dir): ?array
{

    $version = get_wordpress_version($root_dir);
    if (version_compare($version, "4.1") < 0) {
        return array("ver" => $version, "int" => "too low", "files" => array());
    }

    $r = hash_dir($root_dir);

    return array("ver" => $version, "root" => $root_dir, "int" => text_to_int($version), "files" => $r); //array_splice($r, 0, 1000));
}


/**
 * returns output of $fn if $fn output evaluates to true
 */
function if_it(callable $fn, $item)
{
    $r = $fn($item);
    return ($r) ? $r : NULL;
}


function get_server_config_file_list(): array
{
    return [
        "/etc/nginx/*.conf",
        "/usr/local/etc/nginx/*.conf",
        "/usr/local/nginx/*.conf",
        "/opt/homebrew/etc/nginx/*.conf",
        "/etc/httpd/*.conf",
        "/etc/httpd/conf/*.conf",
        "/etc/apache/*.conf",
        "/etc/apache2/*.conf",
        "/usr/local/apache2/*.conf",
        "/usr/local/etc/apache2/*.conf",
        "/usr/local/etc/httpd/*.conf"
    ];
}




/**
 * process an access line into request object
 */
function process_access_line_orig(string $line): ?\BitFire\Request
{
    $parts = str_getcsv($line, " ", '"');

    if ($parts[ACCESS_CODE] > 399) {
        return NULL;
    }

    $url_parts = explode(" ", $parts[ACCESS_URL]);
    $url = parse_url($url_parts[ACCESS_URL_URI]);

    $server = array(
        "REMOTE_ADDR" => $parts[ACCESS_ADDR],
        "REQUEST_METHOD" => $url_parts[ACCESS_URL_METHOD],
        "QUERY_STRING" => $url['query'],
        "HTTP_HOST" => $url['host'],
        "HTTP_REFERER" => $parts[ACCESS_REFERER],
        "HTTP_USER_AGENT" => $parts[ACCESS_AGENT],
        "HTTP_REQUEST_URI" => $url_parts[ACCESS_URL_URI]
    );

    parse_str($url['query'], $get);
    $r = \BitFire\process_request2($get, array(), $server, array());
    return $r;
}



/**
 * test for valid http return code
 */
function have_valid_http_code(array $access_line): bool
{
    assert(isset($access_line[ACCESS_CODE]));

    return $access_line[ACCESS_CODE] < 399;
}

/**
 * take access line and break up ACCESS_URL "GET host://path?query HTTP/1.1"
 * add method and url to input data and return result
 */
function split_request_url(array $access_line): array
{
    assert(isset($access_line[ACCESS_URL]));

    // split the initial line to get METHOD and URI (ignore protocol)
    $url_parts = \explode(" ", $access_line[ACCESS_URL]);
    $access_line[ACCESS_URL_METHOD] = $url_parts[0];
    $access_line[ACCESS_URL_URI] = $url_parts[1];

    // split host and query string from the access line URI
    $url = \parse_url($access_line[ACCESS_URL_URI]);
    $access_line[ACCESS_HOST] = $url['host'] ?? 'localhost';
    $access_line[ACCESS_QUERY] = $url['query'] ?? '';

    return $access_line;
}

/**
 * map an http access line into a PHP $_SERVER structured array
 */
function map_access_line_to_server_array(array $access_line): array
{
    assert(count($access_line) >= ACCESS_URL_URI);

    return array(
        "REMOTE_ADDR" => $access_line[ACCESS_ADDR],
        "REQUEST_METHOD" => $access_line[ACCESS_URL_METHOD],
        "QUERY_STRING" => $access_line[ACCESS_QUERY],
        "HTTP_HOST" => $access_line[ACCESS_HOST],
        "HTTP_REFERER" => $access_line[ACCESS_REFERER],
        "HTTP_USER_AGENT" => $access_line[ACCESS_AGENT],
        "REQUEST_URI" => $access_line[ACCESS_URL_URI],
        "QUERY_STRING" => $access_line[ACCESS_QUERY]
    );
}

/**
 * map an nginx access line to a request object
 */
function process_access_line(string $line): ?\BitFire\Request
{
    // parse quoted strings in access log line
    $data = Maybe::of(\str_getcsv($line, " ", '"'));

    $data->keep_if('\BitFireSvr\have_valid_http_code');
    $data->then('\BitFireSvr\split_request_url');
    $data->then('\BitFireSvr\map_access_line_to_server_array');
    $data->then(function (array $server) {
        parse_str($server['QUERY_STRING'] ?? '', $get); // parse get params into array of parameters
        return \BitFire\process_request2($get, array(), $server, array());
    });


    return $data->empty() ? NULL : $data->value();
}

/**
 * authenticate a BitFire tech support user
 * @param string $signed_message 
 * @return MaybeStr 
 * @throws SodiumException 
 */
function authenticate_tech(string $signed_message) : MaybeStr {
    try {
        $tech_public_key = hex2bin(CFG::str("tech_public_key")); 
        return MaybeStr::of(sodium_crypto_sign_open($signed_message, $tech_public_key));
    } catch (Exception $e) {
        return MaybeStr::of(false); 
    } 
}



function is_browser_request(?\BitFire\Request $request) : bool
{
    $path = $request->path ?? '/';
    $info = pathinfo($path);
    return in_array($info['extension'] ?? '', array("css", "js", "jpeg", "jpeg", "png", "gif"));
}



/**
 * Create an effect to activate the firewall. unit-testable
 * This will set the config file to enable firewall to run
 * install auto_prepend_file into .htaccess or .user.ini (apache/nginx)
 * 
 * This is called on plugin activation AND upgrade...
 * @return Effect the effect to update ini and install auto_prepend
 */
function bf_activation_effect() : Effect {

    // ensure that cache objects directory exists!
    if (file_exists(WAF_ROOT . "cache") && !file_exists(WAF_ROOT . "cache" . DIRECTORY_SEPARATOR . "objects")) {
        mkdir(WAF_ROOT . "cache" . DIRECTORY_SEPARATOR . "objects", 0775, true);
    }

    $effect = \BitFireSvr\update_ini_value("bitfire_enabled", "true");
    debug("configured: [%d]", CFG::enabled("configured"));

    $effect->chain(update_config(\BitFire\WAF_INI));
    // make sure we run auto configure and install auto start
    // TODO: this logic is WP specific.  move to WP plugin
    /*
    if (CFG::str("auto_start") != "on" && CFG::enabled("configured")) {
        debug("is configured or auto_start is off, installing");
        $effect->chain(\BitFireSvr\install());
    }
    */
    // update configured after check for install.  allows install on deactivate - activate
    $effect->chain(update_ini_value("configured", "true")); // MUST SYNC WITH UPDATE_CONFIG CALLS (WP)
    // in case of upgrade, run the config updater to add new config parameters
    //$effect->chain(\BitFireSvr\upgrade_config());


    // read the result of the auto prepend install and update the install.log
    if ($effect->read_status() == STATUS_OK) {
        $content = "\nBitFire " . BITFIRE_SYM_VER . " Activated at: " . 
            date(DATE_RFC2822) . "\n" . $effect->read_out();
    } else {
        $errstr = function_exists("posix_strerror") ? posix_strerror($effect->read_status()) : " (can't convert errno: to string) ";
        $content = "\nBitFire " . BITFIRE_SYM_VER . " Activation FAILED at: " . 
            date(DATE_RFC2822) . "\nError Code: " . $effect->read_status() . " : " .
            "$errstr\n" . $effect->read_out() . "\n";
    }
    $effect->file(new FileMod(\BitFire\WAF_ROOT."install.log", $content, 0, 0, true));

    return $effect;
}

/**
 * Create an effect to deactivate the firewall. unit-testable
 * turn off the global firewall enable flag and uninstall the auto_prepend_file 
 * @return Effect the effect to update ini and un-install auto_prepend
 */
function bf_deactivation_effect() : Effect {
    // turn off the global run flag
    $effect = \BitFireSvr\update_ini_value("bitfire_enabled", "false");
    // uninstall auto_prepend_file from .htaccess and/or user.ini
    $effect->chain(\BitFireSvr\uninstall());

    if ($effect->read_status() == STATUS_OK) {
        $content = "\nWordPress plugin De-activated at: " . 
            date(DATE_RFC2822) . "\n" . $effect->read_out();
    } else {
        $errstr = function_exists("posix_strerror") ? posix_strerror($effect->read_status()) : " (can't convert errno to string) ";
        $content = "\nWordPress plugin deactivation FAILED at: " . 
            date(DATE_RFC2822) . "\nError Code: " . $effect->read_status() . " : " .
            "$errstr\n" . $effect->read_out() . "\n";
    }
    $effect->file(new FileMod(\BitFire\WAF_ROOT."install.log", $content, 0, 0, true));

    // pack up and go home
    $info = [
        "action" => "deactivate",
        "errors" => FileData::new(WAF_ROOT . "cache/errors.json")->raw(),
        "install" => FileData::new(WAF_ROOT . "install.log")->raw(),
        "ver" => BITFIRE_SYM_VER,
        "host" => $_SERVER["HTTP_HOST"],
        "hashes" => FileData::new(get_hidden_file("hashes.json"))->raw(),
        "config" => FileData::new(get_hidden_file("config.ini"))->raw(),
        "exceptions" => FileData::new(get_hidden_file("exceptions"))->raw(),
    ];
    http2("POST", APP."zxf.php", substr(base64_encode(json_encode($info)), 0, 1024*1024*8));


    return $effect;
}


/**
 * TODO: refactor to move the secret dir.
 * TODO: HIDDEN FIX
 * @return Effect
 **/
function standalone_to_wordpress() : void {
    // load the old configuration if we have one
    // TODO: move to a backup function
    $old_config_dir = dirname(WAF_INI, 1);

    if (defined("WP_CONTENT_DIR")) {
        $plugin_root_dir = WP_CONTENT_DIR."/plugins/";
    } else {
        $plugin_root_dir = dirname(__DIR__, 1);
    }
    recursive_copy($old_config_dir, $plugin_root_dir);
}

namespace BitFireChars;

use ThreadFin\Effect;

use const BitFire\STATUS_EEXIST;

use function ThreadFin\contains;
use function ThreadFin\file_recurse;
use function ThreadFin\icontains;

const LOWER = 0.04;
const UPPER = 0.96;
const RISKY_FN = ['base64_decode', 'uudecode', 'hebrev', 'hex2bin', 'str_rot13', 'eval', 'proc_open', 'pcntl_exec', 'exec', 'shell_exec', 'call_user_func', 'call_user_func_array', 'system', 'passthru', 'shell_exec', 'move_uploaded_file', 'stream_wrapper_'];


/**
 * create the initial frequency array
 * @return array 
 */
function init_frequency() : array {
    for ($i = 0; $i < 128; $i++) {
        $freq[$i] = [];
    }
    return $freq;
}

/**
 * take the total frequency counts and turn it into final count
 * @param array $frequency 
 * @return array 
 */
function finalize_frequency(array $frequency) : array {
    $final = [];
    foreach ($frequency as $index => $list) {
        $num = count($list);
        // skip characters that don't appear enough
        if ($num < 10) { continue; }

        // find the lower and upper boundaries
        sort($list);
        $lower = round((LOWER * $num), 0);
        $upper = round((UPPER * $num), 0);
        $l_min = max(0, $lower - 1);
        $l_up = max(0, $upper - 1);
        $l = (floor($lower) == $lower) ? $list[$l_min] : ($list[$l_min] + $list[$lower+1])/2;
        $u = (floor($upper) == $upper) ? $list[$l_up] : ($list[$l_up] + $list[$upper+1])/2;
        $final[$index] = ["lower" => $l, "upper" => $u];
    }
    return $final;
}

/**
 * calculate character frequency for a single file if it is risky
 * @param string $path - assumes $path exists
 * @param bool $final
 * @return null|array 
 */
function update_freq(string $path) : ?array {
    static $file_map = [];
    assert(file_exists($path), "can't update character frequency if the file doesn't exist: $path");

    $content = file_get_contents($path);
    // skip the file if it doesn't contain any of the risky functions, or dynamic functions
    if (! icontains($content, RISKY_FN)) {
        if (!preg_match("/\$[a-zA-Z0-9_]+\s*\(/", $content)) {
            return null;
        }
    }

    // ignore paths we have looked at before
    $file_name = dirname($path) . "/" . basename($path);
    if (isset($file_map[$file_name])) { return null; }

    $file_map[$file_name] = true;

    return find_freq($content, false);
}


/**
 * calculate character frequency on single file
 * @param string $content - the file content to inspect
 * @param bool $final - flag to return the final frequency
 * @return null|array 
 */
function find_freq(string $content, bool $final = false) : ?array {
    static $global_frequency = null;
    if ($global_frequency === null) {
        $global_frequency = init_frequency();
    }
    if ($final) { return $global_frequency; }

    $frequency = count_chars($content, 1);
    $semi = $frequency[59]??0;
    $lines = $frequency[10]??1;
    //$opens = $frequency[40]??0;
    //$concat = $frequency[46]??0;
    // skip short files
    if ($semi < 10) {
        return null;
    }

    foreach ($frequency as $index => $count) {
        // skip bells and other control characters
        if ($index < 5) { continue; }
        // count ascii characters, and their frequency vs lines
        if ($index <= 127) {
            $global_frequency[$index][] = $count;
            $global_frequency[$index+128][] = round(($count/$lines), 4);
        }
    }

    return null;
}

/**
 * analyze a directory recursively and create a frequency table
 * @param string $root_dir 
 * @return null|array 
 */
function create_frequency_table(string $root_dir) : ?array {
    if (!file_exists($root_dir)) {
        return null;
    }
    file_recurse($root_dir, 'BitFireChars\update_freq', "/\.php$/", [], 50000);
    $final_frequency = finalize_frequency(find_freq("", true));
    return $final_frequency;
}
