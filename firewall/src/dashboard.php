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

namespace BitFire;

use BitFire\Config as CFG;
use RuntimeException;
use Exception;
use ThreadFin\FileData;
use ThreadFin\Effect;
use ThreadFinDB\Credentials;
use ThreadFinDB\DB;

use const ThreadFin\DAY;
use const ThreadFin\ENCODE_RAW;

use function BitFirePlugin\get_cms_version;
use function BitFirePlugin\malware_scan_dirs;
use function BitFireSvr\array_to_ini;
use function BitFireSvr\cms_root;
use function BitFireSvr\parse_scan_config;
use function BitFireSvr\update_ini_fn;
use function BitFireSvr\update_ini_value;
use function ThreadFin\machine_date;
use function BitFireWP\wp_parse_credentials;
use function BitFireWP\wp_parse_define;
use function ThreadFin\_t;
use function ThreadFin\array_add_value;
use function ThreadFin\b2s;
use function ThreadFin\ip_to_country;
use function ThreadFin\compact_array;
use function ThreadFin\compose;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\en_json;
use function ThreadFin\ends_with;
use function ThreadFin\find_fn;
use function ThreadFin\map_mapvalue;
use function ThreadFin\partial_right as BINDR;
use function ThreadFin\partial as BINDL;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\find_const_arr;
use function ThreadFin\get_hidden_file;
use function ThreadFin\HTTP\http2;
use function ThreadFin\icontains;
use function ThreadFin\output_profile;
use function ThreadFin\render_file;
use function ThreadFin\un_json;

require_once \BitFire\WAF_SRC . "api.php";
require_once \BitFire\WAF_SRC . "const.php";
require_once \BitFire\WAF_SRC . "cms.php";
require_once \BitFire\WAF_SRC . "server.php";
require_once \BitFire\WAF_SRC . "botfilter.php";
require_once \BitFire\WAF_SRC . "renderer.php";

const PAGE_SZ = 30;
const PORN_WORD = "sex|teen|adult|chat|porn|naked|pussy|hardcore|anal|cock|xxx|webcam|amateur|girls";

if (file_exists(\BitFire\WAF_ROOT . "includes.php")) {
	require_once \BitFire\WAF_ROOT . "includes.php";
}


/**
 * truncate the file to max num_lines, returns true if result file is <= $num_lines long
 * SNAP, file_put_contents back
 */
function remove_lines(FileData $file, int $num_lines) : FileData {
    debug("File lines: %d num_lines: %d", $file->num_lines, $num_lines);

    if ($file->num_lines > $num_lines) { 
        $file->lines = array_slice($file->lines, -$num_lines);
        $content = join("", $file->lines);
        
        file_put_contents($file->filename, $content, LOCK_EX);
    }
    return $file;
}

function get_file_count($path) : int {
    $files = scandir($path);
    if (!$files) { return 0; }

    $size = 0;
    $ignore = array('.','..');
    foreach($files as $t) {
        if(in_array($t, $ignore)) continue;
        if (is_dir(rtrim($path, '/') . '/' . $t)) {
            $size += get_file_count(rtrim($path, '/') . '/' . $t);
        } else {
            if (strpos($t, ".php") > 0) { $size++; }
        }   
    }
    return $size;
}


function list_text_inputs(string $config_name) :string {

    $assets = (defined("WPINC")) ? CFG::str("cms_content_url")."/plugins/bitfire/public/" : "https://bitfire.co/assets/"; // DUP
    $list = CFG::arr($config_name);
    $idx = 0;
    //$result = \BitFirePlugin\add_script_inline("bitfire-list-$config_name", 'window.list_'.$config_name.' = '.json_encode($list).';');
    $result = '<script>window.list_'.$config_name.' = '.json_encode($list).';</script>';
    foreach ($list as $element) {
        $id = $config_name.'-'.$idx;
        $result .= '
        <div style="margin-bottom:5px;" id="item_'.$id.'">
        <input type="text" autocomplete="off" disabled id="list_'.$id.'" class="form-control txtin" style="width:80%;float:left;margin-right:10px" value="'.htmlspecialchars($element).'">
        <div class="btn btn-danger" style="cursor:pointer;padding-top:10px;padding-left:10px;" title="remove list element" onclick="remove_list(\''.$config_name.'\', \''.htmlspecialchars($element).'\', '.$idx.")\"><span class=\"fe fe-trash-2 orange\"></span></div></div>"; 
        $idx++;
    }
    $result .= '
    <div style="margin-bottom:5px;">
    <input type="text" id="new_'.$config_name.'" autocomplete="off" class="form-control txtin" style="width:80%;float:left;margin-right:10px" value="" placeholder="new entry">
    <div class="btn btn-success" style="cursor:pointer;padding-top:10px;padding-left:10px;" title="add new list element" onclick="add_list(\''.$config_name.'\')"><span class="fe fe-plus"></span></div>'; 
    return $result;
}


function country_enricher(array $country_info): callable {
    return function (?array $input) use ($country_info): ?array {
        if (!empty($input)) {
            $code = ip_to_country($input['request']['ip'] ?? $input['ip'] ?? '');
            $input['country'] = $country_info[$code];
        }
        return $input;
    };
}

function country_resolver(string $ip, array $country_info): string {
    if (!empty($ip)) {
        $code = ip_to_country($ip);
        if (isset($country_info[$code])) {
            return $country_info[$code];
        }
    }
    return "-";
}

function add_country($data)
{
    if (!is_array($data) || count($data) < 1) {
        return $data;
    }
    $map = un_json(file_get_contents(\BitFire\WAF_ROOT . "cache/country.json"));
    $result = array();
    foreach ($data as $report) {
        $code = ip_to_country($report['ip'] ?? '');
        $report['country'] = $map[$code];
        $result[] = $report;
    }
    return $result;
}

function is_dis()
{
    static $result = NULL;
    if ($result === NULL) {
        $result = is_writeable(\BitFire\WAF_INI) && is_writeable(\BitFire\WAF_ROOT . "config.ini.php");
    }
    return ($result) ? " " : "disabled ";
}


function url_to_path($url) {
    $idx = strpos($url, "/");
    return substr($url, $idx);
}

function get_asset_dir() {
    $assets = "https://bitfire.co/assets/";
    if (defined("WPINC")) {
        $assets = CFG::str("cms_content_url")."/plugins/bitfire/public/";
    } else if (contains($_SERVER['REQUEST_URI'], "startup.php")) {
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $assets = dirname($path) . "/public/";
    }
    return $assets;
}

/**
 * render an html template
 * @param string $view_filename full path to the html file
 * @param string $page_name menu name entry
 * @param array $variables variables to pass to template
 * @return Effect an effect that can render the view
 */
function render_view(string $view_filename, string $page_name, array $variables = []) : Effect {
    $custom_css_file = WAF_ROOT."/views/custom.css";
    assert(file_exists($custom_css_file), "missing core file $custom_css_file");
    assert(is_readable($custom_css_file), "core file $custom_css_file is not readable");
    
    $page = (defined("WPINC")) ? "BITFIRE_WP_PAGE" : "BITFIRE_PAGE";
    $url_fn = find_fn("dashboard_url");

    $is_free = (strlen(Config::str('pro_key')) < 20);


    $assets = "https://bitfire.co/assets/";
    if (defined("WPINC")) {
        $assets = CFG::str("cms_content_url")."/plugins/bitfire/public/";
    }
    if (isset($variables['assets'])) { $assets = $variables['assets']; ;}




    $content = CFG::str("cms_content_url");
    $variables['license'] = CFG::str('pro_key', "unlicensed");
    $variables['font_path'] = (defined("WPINC") && !empty($content)) ? "$content/plugins/bitfire/public" : "https://bitfire.co/dash/fonts/cerebrisans";
    $variables['is_wordpress'] = (!empty(\BitFireSvr\cms_root())) ? "true" : "false";
    $variables['api_code'] = make_code(CFG::str("secret"));
    $variables['api'] = BITFIRE_COMMAND;
    $variables['self'] = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);
    $variables['page_tz'] = date('Z');

    $variables['password_reset'] = (CFG::str('password') === 'default') || (CFG::str('password') === 'bitfire!');
    $variables['is_free'] = b2s($is_free);
    $variables['llang'] = "en-US";
    $variables['public'] = \ThreadFin\get_public();
    $variables['assets'] = $assets;
    $variables['version'] = BITFIRE_VER;
    $variables['sym_version'] = BITFIRE_SYM_VER;
    $variables['showfree_class'] = $is_free ? "" : "hidden";
    $variables['hidefree_class'] = $is_free ? "hidden" : "";
    $variables['release'] = (($is_free)  ? "FREE" : "PRO") . " Release " . BITFIRE_SYM_VER;
    $variables['underscore_path'] = (defined("WPINC")) ? "/wp-includes/js/underscore.min.js" : "https://bitfire.co/assets/js/unders"."core.min.js";
    $variables['show_wp_class'] = (defined("WPINC")) ? "" : "hidden";
    //$variables['jquery'] = (defined("WPINC")) ? "" : "https://bitfire.co/assets/js/jqu"."ery/jqu"."ery.js";
    $variables['need_reset'] = b2s((CFG::str('password') === 'bitfire!'));
    $variables['gtag'] = '';
    $header_variables = array_merge($variables, [
        "dashboard_url" => $url_fn("bitfire", "DASHBOARD"),
        "malware_url" => $url_fn("bitfire_malware", "MALWARE"),
        "settings_url" => $url_fn("bitfire_settings", "SETTINGS"),
        "exceptions_url" => $url_fn("bitfire_exceptions", "EXCEPTIONS"),
        "database_url" => $url_fn("bitfire_database", "DATABASE"),
        "advanced_url" => $url_fn("bitfire_advanced", "ADVANCED"),
        "botlist_url" => $url_fn("bitfire_advanced", "BOTLIST"),
    ], $variables);
    // inject header and style
    if (!isset($header_variables["plugin_alerts"])) {
        $header_variables["plugin_alerts"] = "";
    }
    $variables['header'] = \ThreadFin\render_file(WAF_ROOT . "views/header.html", $header_variables);
    $variables['custom_css'] = str_replace("{{public}}", $variables["public"], file_get_contents($custom_css_file));

    // handle old "include" style views and new templates
    $effect = Effect::new();



    if (ends_with($view_filename, "html")) {
        if (CFG::enabled("dashboard-usage")) {
            $variables['gtag']  = file_get_contents(\BitFire\WAF_ROOT."views/gtag.html");
        }
        $effect->out(\ThreadFin\render_file($view_filename, $variables));
    }

    // if we don't have wordpress, then wrap the content in our skin
    if (!defined("WPINC")) {
        // save current content
        $out = $effect->read_out();
        $variables["maincontent"] = $out;
        $variables["has_scanner"] = (empty(CFG::str("CMS_ROOT"))) ? "hidden" : "";
        // render the skin with old content
        $effect->out(render_file(\BitFire\WAF_ROOT."views/skin.html", $variables), ENCODE_RAW, true);
    }

    return $effect;
}



 
function dump_dirs() : array {
    // todo root maybe null
    $root = \BitFireSvr\cms_root();
    $root_ver = get_cms_version($root);
    if ($root == NULL) { return NULL; }

    $all_paths = malware_scan_dirs($root);
    $dir_versions = array_add_value($all_paths, 'BitFirePlugin\version_from_path');

    // add these for wordpress, extract into malware_scan_dirs...
    if (file_exists("{$root}/wp-includes")) {
        $dir_versions["{$root}/wp-includes"] = $root_ver;
        $dir_versions["{$root}/wp-admin"] = $root_ver;
    }
    return $dir_versions;
}


/**
 * @return ?array ("count" => $num_files, "root" => $root, "files" => $enriched_files);
 */
function dump_hashes() : ?array {
    require_once WAF_SRC . "diff.php";
    $root = \BitFireSvr\cms_root();
    $ver = get_cms_version($root);
    
    if ($root == NULL && empty(CFG::str("cms_content_dir"))) { return NULL; }

    $all_roots = glob("$root/*.php");
    $list1 = array_filter($all_roots, function($x) { return !ends_with($x, "wp-config.php"); });
    $mu_plugins = glob(CFG::str("cms_content_dir")."/mu-plugins/*.php");
    if (!$mu_plugins) { $mu_plugins = []; }
    /*
    $all_plugins_root = glob(CFG::str("cms_content_dir")."/plugins/*.php");
    $all_themes_root = glob(CFG::str("cms_content_dir")."/themes/*.php");
    */

    $hash_fn = BINDR('\BitFireSvr\hash_file2', $root, "", find_fn('file_type'));
    $hashes = array_map($hash_fn, array_merge($list1, $mu_plugins));
    $h2 = en_json(["ver" => $ver, "files" => array_filter($hashes)]);
    $encoded = base64_encode($h2);

    // send these hashes to the server for checking against the database
    $response = http2("POST", APP."hash_compare.php", $encoded, array("Content-Type" => "application/json"));

    $num_files = 0;
    // decode the result of the server test
    $decoded = un_json($response->content);

    if (!empty($decoded)) {
        $allowed = FileData::new(get_hidden_file("hashes.json"))->read()->un_json()->lines;
        $allow_map = [];
        foreach ($allowed as $file) { $allow_map[$file["file"]] = $file["path"]; }


        $num_files = count($hashes);
        $ver = get_cms_version($root);
        $enrich_fn  = BINDL('\BitFire\enrich_hashes', $ver, $root, $num_files);
        $enriched_files = array_map($enrich_fn, $decoded);


        //echo "<pre>\n";
        //dbg($enriched_files);

        // remove files that passed check
        $filtered = array_filter($enriched_files, function ($file) use ($allow_map) {
            $r = $file['r']??'fail';
            $keep = ($r !== "PASS");
            //echo "keep: [$r] - ($keep)\n";
            if ($keep) {
                $keep = ($allow_map[$file['file_path']]??false) ? false : true;
                //echo "allowed ($keep)!\n";
            }
            // now skip root files that don't have malware
            if ($keep) {
                $num_malware = $file["malware"]->count();
                //echo $file["file_path"] . " - file has problem, check malware [$num_malware]\n";
                return $file["malware"]->count() > 0;
            }
            
            return $keep;
        });
        // die("filtered");
    }
    else {
        $filtered = [];
    }



    //$only_malware = array_filter($enriched_files, function($x) { return count($x['malware']) > 0; });
    $enriched = array("count" => $num_files, "root" => $root, "files" => $filtered);

    // TODO: root malware files are not returning the "malware" array, so we can't display the malware
    return $enriched;
}



function serve_malware() {
    require_once WAF_SRC . "cms.php";
    // start the profiler if we have one
    if (function_exists('xhprof_enable') && file_exists(WAF_ROOT . "profiler.enabled")) {
        xhprof_enable(XHPROF_FLAGS_CPU + XHPROF_FLAGS_MEMORY);
    }

    // authentication guard
    $auth = validate_auth();
    $auth->run();
    if ($auth->read_status() == 302) { return; }

    // load the scanner config
    $raw_scan_config = CFG::arr("malware_config");
    if (empty($raw_scan_config)) {
        $raw_scan_config = ["unknown_core:1", "standard_scan:false", "access_time:1", "random_name_per:50", "line_limit:12000", "freq_limit:768", "random_name_per:75", "fn_freq_limit:512", "fn_line_limit:2048", "fn_random_name_per:60",  "includes:0", "var_fn:1", "call_func:1", "wp_func:0", "extra_regex:"];
        $eff = update_ini_fn(BINDL('\BitFireSvr\array_to_ini', 'malware_config', $raw_scan_config), WAF_INI, true);
        $eff->run();
    }
    $scanConfig = parse_scan_config($raw_scan_config);

    // for reading php files
    if (CFG::enabled("FPL") && function_exists("\BitFirePRO\site_unlock")) { 
        \BitFirePro\site_unlock();
    }
    $config = map_mapvalue(Config::$_options, '\BitFire\alert_or_block');
    $config['security_headers_enabled'] = ($config['security_headers_enabled'] === "block") ? "true" : "false";

    //$odd = odd_access_times("/var/www/wordpress/wp-admin");
    //dbg($odd, "odd");

    // $scanConfig->

    //$file_list = dump_hashes();
    //$file_list = array("count" => 0, "root" => cms_root(), "files" => []);
    //$dir_list = dump_dirs();


    $is_free = (strlen(CFG::str("pro_key")) < 20);
    $root = \BitFireSvr\cms_root();
    $data = array();

    //$assets = (defined("WPINC")) ? CFG::str("cms_content_url")."/plugins/bitfire/public/" : "https://bitfire.co/assets/";
    //$f2 = "{$assets}vs2015.css";
    //$f3 = "{$assets}prism2.css";
    //debug("F2 [$f3]");
    //$f4 = \BitFire\WAF_ROOT . "public/theme.min.css";
    //$f5 = \BitFire\WAF_ROOT . "public/theme.bundle.css";
    //$data['theme_css'] = file_get_contents($f3) . file_get_contents($f4) . file_get_contents($f5);
    $data['date_z'] = date('Z');
    $data['version'] = BITFIRE_VER;
    $data['version_str'] = BITFIRE_SYM_VER;
    $data['llang'] = "en-US";
    $data['wp_ver'] = get_cms_version($root);
    //$data['file_count'] = count($file_list['files']);
    //$data['file_list_json'] = en_json(compact_array($file_list['files']));
    //$data['dir_ver_json'] = en_json($dir_list);
    $data['is_free'] = $is_free;
    //$data['dir_list_json'] = en_json(array_keys($dir_list));
    $data['show_diff1'] = ($is_free) ? "\nalert('d1 Upgrade to PRO to access over 10,000,000 WordPress file datapoints and view and repair these file changes');\n" : "\nout.classList.toggle('collapse');\n";
    $data['show_diff2'] = (!$is_free) ? "\ne.innerHTML = html;\ne2.innerText = line_nums.trim();\n" : "";
    $root = \BitFireSvr\cms_root();
    $data["total_files"] = get_file_count($root);
    $data["scan_config"] = $scanConfig;
    $data["server"] = urlencode($_SERVER['HTTP_HOST']);
    $data["email"] = CFG::str("notification_email");
    $data["free_disable"] = ($is_free) ? "disabled" : "";
    //$data["free_disable"] = "";


    $view = ($root == "") ? "nohashes.html" : "hashes.html";

if (function_exists('xhprof_enable') && file_exists(WAF_ROOT . "profiler.enabled")) {
    $rrr = xhprof_disable();
    file_put_contents('/tmp/xhr_profile2.json', json_encode($rrr, JSON_PRETTY_PRINT));
    output_profile($rrr, "/tmp/callgrind_2.out");
    $rrr = array_filter($rrr, function ($elm) {
        return $elm['wt'] > 100 || $elm['cpu'] > 100;
    });
    uasort($rrr, '\ThreadFin\prof_sort');
    file_put_contents('/tmp/xhr_profile2.min.json', json_encode($rrr, JSON_PRETTY_PRINT));
}

    render_view(\BitFire\WAF_ROOT."views/$view", "bitfire_malware", $data)->run();
}

function human_date($time) : string {
    return date("D M j Y, h:i:s A P", (int)$time);
}
function human_date2($time) : string {
    return 
    "<span class='text-primary'>".date("D M j", (int)$time).", </span>".
    "<span class='text-muted'>".date("Y", (int)$time)."</span> ".
    "<span class='text-info'>".date("h:i:s A", (int)$time)."</span> ".
    "<span class='text-muted'>".date("P", (int)$time)."</span> ";
}

// return a url to this page stripped of BITFIRE parameters.
function dashboard_url(string $token, string $internal_name) : string {
    trace("self_url");
    // handle all other cases.  we want to recreate our exact url 
    // to handle all cases WITHOUT bitfire parameters...
    $url = parse_url($_SERVER['REQUEST_URI']);
    $get = ['1' => '0'];
    foreach($_GET as $k => $v) {
        $get[urldecode($k)] = urldecode($v);
    }
    unset($get['BITFIRE_WP_PAGE']);
    unset($get['BITFIRE_PAGE']);
    unset($get['tooltip']);
    unset($get['page']);
    unset($get['block_page_num']);
    unset($get['alert_page_num']);
    unset($get['block_filter']);
    return $url['path'] . '?' . http_build_query($get) . "&BITFIRE_PAGE=$internal_name";
}



function serve_settings() {
    // authentication guard
    $auth = validate_auth();
    $auth->run();
    if ($auth->read_status() == 302) { return; }


    $view = (CFG::disabled("wizard")) ? "wizard.html" : "settings.html";
    if (CFG::str("password") == "configure") {
        $view = "setup.html";
    }

    $email = "you@mail.com";
    if (function_exists("wp_get_current_user")) {
        $user = wp_get_current_user();
        $email = $user->user_email;
    }

    //"dashboard_path" => $dashboard_path,
    render_view(\BitFire\WAF_ROOT . "views/$view", "bitfire_settings", array_merge(CFG::$_options, array(
        "auto_start" => CFG::str("auto_start"),
        "your_email" => $email,
		//"theme_css" => file_get_contents(\BitFire\WAF_ROOT."public/theme.min.css"). file_get_contents(\BitFire\WAF_ROOT."public/theme.bundle.css"),
        "valid_domains_html" => list_text_inputs("valid_domains"),
        "hide_shmop" => (function_exists("shmop_open")) ? "" : "hidden",
        "hide_apcu" => (function_exists("apcu_store")) ? "" : "hidden",
        "hide_shm" => (function_exists("shm_put_var")) ? "" : "hidden"
    )))->run();
}

function serve_advanced() {
    // authentication guard
    validate_auth()->run();
    $is_free = (strlen(Config::str('pro_key')) < 20);
    $disabled = ($is_free) ? "disabled='disabled'" : "";
    $info = ($is_free) ? "<h4 class='text-info'> * Runtime Application Self Protection must first be installed with BitFire PRO. See link in header for details.</h4>" : "";
    $data = ["mfa" => defined("WPINC") ? "Enable multi factor authentication. Add MFA phone numbers in user editor." :
        "Multi Factor Authentication is only available in the WordPress plugin. Please install from the WordPress plugin directory.",
        "show_mfa" => (defined("WPINC")) ? "" : "hidden",
        "disabled" => $disabled,
        "info" => $info,
        "mfa_class" => (defined("WPINC")) ? "text-muted" : "text-danger"];
    //"dashboard_path" => $dashboard_path,
    render_view(\BitFire\WAF_ROOT . "views/advanced.html", "bitfire_advanced", array_merge(CFG::$_options, $data))->run();
}

function serve_bot_list() {
    // authentication guard
    validate_auth()->run();
    $url_fn = find_fn("dashboard_url");
    $request = BitFire::get_instance()->_request;

    require_once WAF_SRC . "botfilter.php";
    $bot_dir = get_hidden_file("bots");
    $bot_files = glob("{$bot_dir}/*.json");
    $country_mapping = \ThreadFin\un_json(file_get_contents(\BitFire\WAF_ROOT . "cache/country_name.json"));
    $country_fn = BINDR("BitFire\country_resolver", un_json(file_get_contents(\BitFire\WAF_ROOT . "cache/country.json")));


    $all_bots = array_map(function ($file) {
        $id = pathinfo($file, PATHINFO_FILENAME);
        $bot = unserialize(file_get_contents($file));
        if (!$bot) { return new BotInfo("broken bot ($id)"); }
        if (empty($bot->mtime)) { $bot->mtime = filemtime($file); }
        $bot->last_time = filemtime($file);
        // ID must always be the filename...
        $bot->id = $id;

        return $bot;
    }, $bot_files);

    $known = $request->get["known"]??"unknown";
    $filter_bots = array_filter($all_bots, function($bot) use ($known) {
        if ($known=="known") {
            return $bot->category != "Auto Learn";
        } else {
            return $bot->category == "Auto Learn";
            //return ($bot->mtime > (time() - DAY*30)) && ($bot->valid < 1);
        }
    });

    // order by last time seen, newest first
    usort($filter_bots, function($a, $b) {
        return $b->last_time - $a->last_time;
    });

    $bot_list = array_map(function ($bot) use ($country_fn, $country_mapping) {
        if (empty($bot->country) && !empty($bot->ips)) {
            $ips = array_keys($bot->ips);
            $country_counts = [];
            foreach ($ips as $ip) {
                $country = $country_mapping[$country_fn($ip)]??"-";
                $country_counts[$country] = ($country_counts[$country]??0) + 1;
            }
            arsort($country_counts);
            $bot->country = join(",", array_slice(array_keys($country_counts), 0, 3));
            if (empty($bot->name)) {
                $bot->name = "Unknown Bot";
            }
        } else if (empty($bot->country)) {
            $bot->country = "-";
        }
        // trim down to the minimum user agent, this need to be a function. keep in sync with botfilter.php
        $agent_min1 = preg_replace("/[^a-z\s]/", " ", strtolower(trim($bot->agent)));
        $agent_min2 = preg_replace("/\s+/", " ", preg_replace("/\s[a-z]{1,3}\s([a-z]{1-3}\s)?/", " ", $agent_min1));
        // remove common words
        $rem_fn = function ($carry, $item) {
            return str_replace($item, "", $carry);
        };
        $agent_min_words = array_filter(explode(" ", array_reduce(COMMON_WORDS, $rem_fn, $agent_min2)));

        $bot->trim = substr(trim(join(" ", $agent_min_words)), 0, 250);


        $bot->allow = "authenticated";
        $bot->allowclass = "success";
        if ($bot->net === "*") {
            $bot->allow = "ANY IP";
            $bot->domain = "Any";
        $bot->allowclass = "danger";
        } else if ($bot->net === "!") {
            $bot->allow = "BLOCKED";
            $bot->allowclass = "dark";
        }
        $bot->agent = substr($bot->agent, 0, 160);
        if (!empty($bot->home_page)) { 
            $info = parse_url($bot->home_page);
            $bot->favicon = $info["scheme"] . "://" . $info["host"] . "/favicon.ico";
        } else {$bot->favicon = get_asset_dir() . "robot_nice.svg";}
        $bot->classclass = "danger";
        if ($bot->valid==0) {
            $bot->classclass = "warning";
        } else if ($bot->valid==1) {
            $bot->classclass = "secondary";
        }
        if (empty($bot->hit)) { $bot->hit = 0; }
        if (empty($bot->miss)) { $bot->miss = 0; }
        if (empty($bot->not_found)) { $bot->not_found = 0; }
        if (empty($bot->domain)) { $bot->domain = "-"; }
        if (empty($bot->icon)) { $bot->icon = "robot_nice.svg"; }
        $bot->machine_date = date("Y-m-d", $bot->mtime);
        $bot->machine_date2 = date("Y-m-d", $bot->last_time);
        $bot->checked = ($bot->valid > 0) ? "checked" : "";
        $bot->domain = trim($bot->domain, ",");
        $bot->ip_str = join(", ", array_keys($bot->ips));
        if (empty($bot->home_page)) { 
            $bot->home_page = "https://www.google.com/search?q=" . urlencode($bot->agent);
            $bot->icon = "robot.svg";
        }
        if (empty($bot->vendor)) { $bot->vendor = "Unknown"; }
        return $bot;
    }, $filter_bots);

    $x = $request->get["known"]??"unknown";
    $check = ($x === "known") ? "checked" : "";

    if (empty($bot_list)) {
        $bot = new BotInfo("This is a place-holder bot for display only. Bots will appear here when they are detected. Control access with the triple dot icon on the right.");
        $bot->allow = "no authentication";
        $bot->allowclass = "dark";
        $bot->category = "Test Sample";
        $bot->country = "Local Host";
        $bot->country_code = "-";
        $bot->domain = "BitFire.co";
        $bot->favicon = "https://bitfire.co/favicon.ico";
        $bot->hit = 0;
        $bot->miss = 0;
        $bot->not_found = 0;
        $bot->ips = ['127.0.0.1' => 1];
        $bot->home_page = "https://bitfire.co/sample_bot";
        $bot->favicon = "https://bitfire.co/assets/img/shield128.png";
        $bot->name = "BitFire Sample Bot";
        $bot->net = "-";
        $bot->trim = "BitFire";
        $bot->domain = "bitfire.co";
        $bot->vendor = "BitFire, llc";
        $bot->machine_date = date("Y-m-d");
        $bot->machine_date2 = date("Y-m-d");

        $bot_list = [$bot];
    }

    $data = ["bot_list" => $bot_list, "known_check" => $check];
    render_view(\BitFire\WAF_ROOT . "views/bot_list.html", "bitfire_bot_list", array_merge(CFG::$_options, $data))->run();
}



/**
 * auth on basic auth string or wordpress is admin
 * @param string $raw_pw the password to validate against Config::password
 * @return Effect validation effect. after run, ensured to be authenticated
 */
function validate_auth() : Effect {

    // issue a notice if the web path is not writeable
    /*
    if (!is_writable(WAF_INI)) {
        return render_view(\BitFire\WAF_ROOT."views/permissions.html", "content", ["title" => "bitfire must be web-writeable", "body" => "please make sure bitfire is owned by the web user and web writeable"])->exit(true);
    }
    */

    return \BitFire\verify_admin_password();
}


function enrich_alert(array $report, array $exceptions, array $whitelist) : array{
    assert(isset($report["block"]), "enrich_alert: report must have a block");
    $t = time();

    $cl = \BitFire\code_class($report['block']['code']);
    $report['block']['message_class'] = MESSAGE_CLASS[$cl];
    $test_exception = new \BitFire\Exception($report['block']['code'], 'x', $report['block']['parameter'], $report['request']['path']);

    $report['type_img'] = CODE_CLASS[$cl];
    $browser = \BitFireBot\parse_agent($report['request']['agent']);
    if (!$browser->bot && !$browser->browser) {
        $browser->browser = "unknown";
    }
    $report['browser'] = $browser;
    $report['agent_img'] = ($browser->bot) ? 'robot.svg' : ($browser->browser . ".png");
    $report['country_img'] = strtolower($report['country']) . ".svg";
    $report['country_alt'] = strtolower($report['country']);
    if ($report['country_img'] == "-.svg") {
        $report['country_img'] = "us.svg";
    }

    $report['when'] = human_date($line['tv']??$t);


    // filter out the "would be" exception for this alert, and compare if we removed the exception
    $filtered_list = array_filter($exceptions, compose("\ThreadFin\\not", BINDR("\BitFire\match_exception", $test_exception)));
    if ($test_exception->code == "10029") {
        //dbg($report, "report");
        //dbg([$filtered_list, $test_exception], "test_exception");
    }
    $has_exception = (count($exceptions) > count($filtered_list));


    $report['exception_class'] = ($has_exception) ? "warning" : "secondary";
    $report['exception_img'] = ($has_exception) ? "bandage.svg" : "fix.svg";

    $report['type_title'] = "[" . MESSAGE_CLASS[$cl] . '] url: [' . $report['request']['path']. ']';
    $report['agent_title'] = "Browser type: " . $browser->browser;
    $report['flag_title'] = "Origin Country: " . $report['country'];

    $report['exception_title'] = ($has_exception) ?
    "exception already added for this block" :
    "add exception for [" . MESSAGE_CLASS[$cl] . '] url: [' . $report['request']['path']. ']';

    return $report;
}


function serve_exceptions() :void
{
    $file_name = get_hidden_file("exceptions.json");
    $exceptions = FileData::new($file_name)->read()->un_json()->map(function ($x) {
        $class = (floor($x["code"] / 1000) * 1000);
        $x["message"] = MESSAGE_CLASS[$class];
        if (!$x["parameter"]) {
            $x["parameter"] = "All Parameters";
        }
        if (!$x["host"]) {
            $x["host"] = "All Hosts";
        }
        if (!$x["url"]) {
            $x["url"] = "Any URL";
        }
        return $x;
    });

    // ugly...
    $complete = CFG::int("dynamic_exceptions");
    if ($complete < 10) { 
        $when = "Learning complete";
        $enabled = false;
    } else {
        $enabled = true;
        if ($complete > time()) {
            $num = ceil(($complete - time()) / DAY);
            $day = ($num > 1) ? "days" : "day";
            $when = "Learning complete in $num $day";
        } else {
            $when = "Learning completed on " . date("M j, Y", $complete);
        }
    }
    $data = [
        "exceptions" => $exceptions(),
        "exception_json" => json_encode($exceptions()),
        "learn_complete" => $when,
        "enabled" => $enabled,
        "checked" => ($enabled) ? "checked" : "",
        "exception_file" => substr(get_hidden_file("exceptions.json"), -64) 
    ];

    render_view(\BitFire\WAF_ROOT."views/exceptions.html", "bitfire_exceptions", $data)->run();
}

function binary_search(array $malware, int $needle, int $offset, int $malware_size) {
    if ($offset === 0) {
        $offset = $malware_size / 2;
    }

}


function serve_database() : void
{
    // pull in some wordpress functions in case wordpress is down
    require_once WAF_SRC."wordpress.php";

    $response = http2("GET", "https://bitfire.co/backup2.php?get_info=1", [
        "secret" => sha1(CFG::str("secret")),
        "domain" => $_SERVER['HTTP_HOST']]);
    $backup_status = json_decode($response->content, true);
    
    $backup_status["online"] = ($backup_status["capacity"]??0 > 0);
    $backup_status["online_text"] = ($backup_status["capacity"]??0 > 0) ? _t("Online") : _t("Offline");

    $backup_status["online_class"] = ($backup_status["online"] == true) ? "success" : "warning";

    //$database_file = ;
    //$database_file = FileData::new(WAF_ROOT . "cache/database.json");//->read()->un_json()->lines;

    $info = [];
    $href_list = [];
    $script_list = [];

    $info["backup_status"] = $backup_status;
    $info["backup-age-days"] = "Never";
    $info["backup-age-badge"] = "bg-danger-soft";
    $info["backup-storage-badge"] = "bg-success-soft";
    $info["backup-storage"] = "?" . _t(" MB");
    $info["backup-posts"] = $backup_status["posts"] ?? '?';
    $info["backup-comments"] = $backup_status["comments"] ?? '?';
    $info["restore_disabled"] = "disabled";
    $info["restore-available"] = "N/A";
    $info["points"] = $backup_status["archives"]??'?';

    if ($backup_status["online"]) {
        //$info["restore_disabled"] = "";
        $info["restore-available"] = ($backup_status["storage"]??0 > 64000) ? _t("Online") : _t("N/A");
        $info["restore-class"] = ($backup_status["storage"]??0 > 64000) ? "success" : "danger";

        // database backup info
        $info["backup-storage"] = round(($backup_status["capacity"]-$backup_status["storage"])/1024/1024, 2) . _t(" MB");
        $info["backup-age-sec"] = intval($backup_status["backup_epoch"]??0);
        $info["backup-posts"] = $backup_status["posts"]??0;
        $info["backup-comments"] = $backup_status["comments"]??0;

        if ($info["backup-age-sec"] < time() - (30 * DAY)) {
            $info["backup-age-badge"] = "bg-success-soft";
        }
        $info["backup-size"] = intval($backup_status["storage"]??0);
        if ($info["backup-size"] > 1024*1024*40) {
            $info["backup-storage-badge"] = "bg-danger-soft";
        }
    }

    $credentials = null;
    if (defined("WPINC") && defined("DB_USER")) {
        $prefix  = "wp_";
        if (isset($GLOBALS['wpdb'])) {
            trace("WP_DB");
            $prefix = $GLOBALS['wpdb']->prefix;
        }
        $credentials = new Credentials(DB_USER, DB_PASSWORD, DB_HOST, DB_NAME);
    } else {
        trace("BIT_DB");
        $credentials = wp_parse_credentials(CFG::str("cms_root"));
        if ($credentials) {
            $prefix = $credentials->prefix;
        }
    }
    if ($credentials) {
        $db = DB::cred_connect($credentials)->enable_log(true);
        $info['site_url'] = $db->fetch("select option_value from `{$prefix}options` WHERE option_name = {option_name}", 
            ["option_name" => "siteurl"])
            ->col("option_value")();
        $info[''] = $db->fetch("select option_value from `{$prefix}options` WHERE option_name = {option_name}", 
            ["option_name" => "active_plugins"])
            ->col("option_value")();
        $info['active'] = $db->fetch("select option_name from `{$prefix}options` WHERE option_name = {option_name}", 
            ["option_name" => "active_plugins"])
            ->col("option_value")();
        $info['auto_load_sz_kb'] = $db->fetch("SELECT ROUND(SUM(LENGTH(option_value))/1024) as size_kb FROM `{$prefix}options` WHERE autoload='yes'",
            null)
            ->col("size_kb")();
        $info['auto_load_top10'] = $db->fetch("(SELECT option_name, length(option_value) as size FROM `{$prefix}options` WHERE autoload='yes' ORDER BY length(option_value) DESC LIMIT 10)",
            null)
            ->data();

        $info['num-posts'] = $db->fetch("SELECT count(*) as num FROM `{$prefix}posts` p")->col("num")();
        $info['num-comments'] = $db->fetch("SELECT count(*) as num FROM `{$prefix}comments` p")->col("num")();

        /*
        $posts = $db->fetch("SELECT p.id, post_content, post_title, u.display_name, post_date FROM `{$prefix}posts` p LEFT JOIN `{$prefix}users` u ON p.post_author = u.id ORDER BY post_date DESC LIMIT 1000 OFFSET 0",
            null);

        if (!$posts->empty()) {
            // remap malware list to hashmap
            $malware_file = WAF_ROOT . "/cache/malware.bin";
            $malware_raw = file_get_contents($malware_file);
            $malware = unpack("N*", $malware_raw);
            $malware_total = count($malware);
        }
        */

        $good_domains = [];
        $bad_domains = [];

        $my_url_len = strlen($info["site_url"]);
        /*
        $info["backup-posts"] = $posts->count() - intval($info["backup-posts"]);
        foreach ($posts->data() as $post) {
            if (preg_match_all("/<script([^>]*)>([^<]*)/is", $post["post_content"], $matches)) {
                $seconds = time();
                $script_list[] = [
                    "id" => $post["id"],
                    "title" => $post["post_title"],
                    "author" => $post["display_name"],
                    "date" => $post["post_date"],
                    "days" => ceil($seconds/DAY),
                    "markup" => $matches[1],
                    "domain" => "script content",
                    "content" => $matches[2]
                ];
            }
            if (preg_match_all("/<a[^>]+>/i", $post['post_content'], $links)) {
                foreach ($links as $link) {
                    // skip link if it is marked nofollow, or user content
                    if (icontains($link[0], ["nofollow", "ugc"])) {
                        continue;
                    }
                    // skip the link if it's not a full path...
                    if (!icontains($link[0], "http")) {
                        continue;
                    }
                    // it's a real link
                    if (preg_match("/href\s*=\s*[\"\']?\s*([^\s\"\']+)/i", $link[0], $href)) {
                        // exclude links to ourself...
                        $source = substr($href[1], 0, strlen($my_url_len) + 16);
                        if (icontains($source, $info["site_url"])) { continue; }

                        $check_domain = preg_replace("#https?:\/\/([^\/]+).*#", "$1", $href[1]);

                        // don't search 2x!
                        if (isset($good_domains[$check_domain])) { continue; }

                        // TODO: add list of Top 1000 domains and check those first to exclude the link here
                        $hash = crc32($check_domain );

                        if (in_list($malware, $hash, $malware_total)) {
                            $bad_domains[$check_domain] = true;
                        } else {
                            $good_domains[$check_domain] = true;
                        }


                        if (isset($bad_domains[$check_domain])) {
                            $parsed = date_parse($post["post_date"]);
                            $new_epoch = mktime(
                                $parsed['hour'], 
                                $parsed['minute'], 
                                $parsed['second'], 
                                $parsed['month'], 
                                $parsed['day'], 
                                $parsed['year']
                            );
                            $seconds = time() - $new_epoch;

                            $href_list[$href[1]] = [
                                "id" => $post["id"],
                                "name" => $post["display_name"],
                                "title" => $post["post_title"],
                                "date" => $post["post_date"],
                                "days" => ceil($seconds/DAY),
                                "markup" => $link[0],
                                "domain" => $check_domain,
                                "md5" => md5($check_domain),
                                "hash" => $hash
                            ];
                        }
                    }
                }
            }
        }
        */
    }


    $info["malware"] = $href_list;

    $defines = wp_parse_define(CFG::str("cms_root") . "/wp-includes/version.php");
    $info['wp_version'] = $defines['wp_version']??"unknown";
    $info['db_version'] = $defines['wp_db_version']??"unknown";
    $info['num_malware'] = count($href_list);

    // http2("POST", APP."domain_check.php", en_json($href_list));

    render_view(\BitFire\WAF_ROOT . "views/database.html", "bitfire_database", $info)->run();
}

/**
 * TODO: split this up into multiple functions
 */
function serve_dashboard() :void {
    // handle dashboard wizard
    if (CFG::disabled("wizard") && !isset($_GET['tooltip'])) {
       serve_settings();
       return;
    }

    // authentication guard
    $auth = validate_auth();
    $auth->run();
    if ($auth->read_status() == 302) { return; }
    
    $block_page_num = intval($_GET["block_page_num"]??0);
    $alert_page_num = intval($_GET["alert_page_num"]??0);
    $data = [
        "block_page_num" => max(0, $block_page_num),
        "alert_page_num" => max(0, $alert_page_num)
    ];

    $country_fn = country_enricher(\ThreadFin\un_json(file_get_contents(\BitFire\WAF_ROOT . "cache/country.json")));

    $review_file = FileData::new(get_hidden_file("review.json"))
        ->read()
        ->map('\ThreadFin\un_json');
    $review_data = [];
    array_walk($review_file->lines, function($x) use (&$review_data) {
        $review_data[$x['uuid']] = $x['name'];
    });


    // load all alert data
    // TODO: make dry
    $report_code = intval($_GET['report_filter']??0);
    $report_file = \ThreadFin\FileData::new(get_hidden_file("alerts.json"))
        ->read();

    $report_count = $report_file->num_lines;
    debug("report count: %d page: %d, size: %d", $report_count, $alert_page_num, PAGE_SZ);
    $report_file->apply(BINDR('\BitFire\remove_lines', 400))
        ->apply_ln('array_reverse')
        ->apply_ln(BINDR('array_slice', $alert_page_num * PAGE_SZ, PAGE_SZ, false))
        ->map('\ThreadFin\un_json')
        ->map($country_fn);
    $reporting = $report_file->lines;

    // filter to just the requested block type
    if ($report_code > 0) {
        $reporting = array_filter($reporting, function($x) use ($report_code) {
            // if the filter is a class, then allow anything with that class
            $class = code_class($report_code);
            if ($report_code == $class) {
                $block_class = code_class($x["block"]["code"]);
                return $block_class == $report_code;
            }
            // allow only the exact code
            return $x["block"]["code"] == $report_code;
        });
    }


    // calculate number of alert pages
    //$report_count = $report_file->num_lines;
    $data["report_count"] = $report_count;
    $data["report_range"] = ($alert_page_num * PAGE_SZ) . " - " . (($alert_page_num * PAGE_SZ) + PAGE_SZ);
    $data["report_pages"] = ceil($report_count / PAGE_SZ);
    $data["alerts"] = [];
    $data["access"] = defined("WPINC") ? "You can access the dashboard by clicking the BitFire icon in the admin bar." : "You can access the dashboard by visiting " .  parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);

    $exceptions = load_exceptions();
    // this will create a $config array from whitelist agents
    $config = ["botwhitelist" => []];
    //@include (\BitFire\WAF_ROOT."cache/whitelist_agents.ini.php");
    $config = array_merge($config, \parse_ini_file(\BitFire\WAF_ROOT."cache/whitelist_agents.ini"));
    array_walk($reporting, function($line) use (&$data, $exceptions, $config) {
        if (isset($line["block"])) {
            $block = enrich_alert($line, $exceptions, $config["botwhitelist"]);
            $block["block"]["review_class"] = "hidden";
            $block["block"]["review_name"] = "";
            $data["alerts"][] = $block;
        }
    });

    // add alerts
    $data['alerts_json'] = json_encode($data["alerts"], JSON_HEX_APOS);

    $block_code = intval($_GET['block_filter']??0);

    // load all block data
    $block_file = \ThreadFin\FileData::new(get_hidden_file("blocks.json"))
        ->read()
        ->apply(BINDR('\BitFire\remove_lines', 400))
        ->apply_ln('array_reverse')
        ->map('\ThreadFin\un_json');
    $block_count = $block_file->num_lines; // need block count before filtering pagination
    //$blocking_full = $block_file->lines;
    $block_file->apply_ln(BINDR('array_slice', $block_page_num * PAGE_SZ, PAGE_SZ, false))
        ->map($country_fn);
    $blocking = $block_file->lines;

    // filter to just the requested block type
    if ($block_code > 0) {
        $eqfn = ($_GET['invert_block_check']??0) ? "\ThreadFin\\neq" : "\ThreadFin\\eq";
        $blocking = array_filter($blocking, function($x) use ($block_code, $eqfn) {
            // if the filter is a class, then allow anything with that class
            $class = code_class($block_code);
            if ($block_code == $class) {
                $block_class = code_class($x["block"]["code"]??0);
                return $eqfn($block_class, $block_code);
            }
            // allow only the exact code
            return $eqfn($x["block"]["code"], $block_code);
        });
    }

    $data["invert_block_check"] = isset($_GET['invert_block_check']) ? "checked='checked'" : "";
    // calculate number of block pages
    $data["block_count"] = $block_count;
    $data["block_range"] = ($block_page_num * PAGE_SZ) . " - " . (($block_page_num * PAGE_SZ) + PAGE_SZ);
    $data["block_pages"] = ceil($block_count / PAGE_SZ);
    $data["blocks"] = [];

    $exceptions = load_exceptions();
    array_walk($blocking, function($line) use (&$data, $exceptions, $config, $review_data) {
        if (isset($line["block"])) {
            $block = enrich_alert($line, $exceptions, $config["botwhitelist"]);

            if (!empty($block["request"]["get"])) {
                $block["request"]["query"] = '?'. http_build_query($block["request"]["get"]??[]);
            }

            if (isset($block["block"]) && isset($block["block"]["uuid"]) && isset($review_data[$block["block"]["uuid"]])) {
                $block["block"]["review_name"] = $review_data[$block["block"]["uuid"]] . " requested a review";
                $block["block"]["review_class"] = "";
            } else {
                $block["block"]["review_class"] = "hidden";
                $block["block"]["review_name"] = "";
            }
            $data["blocks"][] = $block;
        }
    });

    // add alerts
    $data['blocks_json'] = en_json($data["blocks"]);



    // calculate just the 24 hour block count
    $check_day = time() - DAY*2;
    $block_24 = array_filter($blocking, function ($x) use ($check_day) {
        $pass = isset($x['tv']) && $x['tv'] > $check_day;
        
        return $pass;
    });
    $data['block_count_24'] = count($block_24);
    //$blocks = array_slice($blocking, $block_page_num * PAGE_SZ, PAGE_SZ);


    // calculate hr data
    // x['ts'] is in UTC
    $hr_data = array_reduce($block_24, function ($carry, $x) {

        $ts = (isset($x['tv'])) ? (int)$x['tv'] : 0;
        $hr = (int)date('H', $ts);
        $carry[$hr]++;
        return $carry;
    }, array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
    $data['hr_data_json'] = en_json(["total" => count($hr_data), "data" => $hr_data]);

    // calculate country data
    $country_data = array_reduce($block_24, function ($carry, $x) {
        $c = $x['country']??'-';
        $carry[$c] = isset($carry[$c]) ? $carry[$c] + 1 : 1;
        return $carry;
    }, array());
    $data['country_data_json'] = en_json(["total" => count($country_data), "data" => $country_data]);

    // calculate type data
    $type_data = array_reduce($block_24, function ($carry, $x) {
        $class = code_class($x['block']['code']??0);
        $carry[$class] = isset($carry[$class]) ? $carry[$class] + 1 : 1;
        return $carry;
    }, array());
    $data['type_data_json'] = en_json(["total" => count($type_data), "data" => $type_data]);

    if (function_exists('\BitFirePlugin\create_plugin_alerts')) {
        $alerts = \BitFirePlugin\create_plugin_alerts();
        foreach ($alerts as $alert) {
            $data['plugin_alerts'] = "<div style='border-left: 5px solid #d63638; padding-left: 1rem;'>
            <span class='dashicons dashicons-admin-plugins' data-code='f485'></span> {$alert}</div>\n";
        }
    }

    $url_fn = find_fn("dashboard_url");
    $data["filter_link"] = $url_fn("bitfire", "DASHBOARD");

    //$data["theme_css"] = file_get_contents(\BitFire\WAF_ROOT."public/theme.min.css"). file_get_contents(\BitFire\WAF_ROOT."public/theme.bundle.css");
    render_view(\BitFire\WAF_ROOT."views/dash.html", "bitfire", $data)->run();
}


class Request_Display {
    public string $ip;
    public string $url;
    public string $note;
    public string $method;
    public string $agent;
    public string $agent_icon;
    public int $timestamp;
    public bool $auth;
    public bool $bot;
    //public int $ctr_200;
    //public int $ctr_404;
}

class Request_Store {

}


function serve_traffic() {
    // authentication guard
    validate_auth()->run();
    $url_fn = find_fn("dashboard_url");
    $request = BitFire::get_instance()->_request;

    require_once WAF_SRC . "botfilter.php";
    $bot_dir = get_hidden_file("bots");
    $bot_files = glob("{$bot_dir}/*.json");
    $country_mapping = \ThreadFin\un_json(file_get_contents(\BitFire\WAF_ROOT . "cache/country_name.json"));
    $country_fn = BINDR("BitFire\country_resolver", un_json(file_get_contents(\BitFire\WAF_ROOT . "cache/country.json")));


    $all_bots = array_map(function ($file) {
        $id = pathinfo($file, PATHINFO_FILENAME);
        $bot = unserialize(file_get_contents($file));
        if (!$bot) { return new BotInfo("broken bot ($id)"); }
        if (empty($bot->mtime)) { $bot->mtime = filemtime($file); }
        $bot->last_time = filemtime($file);
        // ID must always be the filename...
        $bot->id = $id;

        return $bot;
    }, $bot_files);

    $known = $request->get["known"]??"unknown";
    $filter_bots = array_filter($all_bots, function($bot) use ($known) {
        if ($known=="known") {
            return $bot->category != "Auto Learn";
        } else {
            return $bot->category == "Auto Learn";
            //return ($bot->mtime > (time() - DAY*30)) && ($bot->valid < 1);
        }
    });

    // order by last time seen, newest first
    usort($filter_bots, function($a, $b) {
        return $b->last_time - $a->last_time;
    });

    $bot_list = array_map(function ($bot) use ($country_fn, $country_mapping) {
        if (empty($bot->country) && !empty($bot->ips)) {
            $ips = array_keys($bot->ips);
            $country_counts = [];
            foreach ($ips as $ip) {
                $country = $country_mapping[$country_fn($ip)]??"-";
                $country_counts[$country] = ($country_counts[$country]??0) + 1;
            }
            arsort($country_counts);
            $bot->country = join(",", array_slice(array_keys($country_counts), 0, 3));
            if (empty($bot->name)) {
                $bot->name = "Unknown Bot";
            }
        } else if (empty($bot->country)) {
            $bot->country = "-";
        }
        // trim down to the minimum user agent, this need to be a function. keep in sync with botfilter.php
        $agent_min1 = preg_replace("/[^a-z\s]/", " ", strtolower(trim($bot->agent)));
        $agent_min2 = preg_replace("/\s+/", " ", preg_replace("/\s[a-z]{1,3}\s([a-z]{1-3}\s)?/", " ", $agent_min1));
        // remove common words
        $rem_fn = function ($carry, $item) {
            return str_replace($item, "", $carry);
        };
        $agent_min_words = array_filter(explode(" ", array_reduce(COMMON_WORDS, $rem_fn, $agent_min2)));

        $bot->trim = substr(trim(join(" ", $agent_min_words)), 0, 250);


        $bot->allow = "authenticated";
        $bot->allowclass = "success";
        if ($bot->net === "*") {
            $bot->allow = "ANY IP";
            $bot->domain = "Any";
        $bot->allowclass = "danger";
        } else if ($bot->net === "!") {
            $bot->allow = "BLOCKED";
            $bot->allowclass = "dark";
        }
        $bot->agent = substr($bot->agent, 0, 160);
        if (!empty($bot->home_page)) { 
            $info = parse_url($bot->home_page);
            $bot->favicon = $info["scheme"] . "://" . $info["host"] . "/favicon.ico";
        } else {$bot->favicon = get_asset_dir() . "robot_nice.svg";}
        $bot->classclass = "danger";
        if ($bot->valid==0) {
            $bot->classclass = "warning";
        } else if ($bot->valid==1) {
            $bot->classclass = "secondary";
        }
        if (empty($bot->hit)) { $bot->hit = 0; }
        if (empty($bot->miss)) { $bot->miss = 0; }
        if (empty($bot->not_found)) { $bot->not_found = 0; }
        if (empty($bot->domain)) { $bot->domain = "-"; }
        if (empty($bot->icon)) { $bot->icon = "robot_nice.svg"; }
        $bot->machine_date = date("Y-m-d", $bot->mtime);
        $bot->machine_date2 = date("Y-m-d", $bot->last_time);
        $bot->checked = ($bot->valid > 0) ? "checked" : "";
        $bot->domain = trim($bot->domain, ",");
        $bot->ip_str = join(", ", array_keys($bot->ips));
        if (empty($bot->home_page)) { 
            $bot->home_page = "https://www.google.com/search?q=" . urlencode($bot->agent);
            $bot->icon = "robot.svg";
        }
        if (empty($bot->vendor)) { $bot->vendor = "Unknown"; }
        return $bot;
    }, $filter_bots);

    $x = $request->get["known"]??"unknown";
    $check = ($x === "known") ? "checked" : "";

    if (empty($bot_list)) {
        $bot = new BotInfo("This is a place-holder bot for display only. Bots will appear here when they are detected. Control access with the triple dot icon on the right.");
        $bot->allow = "no authentication";
        $bot->allowclass = "dark";
        $bot->category = "Test Sample";
        $bot->country = "Local Host";
        $bot->country_code = "-";
        $bot->domain = "BitFire.co";
        $bot->favicon = "https://bitfire.co/favicon.ico";
        $bot->hit = 0;
        $bot->miss = 0;
        $bot->not_found = 0;
        $bot->ips = ['127.0.0.1' => 1];
        $bot->home_page = "https://bitfire.co/sample_bot";
        $bot->favicon = "https://bitfire.co/assets/img/shield128.png";
        $bot->name = "BitFire Sample Bot";
        $bot->net = "-";
        $bot->trim = "BitFire";
        $bot->domain = "bitfire.co";
        $bot->vendor = "BitFire, llc";
        $bot->machine_date = date("Y-m-d");
        $bot->machine_date2 = date("Y-m-d");

        $bot_list = [$bot];
    }

    $data = ["bot_list" => $bot_list, "known_check" => $check];
    render_view(\BitFire\WAF_ROOT . "views/bot_list.html", "bitfire_bot_list", array_merge(CFG::$_options, $data))->run();
}
