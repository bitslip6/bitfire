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
use ThreadFin\FileData;
use ThreadFin\Effect;

use const ThreadFin\DAY;
use const ThreadFin\ENCODE_RAW;

use function BitFire\list_text_inputs as BitFireList_text_inputs;
use function BitFireSvr\get_wordpress_version;
use function BitFireSvr\update_ini_value;
use function ThreadFin\array_add_value;
use function ThreadFin\b2s;
use function ThreadFin\ip_to_country;
use function ThreadFin\compact_array;
use function ThreadFin\compose;
use function ThreadFin\dbg;
use function ThreadFin\en_json;
use function ThreadFin\ends_with;
use function ThreadFin\find_fn;
use function ThreadFin\httpp;
use function ThreadFin\map_mapvalue;
use function ThreadFin\partial_right as BINDR;
use function ThreadFin\partial as BINDL;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\find_const_arr;
use function ThreadFin\un_json;

require_once \BitFire\WAF_SRC . "api.php";
require_once \BitFire\WAF_SRC . "const.php";
require_once \BitFire\WAF_SRC . "cms.php";
require_once \BitFire\WAF_SRC . "server.php";
require_once \BitFire\WAF_SRC . "botfilter.php";
require_once \BitFire\WAF_SRC . "renderer.php";

const PAGE_SZ = 30;

function str_replace_first($from, $to, $content)
{
    $from = '/'.preg_quote($from, '/').'/';
    return preg_replace($from, $to, $content, 1);
}

/**
 * truncate the file to max num_lines, returns true if result file is <= $num_lines long
 * SNAP, file_put_contents back
 */
function remove_lines(FileData $file, int $num_lines) : FileData {
    debug("File lines: " . $file->num_lines . " num_lines: $num_lines");

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




/** @deprecated */
function text_input(string $config_name, string $styles="", string $type="text") :string {
    $value = CFG::str($config_name);
    $str = '
    <div id="%s_spin" class="spinner-border text-success spinner-border-sm left mt-1 mr-2 hidden" role="status">
      <span class="visually-hidden">Saving...</span>
    </div>
    <input type="%s" class="form-control txtin" id="%s_text" autocomplete="off" onchange="update_str(\'%s\')" value="%s" style="%s">';
    return sprintf($str, $config_name, $type, $config_name, $config_name, $value, $styles);

}


function list_text_inputs(string $config_name) :string {

    $assets = (defined("WPINC")) ? CFG::str("wp_contenturl")."/plugins/bitfire/public/" : "https://bitfire.co/assets/"; // DUP
    $list = CFG::arr($config_name);
    $idx = 0;
    //$result = \BitFirePlugin\add_script_inline("bitfire-list-$config_name", 'window.list_'.$config_name.' = '.json_encode($list).';');
    $result = '<script>window.list_'.$config_name.' = '.json_encode($list).';</script>';
    foreach ($list as $element) {
        $id = $config_name.'-'.$idx;
        $result .= '
        <div style="margin-bottom:5px;" id="item_'.$id.'">
        <input type="text" autocomplete="off" disabled id="list_'.$id.'" class="form-control txtin" style="width:80%;float:left;margin-right:10px" value="'.htmlspecialchars($element).'">
        <div class="btn btn-danger" style="cursor:pointer;padding-top:10px;padding-left:10px;" title="remove list element" onclick="remove_list(\''.$config_name.'\', \''.htmlspecialchars($element).'\', '.$idx.")\"><img src=\"$assets/trash.svg\" class=\"orange\" width=\"16\"></div></div>"; 
        $idx++;
    }
    $result .= '
    <div style="margin-bottom:5px;">
    <input type="text" id="new_'.$config_name.'" autocomplete="off" class="form-control txtin" style="width:80%;float:left;margin-right:10px" value="" placeholder="new entry">
    <div class="btn btn-success" style="cursor:pointer;padding-top:10px;padding-left:10px;" title="add new list element" onclick="add_list(\''.$config_name.'\')"><span class="fe fe-plus"></span></div>'; 
    return $result;
}




function country_enricher(array $country_info): callable
{
    return function (?array $input) use ($country_info): ?array {
        if (!empty($input)) {
            $code = ip_to_country($input['request']['ip'] ?? $input['ip'] ?? '');
            $input['country'] = $country_info[$code];
        }
        return $input;
    };
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

function isdis()
{
    static $result = NULL;
    if ($result === NULL) {
        $result = is_writeable(\BitFire\WAF_INI) && is_writeable(\BitFire\WAF_ROOT . "config.ini.php");
    }
    return ($result) ? " " : "disabled ";
}


function url_to_path($url)
{
    $idx = strpos($url, "/");
    return substr($url, $idx);
}



// find a plugin / theme version number located in $path
function version_from_path(string $path) {
    $package_fn = find_fn("package_to_ver");
    $files = find_const_arr("PACKAGE_FILES");

    foreach($files as $file) {
        $file_path = "{$path}/{$file}";
        if (file_exists($file_path)) {
            $version = FileData::new($file_path)->read()->reduce($package_fn, "");
            if ($version) { return $version; }
        }
    }
    return "";
}
 
function dump_dirs() : array {
    // todo root maybe null
    $root = \BitFireSvr\cms_root();
    $root_ver = \BitFireSvr\get_wordpress_version($root);
    if ($root == NULL) { return NULL; }

    $dir_list_fn = find_fn("malware_scan_dirs");
    $all_paths = $dir_list_fn($root);

    $dir_versions = array_add_value($all_paths, '\BitFire\version_from_path');
    $dir_versions["{$root}wp-includes"] = $root_ver;
    $dir_versions["{$root}wp-admin"] = $root_ver;
    return $dir_versions;
}


function dump_hashes()
{
    $root = \BitFireSvr\cms_root();
    $ver = get_wordpress_version($root);
    
    if ($root == NULL) { return NULL; }

    $all_roots = glob("$root/*.php");
    $list1 = array_filter($all_roots, function($x) { return !ends_with($x, "wp-config.php"); });
    $all_plugroot = glob(CFG::str("wp_contentdir")."/plugins/*.php");
    $all_themeroot = glob(CFG::str("wp_contentdir")."/themes/*.php");

    $hash_fn = BINDR('\BitFireSvr\hash_file2', $root, "", find_fn('file_type'));
    $hashes = array_map($hash_fn, array_merge($list1, $all_plugroot, $all_themeroot));
    $h2 = en_json(["ver" => $ver, "files" => array_filter($hashes)]);
    $encoded = base64_encode($h2);

    // send these hashes to the server for checking against the database
    //$result = httpp(APP."hash_compare.php", \base64_encode(en_json($hashes)), array("Content-Type" => "application/json"));
    $result = httpp(APP."hash_compare.php", $encoded, array("Content-Type" => "application/json"));

    // decode the result of the server test
    $decoded = un_json($result);

    $allowed = FileData::new(\BitFire\WAF_ROOT."cache/hashes.json")->read()->unjson()->lines;
    $allow_map = [];
    foreach ($allowed as $file) { $allow_map[$file["trim"]] = $file["path"]; }


    // remove files that passed check
    $filtered = array_filter($decoded, function ($file) use ($allow_map) {
        $pass = $file['r'] !== "PASS";
        if ($pass) {
            $pass = ($allow_map[$file['crc_trim']]??0) > 0 ? false : true;
        }
        
        return $pass;
    });


    $num_files = count($hashes);
    $ver = \BitFireSvr\get_wordpress_version($root);
    $enrich_fn  = BINDL('\BitFire\enrich_hashes', $ver, $root);
    $enriched = array("count" => $num_files, "root" => $root, "files" => array_map($enrich_fn, $filtered));

    return $enriched;
}

function serve_malware()
{
    // authentication guard
    validate_auth()->run();


    // for reading php files
    if (CFG::enabled("FPL") && function_exists("\BitFirePRO\site_unlock")) { 
        \BitFirePro\site_unlock();
    }
    $config = map_mapvalue(Config::$_options, '\BitFire\alert_or_block');
    $config['security_headers_enabled'] = ($config['security_headers_enabled'] === "block") ? "true" : "false";


    error_reporting(E_ERROR | E_PARSE);

    $file_list = dump_hashes();

    $dir_list = dump_dirs();


    $is_free = (strlen(CFG::str("pro_key")) < 20);
    $root = \BitFireSvr\cms_root();
    $data = array();

    //$assets = (defined("WPINC")) ? CFG::str("wp_contenturl")."/plugins/bitfire/public/" : "https://bitfire.co/assets/";
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
    $data['wp_ver'] = \BitFireSvr\get_wordpress_version($root);
    $data['file_count'] = $file_list['count'];
    $data['file_list_json'] = en_json(compact_array($file_list['files']));
    $data['dir_ver_json'] = en_json($dir_list);
    $data['is_free'] = $is_free;
    $data['dir_list_json'] = en_json(array_keys($dir_list));
    $data['show_diff1'] = ($is_free) ? "\nalert('d1 Upgrade to PRO to access over 10,000,000 WordPress file datapoints and view and repair these file changes');\n" : "\nout.classList.toggle('collapse');\n";
    $data['show_diff2'] = (!$is_free) ? "\ne.innerHTML = html;\ne2.innerText = line_nums.trim();\n" : "";
    $root = \BitFireSvr\cms_root();
    $data["total_files"] = get_file_count($root);

    $view = ($root == "") ? "nohashes.html" : "hashes.html";

    render_view(\BitFire\WAF_ROOT."views/$view", "BitFire Malware Scanner", $data)->run();
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
function dashboard_url() : string {
    trace("self_url");
    // handle all other cases.  we want to recreate our exact url 
    // to handle all cases WITHOUT bitfire parameters...
    $url = parse_url(filter_input(INPUT_SERVER, 'REQUEST_URI', FILTER_SANITIZE_URL));
    $get = ['1' => '0'];
    foreach($_GET as $k => $v) {
        $get[urldecode($k)] = urldecode($v);
    }
    unset($get['BITFIRE_WP_PAGE']);
    unset($get['BITFIRE_PAGE']);
    unset($get['tooltip']);
    return $url['path'] . '?' . http_build_query($get);
}


function render_view(string $view_filename, string $page_name, array $variables = []) : Effect {
    
    $variables['self'] = find_fn("dashboard_url")();
    $public = CFG::str("wp_contenturl")."/plugins/bitfire/public/";

    $is_free = (strlen(Config::str('pro_key')) < 20);
    // inject common variables and extract at the end
    $variables['license'] = CFG::str('pro_key', "unlicensed");
    $variables['font_path'] = (defined("WPINC")) ? CFG::str("wp_contenturl")."/plugins/bitfire/public" : "https://bitfire.co/dash/fonts/cerebrisans";
    $variables['is_wordpress'] = !empty(\BitFireSvr\cms_root());
    $variables['page'] = (defined("WPINC")) ? "BITFIRE_WP_PAGE" : "BITFIRE_PAGE";
    $variables['api_code'] = make_code(CFG::str("secret"));
    $variables['api'] = BITFIRE_COMMAND;
    $variables['password_reset'] = (CFG::str('password') === 'default') || (CFG::str('password') === 'bitfire!');
    $variables['is_free'] = b2s($is_free);
    $variables['llang'] = "en-US";
    $variables['public'] = $public;
    $variables['assets'] = (defined("WPINC")) ? CFG::str("wp_contenturl")."/plugins/bitfire/public/" : "https://bitfire.co/assets/";
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
    // handle old "include" style views and new templates
    $effect = Effect::new();



    if (ends_with($view_filename, "html")) {
        if (CFG::enabled("dashboard-usage")) {
            $variables['gtag']  = file_get_contents(\BitFire\WAF_ROOT."views/gtag.html");
        }
        $effect->out(render_file($view_filename, $variables));
    }

    // if we don't have wordpress, then wrap the content in our skin
    if (!defined("WPINC")) {
        // save current content
        $out = $effect->read_out();
        $variables["maincontent"] = $out;
        // render the skin with old content
        $effect->out(render_file(\BitFire\WAF_ROOT."views/skin.html", $variables), ENCODE_RAW, true);
    }

    return $effect;
}


function serve_settings() {
    // authentication guard
    validate_auth()->run();

    $view = (CFG::disabled("wizard", false)) ? "wizard.html" : "settings.html";

    //"dashboard_path" => $dashboard_path,
    render_view(\BitFire\WAF_ROOT . "views/$view", "BitFire Settings", array_merge(CFG::$_options, array(
        "auto_start" => CFG::str("auto_start"),
		//"theme_css" => file_get_contents(\BitFire\WAF_ROOT."public/theme.min.css"). file_get_contents(\BitFire\WAF_ROOT."public/theme.bundle.css"),
        "valid_domains_html" => BitFireList_text_inputs("valid_domains"),
        "hide_shmop" => (function_exists("shmop_open")) ? "" : "hidden",
        "hide_apcu" => (function_exists("apcu_store")) ? "" : "hidden",
        "hide_shm" => (function_exists("shm_put_var")) ? "" : "hidden"
    )))->run();
}

function serve_advanced() {
    // authentication guard
    validate_auth()->run();
    $data = ["mfa" => defined("WPINC") ? "Enable multi factor authentication. Add MFA phone numbers in user editor." :
        "Multi Factor Authentication is only available in the WordPress plugin. Reinstall the plugin to enable.",
        "show_mfa" => (defined("WPINC")) ? "" : "hidden",
        "mfa_class" => (defined("WPINC")) ? "text-muted" : "text-danger"];
    //"dashboard_path" => $dashboard_path,
    render_view(\BitFire\WAF_ROOT . "views/advanced.html", "BitFire Advanced", array_merge(CFG::$_options, $data))->run();
}




/**
 * auth on basic auth string or wordpress is admin
 * @param string $raw_pw the password to validate against Config::password
 * @return Effect validation effect. after run, ensured to be authenticated
 */
function validate_auth() : Effect {

    // ensure that the server configuration is complete...
    if (CFG::disabled("configured")) { \BitFireSVR\bf_activation_effect()->run(); }

    // run the initial password setup if the password is not configured
    if (CFG::str("password") == "configure") {
        render_view(\BitFire\WAF_ROOT."views/setup.html", "BitFire Setup")->run();
    }

    return \BitFire\verify_admin_password();
}


function enrich_alert(array $report, array $exceptions, array $whitelist) : array{
    assert(isset($report["block"]), "enrich_alert: report must have a block");
    $t = time();

    $cl = \BitFire\code_class($report['block']['code']);
    $report['block']['message_class'] = MESSAGE_CLASS[$cl];
    $test_exception = new \BitFire\Exception($report['block']['code'], 'x', NULL, $report['request']['path']);

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
    $has_exception = (count($exceptions) > count($filtered_list));
    if ($cl == 24000) {
        $crc = "crc".crc32($report['request']['agent']);
        $has_exception = array_key_exists($crc, $whitelist);
    }

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
    $file_name = \BitFire\WAF_ROOT."exceptions.json";
    $exceptions = FileData::new($file_name)->read()->unjson()->map(function ($x) {
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
    $complete = CFG::int("dynamic-exceptions");
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
        "checked" => ($enabled) ? "checked" : ""
    ];

    render_view(\BitFire\WAF_ROOT."views/exceptions.html", "BitFire Blocking Exceptions", $data)->run();
}


/**
 * TODO: split this up into multiple functions
 */
function serve_dashboard() :void
{
    // handle dashboard wizard
    if (CFG::disabled("wizard") && !isset($_GET['tooltip'])) {
       serve_settings();
       return;
    }

    // authentication guard
    validate_auth()->run();
    
    $block_page_num = intval($_GET["block_page_num"]??0);
    $alert_page_num = intval($_GET["alert_page_num"]??0);
    $data = [
        "block_page_num" => max(0, $block_page_num),
        "alert_page_num" => max(0, $alert_page_num)
    ];

    $country_fn = country_enricher(\ThreadFin\un_json(file_get_contents(\BitFire\WAF_ROOT . "cache/country.json")));

    // load all alert data
    // TODO: make dry
    $report_file = \ThreadFin\FileData::new(CFG::file(CONFIG_REPORT_FILE))
        ->read();

    $report_count = $report_file->num_lines;
    debug("report count: $report_count, page: $alert_page_num, size: " . PAGE_SZ);
    $report_file->apply(BINDR('\BitFire\remove_lines', 400))
        ->apply_ln('array_reverse')
        ->apply_ln(BINDR('array_slice', $alert_page_num * PAGE_SZ, PAGE_SZ, false))
        ->map('\ThreadFin\un_json')
        ->map($country_fn);
    $reporting = $report_file->lines;
    // calculate number of alert pages
    //$report_count = $report_file->num_lines;
    $data["report_count"] = $report_count;
    $data["report_range"] = ($alert_page_num * PAGE_SZ) . " - " . ($alert_page_num * PAGE_SZ) + PAGE_SZ;
    $data["report_pages"] = ceil($report_count / PAGE_SZ);
    $data["alerts"] = [];
    $data["access"] = defined("WPINC") ? "You can access the dashboard by clicking the BitFire icon in the admin bar." : "You can access the dashboard by visiting " . CFG::str("dashboard_path");

    $exceptions = load_exceptions();
    // this will create a $config array from whitelist agents
    $config = ["botwhitelist" => []];
    //@include (\BitFire\WAF_ROOT."cache/whitelist_agents.ini.php");
    $config = array_merge($config, \parse_ini_file(\BitFire\WAF_ROOT."cache/whitelist_agents.ini"));
    array_map(function($line) use (&$data, $exceptions, $config) {
        if (isset($line["block"])) {
            $data["alerts"][] = enrich_alert($line, $exceptions, $config["botwhitelist"]);
        }
    }, $reporting);

    // add alerts
    $data['alerts_json'] = json_encode($data["alerts"], JSON_HEX_APOS);



    // load all alert data
    $block_file = \ThreadFin\FileData::new(CFG::file(CONFIG_BLOCK_FILE))
        ->read()
        ->apply(BINDR('\BitFire\remove_lines', 400))
        ->apply_ln('array_reverse')
        ->map('\ThreadFin\un_json');
    $block_count = $block_file->num_lines; // need block count before filtering pagination
    $blocking_full = $block_file->lines;
    $block_file->apply_ln(BINDR('array_slice', $block_page_num * PAGE_SZ, PAGE_SZ, false))
        ->map($country_fn);
    $blocking = $block_file->lines;

    // calculate number of alert pages
    $data["block_count"] = $block_count;
    //$last = min([(($block_count / PAGE_SZ)), $block_count]);
    $data["block_range"] = ($block_page_num * PAGE_SZ) . " - " . ($block_page_num * PAGE_SZ) + PAGE_SZ;
    $data["block_pages"] = ceil($block_count / PAGE_SZ);
    $data["blocks"] = [];

    $exceptions = load_exceptions();
    array_map(function($line) use (&$data, $exceptions, $config) {
        if (isset($line["block"])) {
            $data["blocks"][] = enrich_alert($line, $exceptions, $config["botwhitelist"]);
        }
    }, $blocking);

    // add alerts
    $data['blocks_json'] = en_json($data["blocks"]);



    $check_day = time() - DAY;
    $block_24 = array_filter($blocking_full, function ($x) use ($check_day) {
        return isset($x['tv']) && $x['tv'] > $check_day;
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
        $data['plugin_alerts'] = "";
        foreach ($alerts as $alert) {
            $data['plugin_alerts'] = "<div style='border-left: 5px solid #d63638; padding-left: 1rem;'>
            <span class='dashicons dashicons-admin-plugins' data-code='f485'></span> {$alert}</div>\n";
        }
    }

    //$data["theme_css"] = file_get_contents(\BitFire\WAF_ROOT."public/theme.min.css"). file_get_contents(\BitFire\WAF_ROOT."public/theme.bundle.css");
    render_view(\BitFire\WAF_ROOT."views/dash.html", "BitFire Alert Dashboard", $data)->run();
}


// ensure that passwords are always hashed
if (strlen(CFG::str("password")) < 40 && CFG::str("password") != "disabled" && CFG::str("password") != "configure") {
    $hashed = hash("sha3-256", CFG::str("password"));
    update_ini_value("password", $hashed)->run();
}

