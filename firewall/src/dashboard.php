<?php

namespace BitFire;

use BitFire\Config as CFG;
use ThreadFin\FileData;
use ThreadFin\Effect;

use const ThreadFin\DAY;

use function BitFire\list_text_inputs as BitFireList_text_inputs;
use function BitFireSvr\get_wordpress_version;
use function ThreadFin\array_add_value;
use function ThreadFin\b2s;
use function ThreadFin\compact_array;
use function ThreadFin\compose;
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
// this case is impossible to hit, but it's better to be safe

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
    if ($file->num_lines > $num_lines) { 
        $file->lines = array_slice($file->lines, -$num_lines);
        $content = join("\n", $file->lines);
        file_put_contents($file->filename, $content, LOCK_EX);
    }
    return $file;
}




/** @depricated */
function text_input(string $config_name, string $styles="", string $type="text") :string {
    $value = CFG::str($config_name);
    $str = '
    <div id="%s_spin" class="spinner-border text-success spinner-border-sm left mt-1 mr-2 hidden" role="status">
      <span class="visually-hidden">Saving...</span>
    </div>
    <input type="%s" class="form-control txtin" id="%s_text" autocomplete="off" onchange="update_str(\'%s\')" value="%s" style="%s">';
    return sprintf($str, $config_name, $type, $config_name, $config_name, $value, $styles);

}


function toggle_report(string $config_name, string $tooltip = "", bool $onoff = false) :string {
    $alert = alert_or_block(CFG::str($config_name));
    $check1 = ($alert == "report") ? "checked" : "";
    $check2 = ($alert == "on") ? "checked" : "";
    if (empty($tooltip)) { $tooltip == "Enable / Disable " . $config_name; }
    $tail1 = ($onoff) ? "" : " in alert mode only";
    $tail2 = ($onoff) ? "" : " in full blocking";
    $tool1 = 'data-bs-toggle="tooltip" data-bs-placement="top" title="'.$tooltip.$tail1.'"';
    $tool2 = 'data-bs-toggle="tooltip" data-bs-placement="top" title="'.$tooltip.$tail2.'"';
    $format = 
    '<div id="%s_spin" class="spinner-border text-success spinner-border-sm left mt-1 mr-2 hidden" role="status">
      <span class="visually-hidden">Saving...</span>
    </div>';
    $format .= ($onoff == false) ? '<div class="form-check form-switch left">
        <input class="form-check-input warning" id="%s_report" autocomplete="off" type="checkbox" onclick="return toggle_report(\'%s\', true)" %s %s>
    </div>' : '<!-- %s %s %s %s -->';

    $format .= '
    <div class="form-switch right">
        <input class="form-check-input success" autocomplete="off" id="%s_block" type="checkbox" onclick="return toggle_report(\'%s\', false)" %s %s>
    </div><script type="text/javascript">window.CONFIG_LIST["%s"] = "%s"; </script>';
    return sprintf($format, $config_name, $config_name, $config_name, $check1, $tool1, $config_name, $config_name, $check2, $tool2, $config_name, $alert);
}

function list_text_inputs(string $config_name) :string {

    $assets = (CFG::enabled("wp_contenturl")) ? CFG::str("wp_contenturl")."/plugins/bitfire/public/" : "https://bitfire.co/assets/"; // DUP
    $list = CFG::arr($config_name);
    $idx = 0;
    $result = '<script type="text/javascript">window.list_'.$config_name.' = '.json_encode($list).';</script>'."\n";
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

/**
 * find the IP DB for a given IP
 * TODO: split into more files, improve distribution
 * PURE: IDEMPOTENT, REFERENTIAL INTEGRITY
 */
function ip_to_file(int $ip_num) : string {
    $n = floor($ip_num/0x5F5E100);
	return "cache/ip.$n.bin";
}

/**
 * ugly AF returns the country number
 * depends on IP DB
 * NOT PURE, should this be refactored to FileData ?
 */
function ip_to_country(?string $ip) : int {
    if (empty($ip)) { return 0; }
	$n = ip2long($ip);
    if ($n === false) { return 0; }
	$d = file_get_contents(\BitFire\WAF_ROOT.ip_to_file($n));
	$len = strlen($d);
	$off = 0;
	while ($off < $len) {
		$data = unpack("Vs/Ve/Cc", $d, $off);
		if ($data['s'] <= $n && $data['e'] >= $n) { return $data['c']; }
		$off += 9;
	}
	return 0;
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

/**
 * return sub directories for a single directory. non-recursive. non-pure
 * @param string $dirname to search
 * @return array 
 */
function get_subdirs(string $dirname) : array {
    $dirs = array();
    if (!file_exists($dirname)) { debug("unable to find subdirs [$dirname]"); }

    if ($dh = \opendir($dirname)) {
        while(($file = \readdir($dh)) !== false) {
            $path = $dirname . '/' . $file;
            if (!$file || $file === '.' || $file === '..') {
                continue;
            }
            if (is_dir($path) && !is_link($path)) {
                $dirs[] = $path;
			}
        }
        \closedir($dh);
    }

    return $dirs;
}


// find a plugin / theme version number located in $path
function version_from_path(string $path) {
    $package_fn = find_fn("package_to_ver");
    $files = find_const_arr("PACKAGE_FILES");

    foreach($files as $file) {
        $file_path = "{$path}/{$file}";
        if (file_exists($file_path)) {
            return FileData::new($file_path)->read()->reduce($package_fn, "");
        }
    }
    return "";
}

 
function dump_dirs() : array {
    // todo root maybe null
    $root = \BitFireSvr\cms_root();
    $rootver = \BitFireSvr\get_wordpress_version($root);
    if ($root == NULL) { return NULL; }

    $dir_list_fn = find_fn("malware_scan_dirs");
    $all_paths = $dir_list_fn($root);

    $dir_versions = array_add_value($all_paths, '\BitFire\version_from_path');
    $dir_versions["{$root}wp-includes"] = $rootver;
    $dir_versions["{$root}wp-admin"] = $rootver;
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

    //$files = FileData::new(\BitFire\WAF_ROOT."cache/file_roots.json")->read()->unjson()->lines;
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
    $pw = filter_input(INPUT_SERVER, "PHP_AUTH_PW", FILTER_SANITIZE_URL);
    validate_auth($pw)->run();


    $config = map_mapvalue(Config::$_options, '\BitFire\alert_or_block');
    $config['security_headers_enabled'] = ($config['security_headers_enabled'] === "block") ? "true" : "false";


    error_reporting(E_ERROR | E_PARSE);

    $file_list = dump_hashes();

    $dir_list = dump_dirs();


    $is_free = (strlen(CFG::str("pro_key")) < 20);
    $root = \BitFireSvr\cms_root();
    $data = array();

    $assets = (CFG::enabled("wp_contentdir")) ? CFG::str("wp_contentdir")."/plugins/bitfire/public/" : "https://bitfire.co/assets/";
    //$f2 = "{$assets}vs2015.css";
    $f3 = "{$assets}prism2.css";
    debug("F2 [$f3]");
    $f4 = \BitFire\WAF_ROOT . "public/theme.min.css";
    $f5 = \BitFire\WAF_ROOT . "public/theme.bundle.css";
    $data['theme_css'] = file_get_contents($f3) . file_get_contents($f4) . file_get_contents($f5);
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

    render_view(\BitFire\WAF_ROOT."views/hashes.html", "BitFire Malware Scanner", $data)->run();
    die();
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
    return $url['path'] . '?' . http_build_query($get);
}


function render_view(string $view_filename, string $page_name, array $variables = []) : Effect {
    
    $variables['self'] = find_fn("dashboard_url")();

    $is_free = (strlen(Config::str('pro_key')) < 20);
    // inject common variables and extract at the end
    $variables['license'] = CFG::str('pro_key', "unlicensed");
    $variables['font_path'] = (CFG::enabled("wp_contenturl")) ? CFG::str("wp_contenturl")."/plugins/bitfire/public" : "https://bitfire.co/dash/fonts/cerebrisans";
    $variables['is_wordpress'] = !empty(\BitFireSvr\cms_root());
    $variables['page'] = ($variables["is_wordpress"]) ? "BITFIRE_WP_PAGE" : "BITFIRE_PAGE";
    $variables['api_code'] = make_code(CFG::str("secret"));
    $variables['api'] = BITFIRE_COMMAND;
    $variables['password_reset'] = (CFG::str('password') === 'default') || (CFG::str('password') === 'bitfire!');
    $variables['is_free'] = b2s($is_free);
    $variables['llang'] = "en-US";
    $variables['assets'] = (CFG::enabled("wp_contenturl")) ? CFG::str("wp_contenturl")."/plugins/bitfire/public/" : "https://bitfire.co/assets/";
    $variables['version'] = BITFIRE_VER;
    $variables['sym_version'] = BITFIRE_SYM_VER;
    $variables['showfree_class'] = $is_free ? "" : "hidden";
    $variables['hidefree_class'] = $is_free ? "hidden" : "";
    $variables['release'] = (($is_free)  ? "FREE" : "PRO") . " Release " . BITFIRE_SYM_VER;
    $variables['underscore_path'] = (defined("WPINC")) ? "/wp-includes/js/underscore.min.js" : "https://bitfire.co/assets/js/unders"."core.min.js";
    $variables['show_wp_class'] = (defined("WPINC")) ? "" : "hidden";
    $variables['jquery'] = (defined("WPINC")) ? "" : "https://bitfire.co/assets/js/jqu"."ery/jqu"."ery.js";
    $variables['need_reset'] = b2s((CFG::str('password') === 'bitfire!'));
    $variables['gtag'] = '';
    if (CFG::enabled("dashboard-usage")) {
        $variables['gtag'] = '<script async src="https://www.googletagmanager.com/gtag/js?id=G-2YZ4QCZJHC"></script> <script> window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);} gtag("js", new Date()); gtag("config", "G-2YZ4QCZJHC"); </script>';
    }


    // handle old "include" style views and new templates
    $effect = Effect::new()->exit(true);
    if (ends_with($view_filename, "html")) {
        $effect->out(render_file($view_filename, $variables));
    }

    return $effect;
}


function serve_settings() {
    // authentication guard
    $pw = filter_input(INPUT_SERVER, "PHP_AUTH_PW", FILTER_SANITIZE_URL);
    validate_auth($pw)->run();

    //"dashboard_path" => $dashboard_path,
    render_view(\BitFire\WAF_ROOT . "views/settings.html", "BitFire Settings", array_merge(CFG::$_options, array(
        "auto_start" => CFG::str("auto_start"),
		"theme_css" => file_get_contents(\BitFire\WAF_ROOT."public/theme.min.css"). file_get_contents(\BitFire\WAF_ROOT."public/theme.bundle.css"),
        "valid_domains_html" => BitFireList_text_inputs("valid_domains"),
        "hide_shmop" => (function_exists("shmop_open")) ? "" : "hidden",
        "hide_apcu" => (function_exists("apcu_store")) ? "" : "hidden",
        "hide_shm" => (function_exists("shm_put_var")) ? "" : "hidden"
    )))->run();
}

function serve_advanced() {
    // authentication guard
    $pw = filter_input(INPUT_SERVER, "PHP_AUTH_PW", FILTER_SANITIZE_URL);
    validate_auth($pw)->run();

    //"dashboard_path" => $dashboard_path,
    render_view(\BitFire\WAF_ROOT . "views/advanced.html", "BitFire Advanced", array_merge(CFG::$_options, array(
		"theme_css" => file_get_contents(\BitFire\WAF_ROOT."public/theme.min.css"). file_get_contents(\BitFire\WAF_ROOT."public/theme.bundle.css")
    )))->run();
}




/**
 * auth on bastic auth string or wordpress is admin
 * @param string $raw_pw the password to validate against Config::password
 * @return Effect validation effect. after run, ensured to be authenticated
 */
function validate_auth(?string $raw_pw) : Effect {
    $effect = Effect::new();
    //$effect = cache_prevent();
    // disable caching for auth pages
    $effect->response_code(203);

    // prefeer plugin authentication first
    if (function_exists("BitFirePlugin\is_admin") && \BitFirePlugin\is_admin()) {
        return $effect;
    }



    // inspect the cookie wp admin status, we pass auth if wp value is admin(2)
    // TODO: make this a function on the BitFire class
    $cookie = BitFire::get_instance()->cookie;
    if ($cookie != null) {
        if ($cookie->extract("wp")->value("int") == 2) {
            return $effect;
        }
    }
    // if we don't have a password, or the password does not match
    // or the password function is disabled
    // create an effect to force authentication and exit
    if (strlen($raw_pw) < 2 ||
        CFG::str("password") == "disabled" ||
        (hash("sha3-256", $raw_pw) !== CFG::str('password')) &&
        (hash("sha3-256", $raw_pw) !== hash("sha3-256", CFG::str('password')))) {

        $effect->header("WWW-Authenticate", 'Basic realm="BitFire", charset="UTF-8"');
        $effect->response_code(401);
        $effect->exit(true);
    }

    return $effect;
}

function enrich_alerts(array $reporting) : array{
    $t = time();
    $exceptions = \BitFire\load_exceptions();

    for($i=0,$m=count($reporting); $i<$m; $i++) {
        if (!isset($reporting[$i])) { continue; }
        $cl = \BitFire\code_class($reporting[$i]['block']['code']);
        $reporting[$i]['block']['message_class'] = MESSAGE_CLASS[$cl];
        $test_exception = new \BitFire\Exception($reporting[$i]['block']['code'], 'x', NULL, $reporting[$i]['request']['path']);

        $reporting[$i]['type_img'] = CODE_CLASS[$cl];
        $browser = \BitFireBot\parse_agent($reporting[$i]['request']['agent']);
        if (!$browser->bot && !$browser->browser) {
            $browser->browser = "unknown";
        }
        $reporting[$i]['browser'] = $browser;
        $reporting[$i]['agent_img'] = ($browser->bot) ? 'robot.svg' : ($browser->browser . ".png");
        $reporting[$i]['country_img'] = strtolower($reporting[$i]['country']) . ".svg";
        $reporting[$i]['country_alt'] = strtolower($reporting[$i]['country']);
        if ($reporting[$i]['country_img'] == "-.svg") {
            $reporting[$i]['country_img'] = "us.svg";
        }

        $reporting[$i]['when'] = human_date($line['tv']??$t);


        // filter out the "would be" exception for this alert, and compare if we removed the exception
        $filtered_list = array_filter($exceptions, compose("\ThreadFin\\not", BINDR("\BitFire\match_exception", $test_exception)));
        $has_exception = (count($exceptions) > count($filtered_list));
        $reporting[$i]['exception_class'] = ($has_exception) ? "warning" : "secondary";
        $reporting[$i]['exception_img'] = ($has_exception) ? "bandage.svg" : "fix.svg";
        $reporting[$i]['exception_title'] = ($has_exception) ?
        "exception already added for this block" :
        "add exception for [" . MESSAGE_CLASS[$cl] . '] url: [' . $reporting[$i]['request']['path']. ']';
    }
    return $reporting;
}

function enrich_alert(array $report, array $exceptions) : array{
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
    $report['exception_class'] = ($has_exception) ? "warning" : "secondary";
    $report['exception_img'] = ($has_exception) ? "bandage.svg" : "fix.svg";
    $report['exception_title'] = ($has_exception) ?
    "exception already added for this block" :
    "add exception for [" . MESSAGE_CLASS[$cl] . '] url: [' . $report['request']['path']. ']';

    return $report;
}



/**
 * TODO: split this up into multiple functions
 */
function serve_dashboard() :void
{
    // authentication guard
    $pw = filter_input(INPUT_SERVER, "PHP_AUTH_PW", FILTER_SANITIZE_URL);
    validate_auth($pw)->run();
    
    $page = filter_input(INPUT_GET, "page_num", FILTER_VALIDATE_INT);
    $data = [];

    $country_fn = country_enricher(\ThreadFin\un_json(file_get_contents(\BitFire\WAF_ROOT . "cache/country.json")));

    // load all alert data
    // TODO: make dry
    $report_file = \ThreadFin\FileData::new(CFG::file(CONFIG_REPORT_FILE))
        ->read()
        ->apply(BINDR('\BitFire\remove_lines', 400))
        ->apply_ln('array_reverse')
        ->apply_ln(BINDR('array_slice', $page * PAGE_SZ, PAGE_SZ, false))
        ->map('\ThreadFin\un_json')
        ->map($country_fn);
    $reporting = $report_file->lines;

    // calcualte number of alert pages
    $report_count = $report_file->num_lines;
    $data["report_pages"] = $report_count / PAGE_SZ;
    $data["alerts"] = [];

    $exceptions = load_exceptions();
    array_map(function($line) use (&$data, $exceptions) {
        if (isset($line["block"])) {
            $data["alerts"][] = enrich_alert($line, $exceptions);
        }
    }, $reporting);

    // add alerts
    $data['alerts_json'] = \ThreadFin\en_json($data["alerts"]);



    // load all alert data
    $block_file = \ThreadFin\FileData::new(CFG::file(CONFIG_BLOCK_FILE))
        ->read()
        ->apply(BINDR('\BitFire\remove_lines', 400))
        ->apply_ln('array_reverse')
        ->apply_ln(BINDR('array_slice', $page * PAGE_SZ, PAGE_SZ, false))
        ->map('\ThreadFin\un_json')
        ->map($country_fn);
    $blocking = $block_file->lines;

    // calcualte number of alert pages
    $block_count = $block_file->num_lines;
    $data["block_pages"] = $block_count / PAGE_SZ;
    $data["blocks"] = [];

    $exceptions = load_exceptions();
    array_map(function($line) use (&$data, $exceptions) {
        if (isset($line["block"])) {
            $data["blocks"][] = enrich_alert($line, $exceptions);
        }
    }, $blocking);

    // add alerts
    $data['blocks_json'] = en_json($data["blocks"]);



    $check_day = time() - DAY;
    $block_24 = array_filter($blocking, function ($x) use ($check_day) {
        return isset($x['tv']) && $x['tv'] > $check_day;
    });
    $data['block_count_24'] = count($block_24);
    $blocks = array_slice($blocking, $page * PAGE_SZ, PAGE_SZ);


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
        $carry[$x['country']] = isset($carry[$x['country']]) ? $carry[$x['country']] + 1 : 1;
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

    $data["theme_css"] = file_get_contents(\BitFire\WAF_ROOT."public/theme.min.css"). file_get_contents(\BitFire\WAF_ROOT."public/theme.bundle.css");
    render_view(\BitFire\WAF_ROOT."views/dash.html", "BitFire Alert Dashboard", $data)->run();
    die();
}
