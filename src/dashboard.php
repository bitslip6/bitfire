<?php

namespace BitFire;

use \BitFire\Config as CFG;
use FunctionalWP\Effect;
use TF\Effect as TFEffect;

use function TF\file_recurse;

require_once WAF_DIR . "src/api.php";
require_once WAF_DIR . "src/const.php";
require_once WAF_DIR . "src/wordpress.php";
require_once WAF_DIR . "src/server.php";

const PAGE_SZ = 30;

/*
//\TF\dbg($_SERVER);
$roots = \BitFire\find_wordpress_root($_SERVER['DOCUMENT_ROOT']);
$result = array();
foreach ($roots as $root) {
    $r = get_wordpress_hashes($root);
	//\TF\dbg($r);
	//$optional_headers['Content-Type'] = "application/x-www-form-urlencoded";
	$header = array('Content-Type' => "application/json");
    $x = \TF\bit_http_request("POST", "http://192.168.0.5:8080/wp.php", \TF\en_json($r), $header);
    \TF\dbg($x);
    //$result[$root] = $r;
}
//echo \TF\en_json($result);
//die();
\TF\dbg($result);
*/

function str_replace_first($from, $to, $content)
{
    $from = '/'.preg_quote($from, '/').'/';
    return preg_replace($from, $to, $content, 1);
}

/**
 * used in settings.html
 * @return void 
 */
function chked(string $config_name) :void {
    if (Config::enabled($config_name)) { echo "checked"; }
}

function text_input(string $config_name, string $styles="", string $type="text") :string {
    $value = CFG::str($config_name);
    $str = '
    <div id="%s_spin" class="spinner-border text-success spinner-border-sm left mt-1 mr-2 hidden" role="status">
      <span class="visually-hidden">Saving...</span>
    </div>
    <input type="%s" class="form-control txtin" id="%s_text" onchange="update_str(\'%s\')" value="%s" style="%s">';
    return sprintf($str, $config_name, $type, $config_name, $config_name, $value, $styles);

}


function toggle_report(string $config_name, string $tooltip = "", bool $onoff = false) :string {
    $alert = alert_or_block(CFG::str($config_name));
    $check1 = ($alert == "report") ? "checked" : "";
    $check2 = ($alert == "on") ? "checked" : "";
    if (empty($tooltip)) { $tooltip == $config_name; }
    $tail1 = ($onoff) ? "" : " in alert mode only";
    $tail2 = ($onoff) ? "" : " in full blocking";
    $tool1 = 'data-bs-toggle="tooltip" data-bs-placement="top" title="Enable '.$tooltip.$tail1.'"';
    $tool2 = 'data-bs-toggle="tooltip" data-bs-placement="top" title="Enable '.$tooltip.$tail2.'"';
    $format = 
    '<div id="%s_spin" class="spinner-border text-success spinner-border-sm left mt-1 mr-2 hidden" role="status">
      <span class="visually-hidden">Saving...</span>
    </div>';
    $format .= ($onoff == false) ? '<div class="form-check form-switch left">
        <input class="form-check-input warning" id="%s_report" type="checkbox" onclick="return toggle_report(\'%s\', true)" %s %s>
    </div>' : '<!-- %s %s %s %s -->';

    $format .= '
    <div class="form-switch right">
        <input class="form-check-input success" id="%s_block" type="checkbox" onclick="return toggle_report(\'%s\', false)" %s %s>
    </div><script type="text/javascript">window.CONFIG_LIST["%s"] = "%s"; </script>';
    return sprintf($format, $config_name, $config_name, $config_name, $check1, $tool1, $config_name, $config_name, $check2, $tool2, $config_name, $alert);
}

function list_text_inputs(string $config_name) :void {
    $list = CFG::arr($config_name);
    $idx = 0;
    echo '<script type="text/javascript">window.list_'.$config_name.' = '.json_encode($list).';</script>'."\n";
    foreach ($list as $element) {
        $id = $config_name.'-'.$idx;
        echo '
        <div style="margin-bottom:5px;" id="item_'.$id.'">
        <input type="text" disabled id="list_'.$id.'" class="form-control txtin" style="width:80%;float:left;margin-right:10px" value="'.$element.'">
        <div class="fe fe-trash-2 btn btn-danger" style="cursor:pointer;padding-top:10px;padding-left:10px;" title="remove list element" onclick="remove_list(\''.$config_name.'\', \''.$element.'\', '.$idx.')"></div></div>'; 
        $idx++;
    }
    echo '
    <div style="margin-bottom:5px;">
    <input type="text" id="new_'.$config_name.'" class="form-control txtin" style="width:80%;float:left;margin-right:10px" value="" placeholder="new entry">
    <div class="fe fe-plus btn btn-success" style="cursor:pointer;padding-top:10px;padding-left:10px;" title="add new list element" onclick="add_list(\''.$config_name.'\')"></div></div>'; 
}


function country_enricher(array $country_info): callable
{
    return function (?array $input) use ($country_info): ?array {
        if (!empty($input)) {
            $code = \TF\ip_to_country($input['request']['ip'] ?? $input['ip'] ?? '');
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
    $map = \TF\un_json(file_get_contents(WAF_DIR . "cache/country.json"));
    $result = array();
    foreach ($data as $report) {
        $code = \TF\ip_to_country($report['ip'] ?? '');
        $report['country'] = $map[$code];
        $result[] = $report;
    }
    return $result;
}

function isdis()
{
    static $result = NULL;
    if ($result === NULL) {
        $result = is_writeable(WAF_DIR . "config.ini") && is_writeable(WAF_DIR . "config.ini.php");
    }
    return ($result) ? " " : "disabled ";
}

function is_locked(): bool
{
    $lockfile = WAF_DIR . "/cache/locked.txt";
    if (file_exists($lockfile)) {
        $r = file_get_contents($lockfile);
        return ($r == "1") ? true : false; 
    }

    $ctr = 0;
    file_recurse($_SERVER['DOCUMENT_ROOT'], function ($file) use (&$ctr, $lockfile) {
        if (is_writeable($file)) {
            $ctr++;
            if ($ctr == 1) {
                file_put_contents($lockfile, ($ctr <= 1) ? "1" : "0");
            }
        }
    }, "/.php$/", array(), 2);
    \TF\debug("lock ctr: [$ctr]");
    return ($ctr <= 1);
}

function url_to_path($url)
{
    $idx = strpos($url, "/");
    return substr($url, $idx);
}

function get_subdirs(string $dirname) {
    $dirs = array();
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

/**
 * return the version number for a package.json or readme.txt file
 * @param mixed $path 
 * @return string 
 */
function package_to_ver($path) : string {
    $text = file_get_contents($path);
    if (preg_match("/stable tag[\'\":\s]+([\d\.]+)/i", $text, $matches)) {
        return $matches[1];
    }
    if (preg_match("/version[\'\":\s]+([\d\.]+)/i", $text, $matches)) {
        return $matches[1];
    }
    return "0";
}

 
function dump_dirs() : array {
    $root = \BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']);
    $ver = \BitFireSvr\get_wordpress_version($root);
    if ($root == NULL) { return NULL; }

    $d1 = "$root/wp-content/plugins";
    $d2 = "$root/wp-content/themes";
    $all_paths = array_merge(get_subdirs($d1), get_subdirs($d2), get_subdirs("$root/wp-includes"), get_subdirs("$root/wp-admin"));
    $all_subs = array();
    foreach ($all_paths as $full) {
        $path = str_replace($root, "", $full);
        if (file_exists("{$full}/package.json")) {
            $ver = package_to_ver("{$full}/package.json");
        }
        if (file_exists("{$full}/readme.txt")) {
            $ver = package_to_ver("{$full}/readme.txt");
        }
        $all_subs[$path] = $ver;
    };
    return $all_subs;
}

function dump_hashes()
{
    $root = \BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']);
    if ($root == NULL) { return NULL; }
    
    // get all wordpress root files
    $wp_root_files = array_map(function($x) use ($root) { return "$root/$x"; }, \BitFireWP\list_of_root_wordpress_files());
    //$wp_root_files = \TF\file_recurse("$root/wp-includes", function ($x) { return $x; }, "/.*.php/", $wp_root_files);
    //$wp_root_files = \TF\file_recurse("$root/wp-admin", function ($x) { return $x; }, "/.*.php/", $wp_root_files);


    // remove config files
    $wp_root_files = array_filter($wp_root_files, function ($x) { return !\TF\contains($x, "config"); });
    // function to hash the wp files
    $hash_fn = \TF\partial_right('\BitFireSvr\hash_file', $root, 0, "");
    // wordpress version in $root
    $ver = \BitFireSvr\get_wordpress_version($root);
    // hash filelist and store in array with root path, and version
    $hashes = array("ver" => $ver, "int" => \BitFireSvr\text_to_int($ver), "root" => $root, "files" => array_map($hash_fn,  $wp_root_files));

    // send these hashes to the server for checking against the database
    //$result = \TF\bit_http_request("POST", "https://bitfire.co/hash.php", \base64_encode(\TF\en_json($hashes)), array("Content-Type" => "application/json"));
    $result = \TF\bit_http_request("POST", "https://bitfire.co/hash_compare.php", \base64_encode(\TF\en_json($hashes)), array("Content-Type" => "application/json"));
    // decode the result of the server test
    $decoded = \TF\un_json($result);

    // remove files that passed check
    $filtered = array_filter($decoded, function ($file) {
        return $file['r'] != "PASS";
    });


    $num_files = count($wp_root_files);
    $enrich_fn  = \TF\partial('\BitFireWP\wp_enrich_wordpress_hash_diffs', $ver, $root);
    $enriched = array("ver" => $ver, "count" => $num_files, "int" => \BitFireSvr\text_to_int($ver), "root" => $root, "files" => array_map($enrich_fn, $filtered));

    return $enriched;

    /*





    $fix_files = array('ver' => $hashes['ver'], 'root' => $root, 'files' => array());
    if ($decoded && count($decoded) > 0) {
        \TF\debug("hash result len " . count($decoded));
        //print_r($decoded);
        
        for ($i=0,$m=count($decoded);$i<$m; $i++) {
            $root = $decoded[$i];
            $ver = $hashes[$i]['ver'];
            $base = $hashes[$i]['root'];
            if (is_array($root)) {
                foreach ($root as $file) {
                    $filename = trim(str_replace($base, "", $file['path']), '/');
                    $path = "https://core.svn.wordpress.org/tags/{$ver}/$filename";
                    //$parts = explode("/", $file[0]);
                    //$out = $file[4] . "/" . join("/", array_slice($parts, 3));
                    //$out = rtrim($out, "/");
                    $out = $_SERVER['DOCUMENT_ROOT'] . "/$filename";
                    $fix_files['files'][] = array('info' => $file['r'], 'url' => $path, 'expected' => $file['crc_expected'], 'actual' => $file['crc_trim'], 'size1' => $file['size'], 'size2' => $file['size2'], 'mtime' => filemtime($out), 'out' => $out);
                }
            } else {
                \TF\debug("unknown root!");
            }
        }
    } else {
        \TF\debug("hash result len 0");
    }

    //\Tf\dbg($fix_files);

    //file_put_contents(WAF_DIR . "cache/file_fix.json", \TF\en_json($fix_files));
    //exit(\TF\en_json($fix_files));
    \TF\debug("fix file len: " . count($fix_files));
    return $fix_files;
    */
}

function serve_malware(string $dashboard_path)
{
    // authentication guard
    validate_auth($_SERVER['PHP_AUTH_PW']??'')->run();

    $locked = is_locked();
    $lock_action = ($locked) ? "unlock" : "lock";

    $config_writeable = is_writeable(WAF_DIR . "config.ini") | is_writeable(WAF_DIR . "config.ini.php");
    $config = \TF\map_mapvalue(Config::$_options, '\BitFire\alert_or_block');
    $config['security_headers_enabled'] = ($config['security_headers_enabled'] === "block") ? "true" : "false";
    $config_orig = Config::$_options;


    $is_free = (strlen(Config::str('pro_key')) < 20);
    error_reporting(E_ERROR | E_PARSE);

	$reg = "#[\?&]".CFG::str("dashboard_path")."=[^\?&]+#";
	$s1 = preg_replace("#[\?&]".CFG::str("dashboard_path")."=[^\?&]+#", "", $_SERVER['REQUEST_URI']);//."&_bitfire_p=".CFG::str("secret");
	$self = preg_replace("#[\?&]BITFIRE_API=[^\?&]+#", "", $s1);
    $self = preg_replace("#[\?&].*#", "", $self);
    //$first = strpos($self,'&'); if ($first) { $self = str_replace('&', '?', $self, 1); }

    $opt_name = "Dashboard";
    $opt_link = $self . ((strpos($self,"?")>0) ? '&' : '?') . "BITFIRE_API=DASHBOARD";

    $file_list = dump_hashes();
    $dir_list = dump_dirs();
    $page_name = "BitFire Malware Scan";

    $llang = "en-US";
    $file =  WAF_DIR . "views/";
    $file .= (!$is_free && file_exists(WAF_DIR . "views/hashes-pro.html")) ? "hashes-pro.html" : "hashes.html";
    $is_wordpress = !empty(\BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']));
    exit(require $file);
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


function render_view(string $view_filename, string $page_name, ?array $variables = NULL) {
    if (!empty($variables)) {
        extract($variables);
    }

    $locked = is_locked();
    $lock_action = ($locked) ? "unlock" : "lock";

    $s1 = preg_replace("#[\?&]".CFG::str("dashboard_path")."=[^\?&]+#", "", $_SERVER['REQUEST_URI']);//."&_bitfire_p=".CFG::str("secret");
	$self = preg_replace("#[\?&]BITFIRE_API=[^\?&]+#", "", $s1);
    $self = preg_replace("#[\?&].*#", "", $self);
    $opt_name = $page_name;
    $opt_link = $self . ((strpos($self,"?")>0) ? '&' : '?') . "BITFIRE_API=MALWARESCAN";

    $password_reset = (Config::str('password') === 'default') || (Config::str('password') === 'bitfire!');
    $is_free = (strlen(Config::str('pro_key')) < 20);
    $llang = "en-US";
    $is_wordpress = !empty(\BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']));

    exit(require WAF_DIR . "views/$view_filename");
}


function serve_settings(string $dashboard_path) {
    // authentication guard
    validate_auth($_SERVER['PHP_AUTH_PW']??'')->run();

    render_view("settings.html", "BitFire Settings", array("dashboard_path" => $dashboard_path));
}


/**
 * @param string $raw_pw the password to validate against Config::password
 * @return TFEffect validation effect. after run, ensured to be authenticated
 */
function validate_auth(string $raw_pw) : \TF\Effect {
    $effect = new \TF\Effect();
    // disable caching for auth pages
    $effect->header("Cache-Control", "no-store, private, no-cache, max-age=0");
    $effect->header("Expires", gmdate('D, d M Y H:i:s \G\M\T', 100000));
    $effect->response_code(203);
    $wp_login_data = \BitFireWP\wp_get_login_cookie($_COOKIE);
    if (!empty($wp_login_data)) {
        if (\BitFireWP\wp_validate_cookie($wp_login_data, $_SERVER['DOCUMENT_ROOT']??getcwd())) {
            return $effect;
        };
    }


    // if we don't have a password, or the password does not match
    // create an effect to force authentication and exit
    if (strlen($raw_pw) < 2 ||
        (sha1($raw_pw) !== Config::str('password', 'default_password')) &&
        (sha1($raw_pw) !== sha1(Config::str('password', 'default_password')))) {

        $effect->header("WWW-Authenticate", 'Basic realm="BitFire", charset="UTF-8"');
        $effect->response_code(401);
        //$effect->header("HTTP/1.0 401 Unauthorized", NULL);
        $effect->exit(true);
    }

    return $effect;
}


/**
 * TODO: split this up into multiple functions
 */
function serve_dashboard(string $dashboard_path) :void
{
    // authentication guard
    validate_auth($_SERVER['PHP_AUTH_PW']??'')->run();
    
    if ($_GET['_infoz'] ?? '' === 'show') {
        phpinfo();
        die();
    }
    $page = intval($_GET['page'] ?? 0);

    require_once WAF_DIR . "src/botfilter.php";

    $config_writeable = is_writeable(WAF_DIR . "config.ini") && is_writeable(WAF_DIR . "config.ini.php");
    $config = \TF\map_mapvalue(Config::$_options, '\BitFire\alert_or_block');
    //$config['security_headers_enabled'] = ($config['security_headers_enabled'] === "block") ? "true" : "false";
    $config_orig = Config::$_options;
    $exceptions = \BitFire\load_exceptions();



    $report_file = \TF\FileData::new(CFG::file(CONFIG_REPORT_FILE))
        ->read()
        ->apply(\TF\partial_right('\TF\remove_lines', 400));
    $report_count = $report_file->num_lines;
        // ->filter(function ($x) { echo "[$x]\n"; return strlen($x) > 10; })
        $report_file->apply_ln(\TF\partial_right('array_slice', $page * PAGE_SZ, PAGE_SZ, false))
        ->map('\TF\un_json')
        ->map(country_enricher(\TF\un_json(file_get_contents(WAF_DIR . "cache/country.json"))));
    $reporting = $report_file->lines;

    $max_pages1 = $report_count / PAGE_SZ;




    //$report_count = count(file(Config::file(CONFIG_REPORT_FILE)));
    //$tmp = add_country(\TF\un_json_array(\TF\read_last_lines(Config::file(CONFIG_REPORT_FILE), 20, 2500)));
//$t2 = \TF\un_json_array(\TF\read_last_lines(Config::file(CONFIG_REPORT_FILE), 20, 2500));
    //$reporting = (isset($tmp[0])) ? array_reverse($tmp, true) : array();



    for($i=0,$m=count($reporting); $i<$m; $i++) {
        if (!isset($reporting[$i]['block'])) { continue; }
        $cl = \BitFire\code_class($reporting[$i]['block']['code']);
        $test_exception = new \BitFire\Exception($reporting[$i]['block']['code'], 'x', NULL, $reporting[$i]['request']['path']);

        $reporting[$i]['type_img'] = CODE_CLASS[$cl];
        $browser = \BitFireBot\parse_agent($reporting[$i]['request']['agent']);
        if (!$browser->bot && !$browser->browser) {
            $browser->browser = "chrome";
        }
        $reporting[$i]['browser'] = $browser;
        $reporting[$i]['agent_img'] = ($browser->bot) ? 'robot.svg' : ($browser->browser . ".png");
        $reporting[$i]['country_img'] = strtolower($reporting[$i]['country']) . ".svg";
        if ($reporting[$i]['country_img'] == "-.svg") {
            $reporting[$i]['country_img'] = "us.svg";
        }




        // filter out the "would be" exception for this alert, and compare if we removed the exception
        $filtered_list = array_filter($exceptions, \TF\compose("\TF\\not", \TF\partial_right("\BitFire\match_exception", $test_exception)));
        $has_exception = (count($exceptions) > count($filtered_list));
        $reporting[$i]['exception_class'] = ($has_exception) ? "grey_blue" : "orange";
        $reporting[$i]['exception_img'] = ($has_exception) ? "bandage.svg" : "fix.svg";
        $reporting[$i]['exception_title'] = ($has_exception) ?
        "exception already added for this block" :
        "add exception for [" . MESSAGE_CLASS[$cl] . '] url: [' . $reporting[$i]['request']['path']. ']';

    }

    $locked = is_locked();
    $lock_action = ($locked) ? "unlock" : "lock";

    $block = \TF\remove_lines(\TF\file_data(Config::file(CONFIG_BLOCK_FILE)), 400);
    $all_blocks = array_reverse(array_map(
        country_enricher(\TF\un_json(file_get_contents(WAF_DIR . "cache/country.json"))),
        array_map('\TF\un_json', $block->lines)
    ));
    $block_count = $block->num_lines;
    $all_blocks = array_filter($all_blocks, function ($x) {
        return !empty($x) && isset($x['ts']) && isset($x['eventid']);
    });
    $max_pages2 = $block_count / PAGE_SZ;


    $check_day = time() - \TF\DAY; // - \TF\DAY;
    $block_24 = array_filter($all_blocks, function ($x) use ($check_day) {
        return isset($x['ts']) && $x['ts'] > $check_day;
    });
    $block_count_24 = count($block_24);
    $blocks = array_slice($all_blocks, $page * PAGE_SZ, PAGE_SZ);

    // calculate hr data
    $hr_data = array_reduce($block_24, function ($carry, $x) {
        $hr = (int)date('H', (int)$x['ts']);
        $carry[$hr]++;
        return $carry;
    }, array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));

    // calculate country data
    $country_data = array_reduce($block_24, function ($carry, $x) {
        $carry[$x['country']] = isset($carry[$x['country']]) ? $carry[$x['country']] + 1 : 1;
        return $carry;
    }, array());

    // calculate type data
    $type_data = array_reduce($block_24, function ($carry, $x) {
        $class = code_class($x['eventid']);
        $carry[$class] = isset($carry[$class]) ? $carry[$class] + 1 : 1;
        return $carry;
    }, array());




    for ($i = 0, $m = count($blocks); $i < $m; $i++) {
        //$cl = intval($blocks[$i]['block']['code']/1000)*1000;
        $cl = \BitFire\code_class($blocks[$i]['eventid']);
        $test_exception = new \BitFire\Exception($blocks[$i]['eventid'], 'x', NULL, url_to_path($blocks[$i]['url']));

        // filter out the "would be" exception for this alert, and compare if we removed the exception
        $filtered_list = array_filter($exceptions, \TF\compose("\TF\\not", \TF\partial_right("\BitFire\match_exception", $test_exception)));
        $has_exception = (count($exceptions) > count($filtered_list));


        $parts = parse_url($blocks[$i]['url']);
        //\TF\dbg($blocks);
        $blocks[$i]['exception_class'] = ($has_exception) ? "grey_blue" : "orange";
        $blocks[$i]['exception_img'] = ($has_exception) ? "bandage.svg" : "fix.svg";
        $blocks[$i]['exception_title'] = ($has_exception) ?
            "exception already added for this block" :
            "add exception for [" . (MESSAGE_CLASS[$cl]??'unknown') . '] to url: [' . $parts['path'] . "]";



        $blocks[$i]['type_img'] = CODE_CLASS[$blocks[$i]['classId']];
        $browser = \BitFireBot\parse_agent($blocks[$i]['ua']);
        if (!$browser->bot && !$browser->browser) {
            $browser->browser = "chrome";
        }
        $blocks[$i]['browser'] = $browser;
        $blocks[$i]['agent_img'] = ($browser->bot) ? 'robot.svg' : ($browser->browser . ".png");
        $blocks[$i]['country_img'] = strtolower($blocks[$i]['country']) . ".svg";
        if ($blocks[$i]['country_img'] == "-.svg") {
            $blocks[$i]['country_img'] = "us.svg";
        }
    }

	$s1 = preg_replace("#[\?&]".CFG::str("dashboard_path")."=[^\?&]+#", "", $_SERVER['REQUEST_URI']);//."&_bitfire_p=".CFG::str("secret");
	$self = preg_replace("#[\?&]BITFIRE_API=[^\?&]+#", "", $s1);
    $self = preg_replace("#[\?&].*#", "", $self);
    //$self = str_replace_first('&', '?', $self);
    //$first = strpos($self,'&'); if ($first) { $self = str_replace('&', '?', $self, 1); }
    $opt_name = "Malware Scan";
    $opt_link = $self . ((strpos($self,"?")>0) ? '&' : '?') . "BITFIRE_API=MALWARESCAN";

    $password_reset = (Config::str('password') === 'default') || (Config::str('password') === 'bitfire!');
    $is_free = (strlen(Config::str('pro_key')) < 20);
    $llang = "en-US";
    $page_name = "BitFire Malware Dashboard";
    $is_wordpress = !empty(\BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']));
    exit(require WAF_DIR . "views/dashboard.html");
}
