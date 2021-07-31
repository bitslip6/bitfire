<?php

namespace BitFire;

use \BitFire\Config as CFG;
use function TF\file_recurse;

require_once WAF_DIR . "src/api.php";
require_once WAF_DIR . "src/const.php";

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
    $ctr = 0;
    file_recurse($_SERVER['DOCUMENT_ROOT'], function ($file) use (&$ctr) {
        if (is_writeable($file)) {
            $ctr++;
            if ($ctr < 5) {
                \TF\debug("writeable [$file]");
            }
        }
    }, "/.php$/");
    \TF\debug("lock ctr: [$ctr]");
    return ($ctr <= 1);
}

function url_to_path($url)
{
    $idx = strpos($url, "/");
    return substr($url, $idx);
}

function dump_hashes()
{
    require_once WAF_DIR . "/src/server.php";
    \TF\debug("search roots: "  . \TF\en_json($_SERVER['DOCUMENT_ROOT']));
    $roots = \BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']);
    \TF\debug("found roots: " . \TF\en_json($roots));

    if (count($roots) < 1) { return array(); }
    
    // save ref to hashes and match with response...
    $hashes = array_map('\BitFireSvr\get_wordpress_hashes', $roots);
    $hashes = array_filter($hashes, function ($x) {
        if (count($x['files']) > 1) {
            \TF\debug("num files: " . count($x['files']));
            return true;
        }
    return false;
    });
    //file_put_contents("/tmp/hash.txt", json_encode($hashes, JSON_PRETTY_PRINT));
    //exit(\TF\en_json($hashes));
    //\TF\bit_http_request("POST", "http://bitfire.co/hash.php", "[{'ver':1,'files':[[0,1,2,3,4]}]");

    /*
    foreach ($hashes as $root)
        $offset = 0;
        while ($offset < count($root['files'])) {
*/
    $result = \TF\bit_http_request("POST", "http://bitfire.co/hash.php", \base64_encode(\TF\en_json($hashes)), array("Content-Type" => "application/json"));

    //file_put_contents("/tmp/hash2.txt", json_encode($result, JSON_PRETTY_PRINT));
    $decoded = \TF\un_json($result);

    //        }
    //    }



    $fix_files = array('ver' => $hashes[0]['ver'], 'root' => $ha, 'files' => array());
    if ($decoded && count($decoded) > 0) {
        \TF\debug("hash result len " . count($decoded));
        
        for ($i=0,$m=count($decoded);$i<$m; $i++) {
            $root = $decoded[$i];
            $ver = $hashes[$i]['ver'];
            $base = $hashes[$i]['root'];
            if (is_array($root)) {
                foreach ($root as $file) {
                    $filename = trim(str_replace($base, "", $file[4]), '/');
                    $path = "http://core.svn.wordpress.org/tags/{$ver}/$filename";
                    $parts = explode("/", $file[0]);
                    $out = $file[4] . "/" . join("/", array_slice($parts, 3));
                    $out = rtrim($out, "/");
                    $fix_files['files'][] = array('info' => $file[5], 'url' => $path, 'expected' => $file[2], 'actual' => $file[3], 'size1' => $file[1], 'size2' => $file[6], 'mtime' => filemtime($out), 'out' => $out);
                }
            } else {
                \TF\debug("unknown root!");
            }
        }
    } else {
        \TF\debug("hash result len 0");
    }

    //file_put_contents(WAF_DIR . "cache/file_fix.json", \TF\en_json($fix_files));
    //exit(\TF\en_json($fix_files));
    return $fix_files;
}

function bytes_to_kb($bytes) : string {
    return round((int)$bytes / 1024, 1) . "Kb";

}

function serve_malware(string $dashboard_path)
{
    if (!isset($_SERVER['PHP_AUTH_PW']) ||
        (sha1($_SERVER['PHP_AUTH_PW']) !== Config::str('password', 'default_password')) &&
        (sha1($_SERVER['PHP_AUTH_PW']) !== sha1(Config::str('password', 'default_password')))) {

        header('WWW-Authenticate: Basic realm="BitFire", charset="UTF-8"');
        header('HTTP/1.0 401 Unauthorized');
        exit;
    }

    header("Cache-Control: no-store, private, no-cache, max-age=0");
    header('Expires: ' . gmdate('D, d M Y H:i:s \G\M\T', 100000));
    http_response_code(203);

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
    exit(require WAF_DIR . "views/hashes.html");
}

function machine_date($time) : string {
    return date("Y-m-d", (int)$time);
}
function human_date($time) : string {
    return date("D M j Y, h:i:s A P", (int)$time);
}

/**
 * TODO: split this up into multiple functions
 */
function serve_dashboard(string $dashboard_path)
{
    if (!isset($_SERVER['PHP_AUTH_PW']) ||
        (sha1($_SERVER['PHP_AUTH_PW']) !== Config::str('password', 'default_password')) &&
        (sha1($_SERVER['PHP_AUTH_PW']) !== sha1(Config::str('password', 'default_password')))) {

        header('WWW-Authenticate: Basic realm="BitFire", charset="UTF-8"');
        header('HTTP/1.0 401 Unauthorized');
        exit;
    }

    if ($_GET['_infoz'] ?? '' === 'show') {
        phpinfo();
        die();
    }
    $page = intval($_GET['page'] ?? 0);


    // try to prevent proxy caching for this page
    header("Cache-Control: no-store, private, no-cache, max-age=0");
    header('Expires: ' . gmdate('D, d M Y H:i:s \G\M\T', 100000));
    http_response_code(203);
    require_once WAF_DIR . "src/botfilter.php";

    $config_writeable = is_writeable(WAF_DIR . "config.ini") && is_writeable(WAF_DIR . "config.ini.php");
    $config = \TF\map_mapvalue(Config::$_options, '\BitFire\alert_or_block');
    //$config['security_headers_enabled'] = ($config['security_headers_enabled'] === "block") ? "true" : "false";
    $config_orig = Config::$_options;
    $exceptions = \BitFire\load_exceptions();



    $report_file = \TF\FileData::new(CFG::file(CONFIG_REPORT_FILE))
        ->read()
        ->apply(\TF\partial_right('\TF\remove_lines', 400))
        ->apply_ln(\TF\partial_right('array_slice', $page * PAGE_SZ, PAGE_SZ, false))
        ->map('\TF\un_json')
        ->map(country_enricher(\TF\un_json(file_get_contents(WAF_DIR . "cache/country.json"))));
    $report_count = $report_file->num_lines;




    //$report_count = count(file(Config::file(CONFIG_REPORT_FILE)));
    $tmp = add_country(\TF\un_json_array(\TF\read_last_lines(Config::file(CONFIG_REPORT_FILE), 20, 2500)));
    $reporting = (isset($tmp[0])) ? array_reverse($tmp, true) : array();

    /*
    for($i=0,$m=count($reporting); $i<$m; $i++) {
        //$cl = intval($reporting[$i]['block']['code']/1000)*1000;
        $cl = \BitFire\code_class($reporting[$i]['block']['code']);
        $test_exception = new \BitFire\Exception($reporting[$i]['block']['code'], 'x', NULL, $reporting[$i]['request']['path']);

        // filter out the "would be" exception for this alert, and compare if we removed the exception
        $filtered_list = array_filter($exceptions, \TF\compose("\TF\\not", \TF\partial_right("\BitFire\match_exception", $test_exception)));
        $has_exception = (count($exceptions) > count($filtered_list));
        $reporting[$i]['exception_class'] = ($has_exception) ? "grey_blue" : "orange";
        $reporting[$i]['exception_img'] = ($has_exception) ? "bandage.svg" : "fix.svg";
        $reporting[$i]['exception_title'] = ($has_exception) ?
        "exception already added for this block" :
        "add exception for " . MESSAGE_CLASS[$cl] . ' url: ' . $reporting[$i]['request']['path'];

        $reporting[$i]['type_img'] = CODE_CLASS[$cl];
        $reporting[$i]['agent_img'] = $reporting[$i]['browser']['browser']??'chrome' . ".png";
        $reporting[$i]['country_img'] = strtolower($reporting[$i]['country']);
        $reporting[$i]['country_img'] .= ".svg";
        if ($reporting[$i]['country_img'] == "-.svg") {
            $reporting[$i]['country_img'] = "us.svg";
        }
    }
	 */

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
            "add exception for " . MESSAGE_CLASS[$cl] ?? 'unknown' . ' url: ' . $parts['path'];



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
//die($opt_link);
    $password_reset = (Config::str('password') === 'default');
    $is_free = (strlen(Config::str('pro_key')) < 20);
    exit(require WAF_DIR . "views/dashboard.html");
}
