<?php
namespace BitFire;

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

function country_enricher(array $country_info) : callable {
    return function (array $input) use ($country_info): array {
        $code = \TF\ip_to_country($input['request']['ip']??$input['ip']??'');
        $input['country'] = $country_info[$code];
        return $input;
    };
}

function add_country($data) {
    if (!is_array($data) || count($data) < 1) { return $data; }
    $map = \TF\un_json(file_get_contents(WAF_DIR . "cache/country.json"));
    $result = array();
    foreach ($data as $report) {
        $code = \TF\ip_to_country($report['ip'] ?? '');
        $report['country'] = $map[$code];
        $result[] = $report; 
    }
    return $result;
}

function isdis() {
    $result = is_writeable(WAF_DIR . "config.ini") && is_writeable(WAF_DIR."config.ini.php");
    return ($result) ? " " : "disabled ";
}

function is_locked() : bool {
    $ctr = 0;
    file_recurse($_SERVER['DOCUMENT_ROOT'], function($file) use (&$ctr) {
        if (is_writeable($file)) { $ctr++; if ($ctr < 5) { \TF\debug("writeable [$file]"); }}
    }, "/.php$/");
    \TF\debug("lock ctr: [$ctr]");
    return ($ctr <= 1);
}

function url_to_path($url) {
    $idx = strpos($url, "/");
    return substr($url, $idx);
}

/**
 * TODO: split this up into multiple functions
 */
function serve_dashboard(string $dashboard_path) {
    if (!isset($_SERVER['PHP_AUTH_PW']) ||
        (sha1($_SERVER['PHP_AUTH_PW']) !== Config::str('password', 'default_password')) &&
        (sha1($_SERVER['PHP_AUTH_PW']) !== sha1(Config::str('password', 'default_password')))) {

        header('WWW-Authenticate: Basic realm="BitFire", charset="UTF-8"');
        header('HTTP/1.0 401 Unauthorized');
        exit;
    }

    if ($_GET['_infoz']??'' === 'show') { phpinfo(); die(); }
    $page = intval($_GET['page']??0);

       
    // try to prevent proxy caching for this page
    header("Cache-Control: no-store, private, no-cache, max-age=0");
    header('Expires: '.gmdate('D, d M Y H:i:s \G\M\T', 100000));
    http_response_code(203);
    require_once WAF_DIR . "src/botfilter.php";

    $config_writeable = is_writeable(WAF_DIR . "config.ini") | is_writeable(WAF_DIR."config.ini.php");
    $config = \TF\map_mapvalue(Config::$_options, '\BitFire\alert_or_block');
    $config['security_headers_enabled'] = ($config['security_headers_enabled'] === "block") ? "true" : "false";
    $config_orig = Config::$_options;
    $exceptions = \BitFire\load_exceptions();

    $report = \TF\remove_lines(\TF\file_data(Config::file(CONFIG_REPORT_FILE)), 400);
    $reporting = array_map(
        country_enricher(\TF\un_json(file_get_contents(WAF_DIR . "cache/country.json"))),
        array_map('\TF\un_json', array_slice($report->lines, $page*PAGE_SZ, PAGE_SZ)));
    $report_count = $report->num_lines;


    

    //$report_count = count(file(Config::file(CONFIG_REPORT_FILE)));
    $tmp = add_country(\TF\un_json_array(\TF\read_last_lines(Config::file(CONFIG_REPORT_FILE), 20, 2500)));
    $reporting = (isset($tmp[0])) ? array_reverse($tmp, true) : array();

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
    
    $locked = is_locked();
    $lock_action = ($locked) ? "unlock" : "lock";
    
    $block = \TF\remove_lines(\TF\file_data(Config::file(CONFIG_BLOCK_FILE)), 400);
    $all_blocks = array_map(
        country_enricher(\TF\un_json(file_get_contents(WAF_DIR . "cache/country.json"))),
        array_map('\TF\un_json', $block->lines));
    $block_count = $block->num_lines;


    $check_day = time() - \TF\DAY - \TF\DAY;
    $block_24 = array_filter($all_blocks, function ($x) use ($check_day) { return $x['ts'] > $check_day; });
    $block_count_24 = count($block_24);
    $blocks = array_slice($all_blocks, $page*PAGE_SZ, PAGE_SZ);

    // calculate hr data
    $hr_data = array_reduce($block_24, function ($carry, $x) {
        $hr = (int)date('H', (int)$x['ts']);
        $carry[$hr]++;
        return $carry;
    }, array(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0));

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




    for($i=0,$m=count($blocks); $i<$m; $i++) {
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
        "add exception for " . MESSAGE_CLASS[$cl]??'unknown' . ' url: ' . $parts['path'];



        $blocks[$i]['type_img'] = CODE_CLASS[$blocks[$i]['classId']];
        $browser = \BitFireBot\parse_agent($blocks[$i]['ua']);
        if (!$browser->bot && !$browser->browser) { $browser->browser = "chrome"; }
        $blocks[$i]['browser'] = $browser;
        $blocks[$i]['agent_img'] = ($browser->bot)?'robot.svg':($browser->browser.".png");
        $blocks[$i]['country_img'] = strtolower($blocks[$i]['country']) . ".svg";
        if ($blocks[$i]['country_img'] == "-.svg") {
            $blocks[$i]['country_img'] = "us.svg";
        }
    }

    $password_reset = (Config::str('password') === 'default');
    $is_free = (strlen(Config::str('pro_key')) < 20);
    exit(require WAF_DIR . "views/dashboard.html");
}


