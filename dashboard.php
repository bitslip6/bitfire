<?php declare(strict_types=1);
namespace BitFire;

use function TF\file_recurse;
use function TF\really_writeable;

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
        if (\TF\ends_with($file, 'php')) {
            if (is_writeable($file)) { $ctr++; }
        }
    });
    \TF\debug("lock ctr: [$ctr]");
    return ($ctr <= 1);
}

function serve_dashboard(string $path) {
    if (rtrim($path, "/") === Config::str(CONFIG_DASHBOARD_PATH)) {
        if (!isset($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW'] !== Config::str('password', 'default_password')) {
            header('WWW-Authenticate: Basic realm="BitFire", charset="UTF-8"');
            header('HTTP/1.0 401 Unauthorized');
            exit;
        }
        require_once WAF_DIR . "botfilter.php";

        $config_writeable = is_writeable(WAF_DIR . "config.ini") | is_writeable(WAF_DIR."config.ini.php");

        $report_count = count(file(Config::file(CONFIG_REPORT_FILE)));//system("wc -l " . Config::file(CONFIG_REPORT_FILE) . "| wc -f 1 -d ' '"); //(is_array($x)) ? count($x) : 0;
        $config_orig = Config::$_options;
        $config = \TF\map_mapvalue(Config::$_options, '\BitFire\alert_or_block');
        $tmp = add_country(\TF\un_json_array(\TF\read_last_lines(Config::file(CONFIG_REPORT_FILE), 20, 2500)));
        $reporting = (isset($tmp[0])) ? array_reverse($tmp, true) : array();

        for($i=0,$m=count($reporting); $i<$m; $i++) {
            $cl = intval($reporting[$i]['block']['code']/1000)*1000;
            $reporting[$i]['type_img'] = CODE_CLASS[$cl];
            $reporting[$i]['agent_img'] = $reporting[$i]['browser']['browser']??'chrome' . ".png";
            $reporting[$i]['country_img'] = $reporting[$i]['country'];
            $reporting[$i]['country_img'] .= ".svg";
            if ($reporting[$i]['country_img'] == "-.svg") {
                $reporting[$i]['country_img'] = "us.svg";
            }
        }
        $data = \TF\read_last_lines(Config::file(CONFIG_REPORT_FILE), 10, 2500);

        $locked = is_locked();
        $lock_action = ($locked) ? "unlock" : "lock";
        
        $src = (Config::enabled(CONFIG_BLOCK_FILE)) ?
            \TF\read_last_lines(Config::file(CONFIG_BLOCK_FILE), 20, 2500) :
            \TF\CacheStorage::get_instance()->load_data("log_data");
        $blocks = (isset($src[0])) ? array_reverse(add_country(\TF\un_json_array($src)), true) : array();

        for($i=0,$m=count($blocks); $i<$m; $i++) {
            //$cl = intval($blocks[$i]['block']['code']/1000)*1000;
            $blocks[$i]['type_img'] = CODE_CLASS[$blocks[$i]['classId']];
            $browser = \BitFireBot\parse_agent($blocks[$i]['ua']);
            $blocks[$i]['agent_img'] = ($browser['browser']??'chrome') . ".png";
            $blocks[$i]['country_img'] = $blocks[$i]['country'] . ".svg";
            if ($blocks[$i]['country_img'] == "-.svg") {
                $blocks[$i]['country_img'] = "us.svg";
            }
        }

        exit(require WAF_DIR . "views/dashboard.html");
    }
}


