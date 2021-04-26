<?php declare(strict_types=1);
namespace BitFire;

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

function is_locked() {
    $cmd = "find " . $_SERVER['DOCUMENT_ROOT'] . " -perm -u=w -type f | wc -l";
    exec($cmd, $list, $retval);
    $f = intval($list[0]);
    header("x-lock: [$f]");
    return ($f <= 1);
}

function serve_dashboard(string $path) {
    if ($path === Config::str(CONFIG_DASHBOARD_PATH)) {
        if (!isset($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW'] !== Config::str('password', 'default_password')) {
            header('WWW-Authenticate: Basic realm="BitFire", charset="UTF-8"');
            header('HTTP/1.0 401 Unauthorized');
            exit;
        }

        $config_writeable = is_writeable(WAF_DIR . "config.ini") | is_writeable(WAF_DIR."config.ini.php");

        $report_count = system("wc -l " . Config::file(CONFIG_REPORT_FILE) . "| wc -f 1 -d ' '"); //(is_array($x)) ? count($x) : 0;
        $config = \TF\map_mapvalue(Config::$_options, '\BitFire\alert_or_block');
        $tmp = add_country(\TF\un_json_array(\TF\read_last_lines(Config::file(CONFIG_REPORT_FILE), 20, 2500)));
        $reporting = (isset($tmp[0])) ? array_reverse($tmp, true) : array();
        $locked = is_locked();
        $lock_action = ($locked) ? "unlock" : "lock";
        
        $src = (Config::enabled(CONFIG_BLOCK_FILE)) ?
            \TF\read_last_lines(Config::file(CONFIG_BLOCK_FILE), 20, 2500) :
            \TF\CacheStorage::get_instance()->load_data("log_data");
        $blocks = (isset($tmp[0])) ? array_reverse(add_country(\TF\un_json_array($src)), true) : array();

        exit(require WAF_DIR . "views/dashboard.html");
    }
}


