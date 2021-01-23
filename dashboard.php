<?php declare(strict_types=1);
namespace BitFire;

function add_country($data) {
    if (!is_array($data) || count($data) < 1) { return $data; }
    $map = json_decode(file_get_contents(WAF_DIR . "cache/country.json"), true);
    $result = array();
    foreach ($data as $report) {
        $code = \TF\ip_to_country($report['ip'] ?? '');
        $report['country'] = $map[$code];
        $result[] = $report; 
    }
    return $result;
}

function serve_dashboard(string $path) {
    if ($path === "/bitfire") {

        if (!isset($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW'] !== Config::str('password', 'default_password')) {
            header('WWW-Authenticate: Basic realm="BitFire", charset="UTF-8"');
            header('HTTP/1.0 401 Unauthorized');
            exit;
        }

        $x = @file(Config::str(CONFIG_REPORT_FILE));
        $report_count = (is_array($x)) ? count($x) : 0;
        $config = \TF\map_mapvalue(Config::$_options, '\BitFire\alert_or_block');
        $tmp = add_country(json_decode('['. join(",", \TF\read_last_lines(Config::str(CONFIG_REPORT_FILE), 20, 2500)) . ']', true));
        $reporting = (isset($tmp[0])) ? array_reverse($tmp, true) : array();
        
        $tmp = add_country(\TF\CacheStorage::get_instance()->load_data("log_data"));
        $blocks = (isset($tmp[0])) ? array_reverse($tmp, true) : array();

        exit(require WAF_DIR . "views/dashboard.html");
    }
}


