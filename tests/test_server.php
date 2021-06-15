<?php declare(strict_types=1);

use BitFire\Config;

use const BitFireSvr\ACCESS_URL_METHOD;

use function BitFireSvr\have_valid_http_code;

/** SETUP  */
if (!defined("WAF_DIR")) {
    define('WAF_DIR', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)));
}
include_once WAF_DIR . "src/server.php";

function access_log_lines() : array {
    return array('::1 - - [11/Feb/2021:13:04:18 -0700] "GET /bitfire?BITFIRE_API=get_hr_data&_bitfire_p=RNQNeCaMExTKHPEI HTTP/1.1" 200 42 "http://localhost:8080/bitfire" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36"');
}

/** TESTS */
function test_conf_globing() : void {
    $r = \BitFireSvr\pattern_to_list_3(\BitFireSvr\get_server_config_file_list());
    assert_gt(count($r), 1, "unable to glob any http configs");
}

function test_get_all_confs()  {
    $r = \BitFireSvr\get_all_http_confs();
    assert_gt(count($r), 1, "unable to glob any http configs");
}

/**
 * @dataprovider access_log_lines
 */
function test_process_access_line(string $line) {
    $r = \BitFireSvr\process_access_line($line);
    assert_instanceof($r, "\BitFire\Request", "process line did not return valid data");
    assert_gt(count($r->get), 1, "unable to process get params");
}

function access_code_checks() : array {
    return array(
        array(\BitFireSvr\ACCESS_CODE => 200, 'result' => true),
        array(\BitFireSvr\ACCESS_CODE => 500, 'result' => false),
        array(\BitFireSvr\ACCESS_CODE => 404, 'result' => false),
        array(\BitFireSvr\ACCESS_CODE => 403, 'result' => false),
        array(\BitFireSvr\ACCESS_CODE => 302, 'result' => true),
        array(\BitFireSvr\ACCESS_CODE => 301, 'result' => true),
        array(\BitFireSvr\ACCESS_CODE => "200", 'result' => true),
        array(\BitFireSvr\ACCESS_CODE => "201", 'result' => true),
        array(\BitFireSvr\ACCESS_CODE => "302", 'result' => true),
    );
}

/**
 * @dataprovider access_code_checks
 */
function test_valid_http_code(array $data) {
    assert_eq(have_valid_http_code($data), $data['result'], "check http response code failed");
}

function test_split_request_url() {
    $data = array(\BitFireSvr\ACCESS_URL => 'GET http://example.com/some/path?param=value&option=data HTTP/1.1');
    $result = \BitFireSvr\split_request_url($data); 

    assert_eq($result[\BitFireSvr\ACCESS_URL_METHOD], "GET", "unable to parse http method");
    assert_eq($result[\BitFireSvr\ACCESS_HOST], "example.com", "unable to parse http method");
}


function test_process_batch() {
    \BitFire\Config::set_value("whitelist_enable", false);
    \BitFire\Config::set_value("blacklist_enable", false);
    \BitFire\Config::set_value("require_full_browser", false);
    $exceptions = \BitFireSvr\process_access_file("access.log");
}

function test_get_wordpress_hashes() : void {
    
    $hashes = \BitFireSvr\get_wordpress_hashes(__DIR__ . "/wp");
    file_put_contents("/tmp/out.txt", TF\en_json($hashes));

}