<?php declare(strict_types=1);

use ThreadFin\FileData;

use function BitFireSvr\have_valid_http_code;
use function BitFireSvr\update_ini_fn;
use function ThreadFin\en_json;
use function ThreadFin\partial;

/** SETUP  */
if (!defined("\BitFire\WAF_ROOT")) {
    define('\BitFire\WAF_ROOT', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)).DIRECTORY_SEPARATOR);
}
include_once \BitFire\WAF_SRC."server.php";

function access_log_lines() : array {
    return array('::1 - - [11/Feb/2021:13:04:18 -0700] "GET /bitfire?".BITFIRE_API=get_hr_data&BITFIRE_NONCE=RNQNeCaMExTKHPEI HTTP/1.1" 200 42 "http://localhost:8080/bitfire" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36"');
}

function test_update_ini_value() : void {
    $effect = \BitFireSvr\update_ini_value("dns_service", "4.2.2.2");
    //\ThreadFin\dbg($effect);
    $files = $effect->read_files();
    assert_gt(count($files), 0, "did not update any files, permission error?");
    assert_contains($files[0]->content, "dns_service = \"4.2.2.2\"", "unable to set dns_service :(");
}

function test_ini_update() : void {
    $sample = "; a comment
    foo = 'bar'
    foobar = 1
    ";

    FileData::mask_file("TEST_FILE", $sample);
    $sample_fn = partial("str_replace", "'bar'", "'baz'");
    $x = $sample_fn("foo'bar'");
    assert_contains($x, "baz'", "ini replace function failure");


    $e = update_ini_fn($sample_fn, "TEST_FILE");
    assert_eq(count($e->read_files()), 2, "update ini file failed to update .ini and .php");

    $file_mod = $e->read_files()[0];
    assert_contains($file_mod->content, "'baz'", "ini replace function failure");

    //assert_contains($)
    //\ThreadFin\dbg($e);
}


/**
 * @type integration
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


function test_get_wordpress_hashes() : void {
    
    $hashes = \BitFireSvr\get_wordpress_hashes(__DIR__ . "/wp");
    file_put_contents("/tmp/out.txt", en_json($hashes));

}