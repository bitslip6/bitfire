<?php declare(strict_types=1);

use function TF\tar_extract;

if (!defined("WAF_DIR")) {
    define('WAF_DIR', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)));
}
include_once WAF_DIR . "src/bitfire.php";
include_once WAF_DIR . "src/util.php";
include_once WAF_DIR . "src/bitfire_pure.php";



function test_ip_block() : void {
    $block = new \BitFire\Block(0, "foobar", "value", "thing", 0);
    $request = new \BitFire\Request();
    $request->agent = "Unit Test";
    $request->ip = "127.0.0.1";
    $block_time = 600;
    $response_code = 200;

    $effect = \BitFire\Pure\ip_block($block, $request, $block_time, $response_code);
    assert_eq(count($effect->read_files()), 1, "ip block did not set any ip block files");
    assert_eq($effect->read_files()[0]->filename, "/tmp/blocks/127.0.0.1", "ip block did not set correct path");
    assert_eq($effect->read_files()[0]->modtime, time() + 600, "ip block did not set correct expiration time");
    assert_gt(strlen($effect->read_files()[0]->content), 128, "ip block did not set block reason");
}


function test_param_to_str() : void {
    
    $params = array("user" => "myself", "pwd" => "secret"); 
    $filter = array("pwd" => true); 

    $result = \BitFire\Pure\param_to_str($params, $filter);
    assert_contains($result, "**REDACTED**", "unable to redact password");
}

