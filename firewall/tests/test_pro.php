<?php

use TinyTest\TestError;

use const BitFire\WAF_SRC;

require_once WAF_SRC . "pro.php";


/**
 * test that http rasp filters out internal requests
 * @return void 
 * @throws TestError 
 */
function test_http_rasp() {
    BitFirePRO\site_lock();

    $index_page = file_get_contents("https://bitfire.co");
    assert_gt(strlen($index_page), 4096, "unable to get index page");

    $internal = file_get_contents("http://127.0.0.1");
    assert_false($internal, "was able to get internal page via IP");

    $internal = file_get_contents("http://localhost");
    assert_false($internal, "was able to get internal page via host alias");
}