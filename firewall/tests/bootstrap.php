<?php
namespace BitFire;

const DS = DIRECTORY_SEPARATOR;
const PD = DS."..".DS;

if (!defined("BitFire\WAF_ROOT")) {
    define('BitFire\WAF_ROOT', realpath(dirname(__DIR__, 1).DS).DS);
    define('BitFire\WAF_INI', dirname(\BitFire\WAF_ROOT, 1).DS."hidden_config".DS."config.ini");
    define('BitFire\WAF_SRC', dirname(\BitFire\WAF_ROOT, 1).DS."firewall/src/");
    define('BitFire\TYPE', "__STANDALONE__");
}


require_once \BitFire\WAF_SRC . "const.php";
require_once \BitFire\WAF_SRC . "util.php";
require_once \BitFire\WAF_SRC . "botfilter.php";
require_once \BitFire\WAF_SRC . "webfilter.php";
require_once \BitFire\WAF_SRC . "bitfire.php";
require_once \BitFire\WAF_SRC . "storage.php";
require_once \BitFire\WAF_SRC . "cms.php";
require_once \BitFire\WAF_ROOT . "/../error_handler.php";

$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['HTTP_HOST'] = 'unit_test';
$_SERVER['REQUEST_URI'] = 'http://localhost/some/url';
$_SERVER['REQUEST_METHOD'] = 'GET';

define('BitFire\BLOCK_DIR', '/tmp/blocks');



/*
function on_err($errno, $errstr, $err_file, $err_line, $context = NULL) : bool {
    throw new \TinyTest\TestError("$errstr[$errno] on $err_file:$err_line", "failure", "success");
}
*/

function make_config() : void {
    $_SERVER['REQUEST_URI'] = "http://localhost";
    \BitFire\Config::set(parse_ini_file(\BitFire\WAF_INI));
    \BitFire\Config::set_value('cache_type', 'nop');
    \BitFire\Config::set_value('debug_file', '/tmp/test_debug.log');
}
make_config();

assert_options(ASSERT_ACTIVE, 1);
assert_options(ASSERT_EXCEPTION, 1);