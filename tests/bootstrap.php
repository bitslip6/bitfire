<?php declare(strict_types=1);

if (!defined("WAF_DIR")) {
    define('WAF_DIR', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)).DIRECTORY_SEPARATOR);
}


require_once WAF_DIR . "src/util.php";
require_once WAF_DIR . "src/botfilter.php";
require_once WAF_DIR . "src/webfilter.php";
require_once WAF_DIR . "src/bitfire.php";
require_once WAF_DIR . "src/storage.php";

$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['HTTP_HOST'] = 'unit_test';
$_SERVER['REQUEST_URI'] = 'http://localhost/some/url';
$_SERVER['REQUEST_METHOD'] = 'GET';

define('BLOCK_DIR', '/tmp/block');

function make_config() : void {
    $_SERVER['REQUEST_URI'] = "http://localhost";
    \BitFire\Config::set(parse_ini_file('config.ini'));
    \BitFire\Config::set_value('cache_type', 'shmop');
}
make_config();