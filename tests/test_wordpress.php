<?php declare(strict_types=1);
namespace BitFirePlugin {
    function is_admin() { return true; }
} 
namespace {

if (!defined("WAF_DIR")) {
    define('WAF_DIR', realpath(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."firewall/"));
    define('BitFire\WAF_ROOT', WAF_DIR);
    define("BitFire\WAF_SRC", realpath(WAF_DIR . "/src") . "/");
    define("BitFire\DS", DIRECTORY_SEPARATOR);
}

function add_action(...$args) {};
function add_filter(...$args) {};
function register_activation_hook(...$args) {};
function register_(...$args) {};

define ("BitFire\WAF_INI", __DIR__ . DIRECTORY_SEPARATOR . "config-sample.ini");
define ("WPINC", 1);

require_once WAF_DIR . "/src/bitfire.php";
require_once WAF_DIR . "/src/util.php";
require_once "wordpress-plugin/bitfire-admin.php";
//require_once "wordpress-plugin/bitfire-admin.php";




function test_upgrade() {
    xdebug_break();
    $effect = BitFirePlugin\upgrade();
    assert_gt(count($effect->read_files()), 0, "upgrade did not modify any files");
    $effect->run();
}

}