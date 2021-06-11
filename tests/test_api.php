<?php declare(strict_types=1);

use function BitFire\get_wordpress_hashes;

if (!defined("WAF_DIR")) {
    define('WAF_DIR', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)));
}

include_once WAF_DIR . "util.php";
include_once WAF_DIR . "api.php";


function test_wordpress_hashes() : void {
    \BitFire\get_wordpress_hashes("/home/cory/tools/bitfire-release");
}
