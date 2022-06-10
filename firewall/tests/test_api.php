<?php declare(strict_types=1);

use function BitFire\get_wordpress_hashes;

if (!defined("\BitFire\WAF_ROOT")) {
    define('\BitFire\WAF_ROOT', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)) . DIRECTORY_SEPARATOR);
}

include_once \BitFire\WAF_SRC."api.php";


function test_wordpress_hashes() : void {
    if (function_exists('\BitFire\get_wordpress_hashes')) {
        \BitFire\get_wordpress_hashes("/home/cory/tools/bitfire-release");
    }
}
