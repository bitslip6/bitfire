<?php declare(strict_types=1);


use const BitFire\DS;
use const BitFire\WAF_ROOT;

use function BitFire\get_names;

require_once \BitFire\WAF_SRC . "cms.php";

/*
function test_matching() : void {
    $sample = "555-1234, 555-9871, 555-0000";
    preg_match_all("/\d{3}-\d{4}/", $sample, $matches);
    print_r($matches);
}
*/

function test_get_names() : void {

    $t1 = "<?php\n\$var_name = 1;\n\$varName = 2;\n\$EVIL = 3\n\$EvIlNa = 4";
    $names = get_names($t1);
    print_r($names);
}