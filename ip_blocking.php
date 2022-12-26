<?php
use BitFire\Block;
use BitFire\Config as CFG;
use const BitFire\DS;

if (!defined("\BitFire\WAF_ROOT")) {
    die("ip_blocking must not be called directly");
}

$ip = filter_input(INPUT_SERVER, CFG::str_up('ip_header', 'REMOTE_ADDR'), FILTER_VALIDATE_IP);
$myself = filter_input(INPUT_SERVER, 'SERVER_ADDR', FILTER_VALIDATE_IP);
if ($ip != '' && $ip != $myself) {
    $block_file = \BitFire\BLOCK_DIR . DS . $ip;
    if (file_exists($block_file)) {
        // ip is still blocked
        if (filemtime($block_file) > time()) {
            BitFire\block_now(00001, "IP Block", "IP Address is blocked", $ip, 0)
                ->run();
        }
        // ip block has expired
        else {
            // whitelisted ips are never blocked
            if (file_get_contents($block_file) != 'allow') {
                unlink($block_file);
            }
        }
    }
}
