<?php

use BitFire\BitFire;
use BitFire\Request;

use const BitFire\CODE_CLASS;

const NUM_BLOCKS = 242;
$param_names = file("params.txt", FILE_IGNORE_NEW_LINES);

$code_keys = array_keys(CODE_CLASS);
$num_codes = count($code_keys);
$urls = ["index.php", "wp-signup.php", "wp-trackback.php", "wp-cron.php"];
$agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0",
"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; Trident/5.0)",
"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0; MDDCJS)",
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"];

for ($i=0; $i<NUM_BLOCKS; $i++) {

    while(!$found) {
        $code = mt_rand(1, 31);
        $class = $code * 10000;
        if (isset(CODE_CLASS[$class])) {
            $found = true;
        }
    }

    $code += mt_rand(0, 10);
    $param = $param_names[mt_rand(0, count($param_names)-1)];

    $req = new Request();
    $req->host = "bitslip6.ath.cx";
    $req->path = $urls[mt_rand(0, count($urls)-1)];
    $req->ip = mt_rand(50,201) . "." .  mt_rand(50,201) . "." .  mt_rand(50,201) . "." .  mt_rand(10,255);
    $req->method = mt_rand(1,20) > 6 ? "GET" : "POST";
    $req->port = "80";
    $req->scheme = "http";
    $req->agent = $agents[mt_rand(0, count($agents)-1)];


    BitFire::new_block(28001, "_bf_block", "url", $this->_request->get['_bf_block'], 0, $req);

}