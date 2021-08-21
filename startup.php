<?php
namespace BitFire;

if (defined("WAF_DIR")) { header("bitfire-x: inc 2x"); return; }

if (PHP_VERSION_ID < 70000) {
    header("x-bitfire: requires php 7.0");
    return;
}

function at(array $elm, $idx, $default) {
    if($elm && isset($elm[$idx])) { return $elm[$idx]; }
    return $default;
}

//tideways_enable(TIDEWAYS_FLAGS_MEMORY | TIDEWAYS_FLAGS_CPU);

// system root paths and timing
$GLOBALS['start_time'] = \microtime(true);
$GLOBALS['bf_err_skip'] = false;
const DS = DIRECTORY_SEPARATOR;
define("WAF_DIR", realpath(__DIR__) . DS); 
define("BLOCK_DIR", WAF_DIR . DS . "blocks");

include WAF_DIR."src/bitfire.php";

function onerr($errno, $errstr, $errfile, $errline, $context = NULL) : bool {
    if ($GLOBALS['bf_err_skip']) { return true; }
    $data = array("errno" => $errno, "errstr" => $errstr, "errfile" => $errfile, "errline" => $errline);
    $known = \TF\un_json(file_get_contents(WAF_DIR."cache/errors.json"));
    $have_err = false;
    foreach ($known as $err) {
        if ($err['errno'] == $data['errno'] && 
            ($err['errline'] == $data['errline']) &&
                $err['errfile'] == $data['errfile']) { $have_err = true; }
    } 
    if (!$have_err) { $known[] = $data; file_put_contents(WAF_DIR."cache/errors.json", \TF\en_json($known)); }

    $data['info'] = $_SERVER;
    \TF\bit_http_request("POST", "https://bitfire.co/err.php", base64_encode(json_encode($data)));
    return false;
}

$error_handler = set_error_handler("\BitFire\onerr");


try {
    \TF\parse_ini(WAF_DIR."config.ini");
    \TF\debug("begin " . BITFIRE_SYM_VER);
    
    if (\BitFire\Config::enabled("allow_ip_block", false)) {
        $blockfile = BLOCK_DIR . DS . at($_SERVER, Config::str_up('ip_header', 'REMOTE_ADDR'), '127.0.0.1');
        if (file_exists($blockfile) && filemtime($blockfile) > time()) { 
            $m1 = microtime(true);
            \TF\debug("ip block: [" . round((($m1-$GLOBALS['start_time'])*1000),3) . "ms] time: " . \TF\utc_date("m/d @H.i.s") . " GMT");
            exit(include WAF_DIR."views/block.php");
        }
    }

    // todo: clean up
    if (strlen(Config::str('pro_key')>20) && file_exists(WAF_DIR."src/pro.php") ) { @include_once WAF_DIR . "src/pro.php"; @include_once WAF_DIR . "src/proapi.php"; }
    $bitfire = \Bitfire\BitFire::get_instance(); 
    $bitfire->inspect()
        ->then(function (\BitFire\Block $block) use ($bitfire) {
            \TF\debug("block 1");
            $ip_data = ($bitfire->bot_filter !== null) ? $bitfire->bot_filter->ip_data : array();
            register_shutdown_function('\BitFire\post_request', $bitfire->_request, $block, $ip_data);
            \BitFire\block_ip($block, $bitfire->_request)->run();
            return $block;
        })->then(function(\BitFire\Block $block) {
            \TF\debug("block 2");
            if ($block->code > 0) {
                \TF\debug("block 3");
                exit(include WAF_DIR."views/block.php");
            }
        })
        ->doifnot(array($bitfire, 'cache_behind'));

    register_shutdown_function('\BitFire\post_request', $bitfire->_request, null, null);
    \TF\debug("end");
}
catch (\Exception $e) {
    \BitFire\onerr($e->getCode(), $e->getMessage(), $e->getFile(), $e->getLine());
}

$m1 = microtime(true);
\TF\debug("time: [" . round((($m1-$GLOBALS['start_time'])*1000),3) . "ms] time: " . \TF\utc_date("m/d @H.i.s") . " GMT");
//$data = array_filter(\tideways_disable(), function($elm) { return ($elm['ct'] > 2 || $elm['wt'] > 9 || $elm['cpu'] > 9); }); 
//uasort($data, '\TF\prof_sort');
//file_put_contents("/tmp/prof.pass.json", json_encode($data, JSON_PRETTY_PRINT));

restore_error_handler();
