<?php
namespace BitFire;
use \BitFire\Config as CFG;

use function ThreadFin\en_json;
use function ThreadFin\httpp;
use function ThreadFin\parse_ini2;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\un_json;

if (defined("BitFire\\WAF_ROOT")) { header("x-bitfire: inc 2x"); return; }
if (PHP_VERSION_ID < 70000) { header("x-bitfire: requires php >= 7.0"); return; }



//xhprof_enable(XHPROF_FLAGS_CPU | XHPROF_FLAGS_MEMORY);

// system root paths and timing
$start_time = microtime(true);
const DS = DIRECTORY_SEPARATOR;
if (!defined("BitFire\WAF_ROOT")) {
    define("BitFire\WAF_ROOT", realpath(__DIR__) . DS); 
    define("BitFire\WAF_INI", \BitFire\WAF_ROOT . "config.ini");
    define("BitFire\BLOCKDIR", \BitFire\WAF_ROOT . "blocks");
    define("BitFire\WAF_SRC", \BitFire\WAF_ROOT . "src/"); 
}

include \BitFire\WAF_SRC."bitfire.php";

function onerr($errno, $errstr, $errfile, $errline, $context = NULL) : bool {
    $data = array("errno" => $errno, "errstr" => $errstr, "errfile" => $errfile, "errline" => $errline);
    $known = un_json(file_get_contents(\BitFire\WAF_ROOT."cache/errors.json"));
    $have_err = false;
    foreach ($known as $err) {
        if ($err['errno'] == $data['errno'] && 
            ($err['errline'] == $data['errline']) &&
                $err['errfile'] == $data['errfile']) { $have_err = true; }
    } 
    if (!$have_err) { 
        $known[] = $data;
        file_put_contents(\BitFire\WAF_ROOT."cache/errors.json", en_json($known, JSON_PRETTY_PRINT));
        $data['bt'] = debug_backtrace(0, 3);
        if (CFG::enabled('send_errors')) { httpp(APP."err.php", base64_encode(json_encode($data))); }
    }
    return false;
}

// capture any bitfire errors
$error_handler = set_error_handler("\BitFire\onerr");
// capture any bitfire fatal errors
register_shutdown_function(function() {
    $e = error_get_last();
    // if last error was from bitfire, log it
    if (is_array($e) && $e['type']??-1 == E_ERROR && strstr($e['file']??"", "bitfire") !== false) {
        onerr(1, $e['message'], $e['file'], $e["line"]);
        exit();
}});



try {
    CFG::set(parse_ini2(\BitFire\WAF_INI));
    debug("bitfire %s", BITFIRE_SYM_VER);
        
    // handle IP level blocks, requires single stat call for test
    if (CFG::enabled("allow_ip_block")) {
        $ip = filter_input(INPUT_SERVER, CFG::str_up("ip_header", "REMOTE_ADDR"), FILTER_VALIDATE_IP);
        if ($ip != "127.0.0.1" && $ip != "::1") {
            $blockfile = \BitFire\BLOCKDIR . DS . $ip;
            if (file_exists($blockfile) && filemtime($blockfile) > time()) { 
                $block = array("blocked IP address");
                exit(include \BitFire\WAF_ROOT."views/block.php");
            }
        }
    }

    // enable/disable assertions via debug setting
    $active = (CFG::enabled("debug_header") || CFG::enabled("debug_file")) ? 1 : 0;
    $zend_assert = 99;
    if ($active) {
        $zend_assert = assert_options(ASSERT_ACTIVE);
        @assert_options(ASSERT_ACTIVE, $active);
        @ini_set("zend.assertions", $active);
    }


    if (strlen(CFG::str("pro_key"))>20) {
        if (file_exists(\BitFire\WAF_SRC."pro.php")) { 
            @include_once \BitFire\WAF_SRC . "pro.php";
            if (cfg::enabled("site_lock") && function_exists('BitFirePRO\site_lock')) { \BitFirePRO\site_lock(); }
        }
    }

    $bitfire = \Bitfire\BitFire::get_instance(); 
    $bitfire->inspect()
        ->then(function (\BitFire\Block $block) use ($bitfire) {
            debug("block 1");
            $ip_data = ($bitfire->bot_filter !== null) ? $bitfire->bot_filter->ip_data : null;
            register_shutdown_function('\BitFire\post_request', $bitfire->_request, $block, $ip_data);
            \BitFire\block_ip($block, $bitfire->_request)->run();
            return $block;
        })->then(function(\BitFire\Block $block) {
            if ($block->code > 0) {
                debug("block 3");
                exit(include \BitFire\WAF_ROOT."views/block.php");
            }
        });
}
catch (\Exception $e) {
    \BitFire\onerr($e->getCode(), $e->getMessage(), $e->getFile(), $e->getLine());
}

$m1 = microtime(true);
debug("bitfire [%dms] [%s]", round((($m1-$start_time)*1000),4), trace());//, utc_date("m/d @H.i.s"));
//file_put_contents("/tmp/xhprf.json", json_encode(xhprof_disable(), JSON_PRETTY_PRINT));
//output_profile(\xhprof_disable());
//$data = \xhprof_disable();
//$data = array_filter(\xhprof_disable(), function($elm) { return ($elm['wt'] > 100 || $elm['cpu'] > 100); }); 
//uasort($data, '\ThreadFin\prof_sort');
//file_put_contents("/tmp/prof2.pass.json", json_encode($data, JSON_PRETTY_PRINT));

// clean up the error handler and assertion settings
restore_error_handler();
if($zend_assert!=99) { assert_options(ASSERT_ACTIVE, $zend_assert); }

// add support for startup chaining 
$autoload = CFG::str("auto_prepend_file");
if (!empty($autoload) && file_exists($autoload)) { @include $autoload; }

