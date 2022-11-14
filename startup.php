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
    define("BitFire\BLOCK_DIR", \BitFire\WAF_ROOT . "blocks");
    define("BitFire\WAF_SRC", \BitFire\WAF_ROOT . "src" . DS); 
    define("BitFire\TYPE", "__TYPE__");
}

include \BitFire\WAF_SRC."bitfire.php";

function on_err($errno, $errstr, $err_file, $err_line, $context = NULL) : bool {
    $data = array("errno" => $errno, "errstr" => $errstr, "err_file" => $err_file, "err_line" => $err_line);
    // ignore errors that may not be ours...
    if (!strpos($err_file, "bitfire")) { return false; }

    $known = un_json(file_get_contents(\BitFire\WAF_ROOT."cache/errors.json"));
    $have_err = false;
    foreach ($known as $err) {
        if ($err['errno'] == $data['errno'] && 
            ($err['err_line'] == $data['err_line']) &&
                $err['err_file'] == $data['err_file']) { $have_err = true; }
    } 
    if (!$have_err) { 
        $data['debug'] = debug(null);
        $data['trace'] = trace(null);
        $known[] = $data;
        file_put_contents(\BitFire\WAF_ROOT."cache/errors.json", en_json($known, true));
        $data['bt'] = debug_backtrace(0, 3);
        if (CFG::enabled('send_errors')) { httpp(APP."err.php", base64_encode(json_encode($data))); }
    }

    return false;
}

// capture any bitfire errors
$error_handler = set_error_handler("\BitFire\on_err");
// capture any bitfire fatal errors
register_shutdown_function(function() {
    $e = error_get_last();
    // if last error was from bitfire, log it
    if (is_array($e) && $e['type']??-1 == E_ERROR && stripos($e['file']??"", "bitfire") > 0) {
        on_err(1, $e['message'], "({$e['file']})", $e["line"]);
}});



try {
    CFG::set(parse_ini2(\BitFire\WAF_INI));
    debug("bitfire %s", BITFIRE_SYM_VER);
        
    // handle IP level blocks, requires single stat call for test
    if (CFG::enabled("allow_ip_block")) {
        $ip = filter_input(INPUT_SERVER, CFG::str_up("ip_header", "REMOTE_ADDR"), FILTER_VALIDATE_IP);
        $myself = filter_input(INPUT_SERVER, "SERVER_ADDR", FILTER_VALIDATE_IP);
        if ($ip != "" && $ip != $myself) {
            $block_file = \BitFire\BLOCK_DIR . DS . $ip;
            if (file_exists($block_file)) {
                // ip is still blocked
                if (filemtime($block_file) > time()) { 
                    $block = array("blocked IP address");
                    header("");
                    exit(include \BitFire\WAF_ROOT."views/block.php");
                }
                // ip block has expired
                else {
                    // whitelisted ips are never blocked
                    if (file_get_contents($block_file) != "allow") { unlink($block_file); }
                }
            }
        }
    }

    // enable/disable assertions via debug setting
    $active = (CFG::enabled("debug_header") || CFG::enabled("debug_file")) ? 1 : 0;
    $zend_assert = 99;
    if (defined("BitFire\ASSERT")) {
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
        })->then(function(\BitFire\Block $block) use ($bitfire) {
            if ($block->code > 0) {
                //debug("block 2 [%s]", print_r($bitfire->bot_filter->browser, true));
                if ($bitfire->bot_filter->browser->valid > 1 && CFG::enabled("dynamic-exceptions")) {
                    if (time() < CFG::int("dynamic-exceptions")) {
                        debug("add dynamic exception");
                        // use the API to add a dynamic exception
                        $r = new \BitFire\Request();
                        $r->post = array("path" => $bitfire->_request->path, "code" => $block->code, "param" => $block->parameter);
                        require_once \BitFire\WAF_SRC."api.php";
                        \BitFire\add_api_exception($r)->hide_output()->run();
                        return;
                    }
                }
                debug("block 3");
                debug(trace(null));
                exit(include \BitFire\WAF_ROOT."views/block.php");
            }
        });
}
catch (\Exception $e) {
    \BitFire\on_err($e->getCode(), $e->getMessage(), $e->getFile(), $e->getLine());
}

$m1 = microtime(true);
debug("bitfire [%dms] [%s]", round((($m1-$start_time)*1000),4), trace());//, utc_date("m/d @H.i.s"));
//file_put_contents("/tmp/xhr_profile.json", json_encode(xhprof_disable(), JSON_PRETTY_PRINT));
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

