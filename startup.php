<?php
namespace BitFire;

if (PHP_VERSION_ID < 70000) {
    header("x-bitfire: requires php 7.0");
    return;
}

function at(array $elm, $idx, $default) {
	if($elm && isset($elm[$idx])) {
		return $elm[$idx];
	}
	return $default;
}

//tideways_enable(TIDEWAYS_FLAGS_MEMORY | TIDEWAYS_FLAGS_CPU);

// system root paths and timing
$GLOBALS['start_time'] = \microtime(true);
const DS = DIRECTORY_SEPARATOR;
define("WAF_DIR", realpath(__DIR__) . DS); 
define("BLOCK_DIR", WAF_DIR . DS . "blocks");

include WAF_DIR."src/bitfire.php";
try {
    \TF\parse_ini(WAF_DIR."config.ini");
    \TF\debug("begin " . BITFIRE_SYM_VER);
    
    if (\BitFire\Config::enabled("allow_ip_block", false)) {
        $blockfile = BLOCK_DIR . DS . at($_SERVER, Config::str('ip_header', 'REMOTE_ADDR'), '127.0.0.1');
        if (file_exists($blockfile) && filemtime($blockfile) > time()) { 
            $m1 = microtime(true);
            \TF\debug("ip block: [" . round((($m1-$GLOBALS['start_time'])*1000),3) . "ms] time: " . \TF\utc_date("m/d @H.i.s") . " GMT");
            exit(include WAF_DIR."views/block.php");
        }
    }

    // todo: clean up
    if (Config::str('pro_key') && file_exists(WAF_DIR . "src/pro.php") ) { include WAF_DIR . "src/pro.php"; }
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
}

$m1 = microtime(true);
\TF\debug("time: [" . round((($m1-$GLOBALS['start_time'])*1000),3) . "ms] time: " . \TF\utc_date("m/d @H.i.s") . " GMT");
//echo "<!-- time: [" . round((($m1-$GLOBALS['start_time'])*1000),3) . "ms] time: " . \TF\utc_date("m/d @H.i.s") . " GMT -->";

//$data = array_filter(\tideways_disable(), function($elm) { return ($elm['ct'] > 2 || $elm['wt'] > 9 || $elm['cpu'] > 9); }); 
//uasort($data, '\TF\prof_sort');
//file_put_contents("/tmp/prof.pass.json", json_encode($data, JSON_PRETTY_PRINT));