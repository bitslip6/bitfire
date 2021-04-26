<?php declare(strict_types=1);
namespace BitFire;

//tideways_enable(TIDEWAYS_FLAGS_MEMORY | TIDEWAYS_FLAGS_CPU); 

// system root paths and timing
$m0 = \microtime(true);
const DS = DIRECTORY_SEPARATOR;
define("BLOCK_DIR", sys_get_temp_dir() . DS . "_BITFIRE_BLOCKS");
define("WAF_DIR", realpath(__DIR__) . DS); 
// create the block directory if it does not exist
if (!file_exists(BLOCK_DIR)) { \mkdir(BLOCK_DIR, 0700, true); }

include WAF_DIR."bitfire.php";
try {
    \TF\parse_ini(WAF_DIR."config.ini");

    if (Config::str('pro_key')) { include WAF_DIR . "pro.php"; }
    $bitfire = \Bitfire\BitFire::get_instance(); 
    $bitfire->inspect()
        ->then(function (\BitFire\Block $block) use ($bitfire) {
            $ip_data = ($bitfire->bot_filter !== null) ? $bitfire->bot_filter->ip_data : array();
            \BitFire\block_ip($block, $ip_data);
            //register_shutdown_function('\\BitFire\\post_request', $bitfire->_request, $block, $ip_data);
            return $block;
        })
        ->then(function($block) use ($m0) {
            if ($block->code > 0) {
                include WAF_DIR."views/block.php";
                exit();
            }
        })
        ->doifnot(array($bitfire, 'cache_behind'));

    //register_shutdown_function('\BitFire\post_request', $bitfire->_request, null, null);
}
catch (\Exception $e) {
}

$m1 = microtime(true);
//$data = array_filter(\tideways_disable(), function($elm) { return ($elm['ct'] > 2 || $elm['wt'] > 9 || $elm['cpu'] > 9); }); 
//uasort($data, '\TF\prof_sort');
//file_put_contents("/tmp/prof.pass.json", json_encode($data, JSON_PRETTY_PRINT));
