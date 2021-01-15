<?php declare(strict_types=1);
namespace BitFire;

//\tideways_enable(TIDEWAYS_FLAGS_MEMORY | TIDEWAYS_FLAGS_CPU); 

// system root paths and timing
$m0 = \microtime(true);
const DS = DIRECTORY_SEPARATOR;
define("BLOCK_DIR", sys_get_temp_dir() . DS . "_BITFIRE_BLOCKS");
define("WAF_DIR", realpath(__DIR__) . DS); 
// create the block directory if it does not exist
if (!file_exists(BLOCK_DIR)) { \mkdir(BLOCK_DIR, 0700, true); }

include WAF_DIR."bitfire.php";
try {
	\BitFire\Config::set(parse_ini_file(WAF_DIR . "config.ini", false, INI_SCANNER_TYPED));

    $bitfire = \Bitfire\BitFire::get_instance(); 
    $bitfire->inspect()
        ->then('\BitFire\Reporting')
        ->then(function ($block) use ($bitfire) {
            $ip_data = ($bitfire->bot_filter !== null) ? $bitfire->bot_filter->ip_data : array();
            \BitFire\block_ip($block, $ip_data);
            register_shutdown_function('\\BitFire\\post_request', $bitfire->_request, $block, $ip_data);
            return $block;
        })
        ->then(function($block) use ($m0) {
            include WAF_DIR."views/block.php";
            exit();
        })
        ->doifnot(array($bitfire, 'cache_behind'));

    register_shutdown_function('\BitFire\post_request', $bitfire->_request, null, null);
}
catch (\Exception $e) {
}

$m1 = microtime(true);
//$data = array_filter(\tideways_disable(), function($elm) { return ($elm['ct'] > 2 || $elm['wt'] > 9 || $elm['cpu'] > 9); }); 
//file_put_contents("/tmp/pass.json", json_encode($data, JSON_PRETTY_PRINT));