<?php declare(strict_types=1);
namespace BitFire;

//\tideways_enable(TIDEWAYS_FLAGS_MEMORY | TIDEWAYS_FLAGS_CPU); 

// system root paths and timing
$m0 = microtime(true);
const DS = DIRECTORY_SEPARATOR;
define("BLOCK_DIR", sys_get_temp_dir() . DS . "_BITFIRE_BLOCKS");
define("WAF_DIR", realpath(__DIR__) . DS); 
// create the block directory if it does not exist
if (!file_exists(BLOCK_DIR)) {
    mkdir(BLOCK_DIR, 0700, true);
}

include WAF_DIR."bitfire.php";
include WAF_DIR."headers.php";
try {
	\BitFire\Config::set(parse_ini_file(WAF_DIR . "config.ini", false, INI_SCANNER_TYPED));
	$bitfire = \BitFire\BitFire::get_instance();
	\BitFireHeader\send_security_headers($bitfire->_request);
	$block = $bitfire->inspect();

	if (!$block->empty()) {
		//$data = array_filter(\tideways_disable(), function($elm) { return ($elm['ct'] > 2 || $elm['wt'] > 9 || $elm['cpu'] > 9); }); 
		//file_put_contents("/tmp/block.json", json_encode($data, JSON_PRETTY_PRINT));
        \http_response_code(Config::int('response_code', 500));
		include WAF_DIR."views/block.php";
	}
	\BitFire\BitFire::get_instance()->cache_behind();
} 
catch (\Exception $e) {
}

$m1 = microtime(true);
// ini_set("realpath_cache_size", "4M");
// ini_set("realpath_cache_ttl", "500");



//$data = array_filter(\tideways_disable(), function($elm) { return ($elm['ct'] > 2 || $elm['wt'] > 9 || $elm['cpu'] > 9); }); 
//file_put_contents("/tmp/pass.json", json_encode($data, JSON_PRETTY_PRINT));