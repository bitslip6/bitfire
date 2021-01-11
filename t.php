<?php
define("WAF_DIR", realpath(__DIR__) . "/"); 

include "storage.php";

$cache = new \TF\CacheStorage('shm');
//$cache->save_data("config.ini", parse_ini_file("config.ini", false, INI_SCANNER_TYPED), 50);
//echo "saved config\n";

function read_config() { return parse_ini_file("config.ini", false, INI_SCANNER_TYPED); }

function test_parse() : string {
	$r = parse_ini_file("config.ini", false, INI_SCANNER_TYPED);
	return strval(count($r));
}

function test_shmop() : string {
	$cache = \TF\CacheStorage::get_instance();
	$r = $cache->load_or_cache("config.ini", 50, "read_config");
print_r($r);
	return strval(count($r));
}
