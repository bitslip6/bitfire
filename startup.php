<?php declare(strict_types=1);
namespace BitFire;

// system root paths and timing
$GLOBALS['start_time'] = \microtime(true);
const DS = DIRECTORY_SEPARATOR;
define("WAF_DIR", realpath(__DIR__) . DS); 
define("BLOCK_DIR", WAF_DIR . DS . "blocks");

// create the block directory if it does not exist
if (!file_exists(BLOCK_DIR)) { \mkdir(BLOCK_DIR, 0700, true); }

include WAF_DIR."src/bitfire.php";
try {
    \TF\parse_ini(WAF_DIR."config.ini");
    \TF\debug("begin");

    if (Config::str('pro_key') && file_exists(WAF_DIR . "src/pro.php") ) { include WAF_DIR . "src/pro.php"; }
    $bitfire = \Bitfire\BitFire::get_instance(); 
    $bitfire->inspect()
        ->then(function (\BitFire\Block $block) use ($bitfire) {
            \TF\debug("block 1");
            $ip_data = ($bitfire->bot_filter !== null) ? $bitfire->bot_filter->ip_data : array();
            register_shutdown_function('\BitFire\post_request', $bitfire->_request, $block, $ip_data);
            \BitFire\block_ip($block, $ip_data);
            return $block;
        })->then(function(\BitFire\Block $block) {
            \TF\debug("block 2");
            if ($block->code > 0) {
                \TF\debug("block 3");
                include WAF_DIR."views/block.php";
                exit();
            }
        })
        ->doifnot(array($bitfire, 'cache_behind'));

    register_shutdown_function('\BitFire\post_request', $bitfire->_request, null, null);
    \TF\debug("end");
}
catch (\Exception $e) {
}

$m1 = microtime(true);
\TF\debug("time: [" . round((($m1-$GLOBALS['start_time'])*1000),3) . "ms] time: " . \TF\utc_date("m/d @H:i:s") . " GMT");
