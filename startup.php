<?php

namespace BitFire;

use BitFire\Config as CFG;
use function BitFirePlugin\is_admin;
use function ThreadFin\debug;
use function ThreadFin\output_profile;
use function ThreadFin\parse_ini;
use function ThreadFin\trace;
use ThreadFin\MaybeBlock;

// enable php assertions
const ASSERT = true;

// do not double include
if (defined('BitFire\\WAF_ROOT')) {
    header('x-bitfire: plug inc 2x');
    return;
}
// PHP version guard
if (PHP_VERSION_ID < 70000) {
    header('x-bitfire: requires php >= 7.1');
    return;
}

// enable/disable assertions via debug setting
if (ASSERT) {
    // $zend_assert = assert_options(ASSERT_ACTIVE);
    $zend_assert = @assert_options(ASSERT_ACTIVE, ASSERT);
    @ini_set('zend.assertions', ASSERT);
} else {
    $zend_assert = assert_options(ASSERT_ACTIVE, 0);
}



// system root paths and firewall timing info
$GLOBALS['start_time'] = microtime(true);
const DS = DIRECTORY_SEPARATOR;
if (!defined('BitFire\WAF_ROOT')) {
    define('BitFire\WAF_ROOT', realpath(__DIR__) . DS);
    define('BitFire\BLOCK_DIR', \BitFire\WAF_ROOT . 'blocks');
    define('BitFire\WAF_SRC', \BitFire\WAF_ROOT . 'src' . DS);
    define('BitFire\TYPE', '__TYPE__');
    define('ThreadFin\view\VIEW_ROOT', WAF_ROOT . "views");
    define('ThreadFin\VIEW_ROOT', WAF_ROOT . "views");
}

// start the profiler if we have one
if (function_exists('xhprof_enable') && file_exists(WAF_ROOT . "profiler.enabled")) {
    xhprof_enable(XHPROF_FLAGS_CPU + XHPROF_FLAGS_MEMORY);
}


// load the firewall program code
include \BitFire\WAF_ROOT . 'error_handler.php';
include \BitFire\WAF_SRC . 'bitfire.php';

try {
    // load the config file
    CFG::set(parse_ini());
    debug('  --> bitfire %s [%s:%s] @%s', BITFIRE_SYM_VER, $_SERVER['REQUEST_METHOD'], substr($_SERVER['REQUEST_URI'], 0, 80), date('D M j G:i:s'));

    // handle IP level blocks
    if (CFG::enabled('allow_ip_block')) {
        include \BitFire\WAF_ROOT . 'ip_blocking.php';
    }

    // call any required bitfire setup code
    bitfire_init();
    
    $bitfire = \Bitfire\BitFire::get_instance();
    $bitfire->inspect()
        ->then(function ($block) use ($bitfire) {
            // TODO: ensure MaybeBlock can only have the type Block
            if ($block instanceof MaybeBlock) { $block = $block(); }
            trace('BL1');
            $ip_data = $bitfire->bot_filter !== null ? $bitfire->bot_filter->ip_data : null;
            register_shutdown_function(
                '\BitFire\post_request',
                $bitfire->_request,
                $block,
                $ip_data
            );
            // block the IP (will check if IP blocks are enabled)
            \BitFire\block_ip($block, $bitfire->_request)->run();
            return $block;
        })
        ->then(function ($block) use ($bitfire) {
            if ($block instanceof MaybeBlock) { $block = $block(); }
            $valid_browser = $bitfire->bot_filter->browser->valid;
            if ($block->code > 0) {
                // make an exception if dynamic exceptions are enabled 
                if ($valid_browser > 1 && CFG::enabled('dynamic_exceptions')) {
                    if (time() < CFG::int('dynamic_exceptions')) {
                        debug('add dynamic exception');
                        // use the API to add a dynamic exception
                        $r = new \BitFire\Request();
                        $r->post = [
                            'path' => $bitfire->_request->path,
                            'code' => $block->code,
                            'param' => $block->parameter,
                        ];
                        require_once \BitFire\WAF_SRC . 'api.php';
                        \BitFire\add_api_exception($r)
                            ->hide_output()
                            ->run();
                        return;
                    }
                }
                trace('BL3');
                \BitFire\block_now($block->code, $block->parameter, $block->value, $block->pattern, $block->block_time)
                    ->run();
            }
        });

    // firewall rules passed. lock the site if we are licensed
    if (cfg::enabled('rasp_filesystem') && function_exists('BitFirePRO\site_lock')) {
        $is_admin =false;
        // this should be abstracted to support auto load and wordpress loading
        // don't site lock administrators
        if (function_exists('BitFirePlugin\is_admin') && is_admin()) {
            $is_admin = is_admin();
        }
        if (!$is_admin) {
            // don't site lock cached administrators
            if ($bitfire->cookie && $bitfire->cookie->extract('wp')->value('int') > 1) {
                $is_admin = true;
                // don't site lock updates (auto updates, etc)
                if ($bitfire->_request->path != '/wp-admin/update.php') {
                    $is_admin = false;
                }
            }
        }

        // we don't want to check the FS for admins, (or authenticated bots?)
        if (! $is_admin && !$bitfire->bot_filter->browser->whitelist) {
            \BitFirePRO\site_lock();
        }
    }
} catch (\Exception $e) {
    \BitFire\on_err($e->getCode(), $e->getMessage(), $e->getFile(), $e->getLine());
}

$m1 = microtime(true);
debug('complete [%.2fms] [%s]', ($m1 - $GLOBALS['start_time']) * 1000, trace());

if (function_exists('xhprof_enable') && file_exists(WAF_ROOT . "profiler.enabled")) {
    $data = xhprof_disable();
    file_put_contents('/tmp/xhr_profile.json', json_encode($data, JSON_PRETTY_PRINT));
    output_profile($data);
    $data = array_filter($data, function ($elm) {
        return $elm['wt'] > 100 || $elm['cpu'] > 100;
    });
    uasort($data, '\ThreadFin\prof_sort');
    file_put_contents('/tmp/xhr_profile.min.json', json_encode($data, JSON_PRETTY_PRINT));
}

// clean up the error handler and assertion settings
restore_error_handler();
// restore default assertion level
assert_options(ASSERT_ACTIVE, $zend_assert);

// add support for startup chaining
$autoload = CFG::str('auto_prepend_file');
if (!empty($autoload) && file_exists($autoload)) {
    @include $autoload;
}

// test blocking if we are in learning mode
if (isset($_GET['bitfire_test']) && CFG::enabled('dynamic_exceptions')) {
    $code = intval($_GET['bitfire_test']);
    block_now($code, 'test_block', 'Lorem ipsum dolor sit amet, consectetur adipiscing elit,
        sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.', 'block_pattern')
        ->run();
}
