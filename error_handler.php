<?php
namespace BitFire;

use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\httpp;
use BitFire\Config as CFG;


function on_err($errno, $errstr, $err_file, $err_line, $context = null): bool {
    static $to_send = [];

    // send any errors that have been queued
    if ($errno < -99) {
        array_walk($to_send, function ($data) {
            httpp(APP . "err.php?file={$data['err_file']}&line={$data['err_line']}", base64_encode(json_encode($data)));
        });
        return false;
    }

    // ignore errors that may not be ours...
    if (!strpos($err_file, 'bitfire')) {
        return false;
    }
    // ignore 404 errors fetching wordpress source code
    if (strpos($errstr, 'request failed')) {
        return false;
    }
    // don't allow infinite recursion...
    if (strpos($err_file, 'error_handler')) {
        return false;
    }

    $data = [
        'ver' => BITFIRE_VER,
        'type' => \BitFire\TYPE,
        'errno' => $errno,
        'errstr' => $errstr,
        'err_file' => $err_file,
        'err_line' => $err_line,
        'php_ver' => phpversion(),
    ];

    // check if we have already sent this error. 
    $known = json_decode(file_get_contents(\BitFire\WAF_ROOT . 'cache/errors.json'), true);
    foreach ($known as $err) {
        if (
            $err['errno'] == $data['errno'] &&
            $err['err_line'] == $data['err_line'] &&
            $err['err_file'] == $data['err_file']
        ) { return false; }
    }

    // debug data if we have it
    if (function_exists('ThreadFin\debug')) {
        $data['debug'] = debug(null);
        $data['trace'] = trace(null);
    }
    $known[] = $data;
    file_put_contents(\BitFire\WAF_ROOT . 'cache/errors.json', json_encode($known, JSON_PRETTY_PRINT));

    // if enabled, notify bitfire that an error occurred in the codebase
    if (
        (class_exists('Bitfire\Config') && CFG::enabled('send_errors')) &&
        function_exists("ThreadFin\httpp")
    ) {
        $data['bt'] = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
        $to_send[] = $data;
    }

    return false;
}

// capture any bitfire errors
$error_handler = set_error_handler('\BitFire\on_err');

// capture any bitfire fatal errors
// send any errors that have been queued after the page has been served
register_shutdown_function(function () {
    $e = error_get_last();
    // if last error was from bitfire, log it
    if (is_array($e) && $e['type'] ?? -1 == E_ERROR && stripos($e['file'] ?? '', 'bitfire') > 0) {
        on_err(1, $e['message'], "({$e['file']})", $e['line']);
    }

    // send any errors that have been queued after the page has been served
    on_err(-100, "", "", 0);
});
