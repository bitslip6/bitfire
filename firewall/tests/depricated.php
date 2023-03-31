<?php

// pulled from startup
/*
if (CFG::enabled("root_restrict")) {
    $base = doc_root() . ':' . ini_get('upload_tmp_dir'); // do not allow file access outside web files
    $tmpsz = ini_get("realpath.cache_size") || "4M";
    ini_set("open_basedir", $base);
    if (ini_get("realpath.cache_size") == 0) { ini_set("realpath.cache_size", $tmpsz); }
}
*/


//use function BitFireSvr\line_at_a_time;


/**
 * return a single line from a file at a time
 */
function line_at_a_time(string $filename): iterable
{
    $r = fopen($filename, 'r');
    if (!$r) {
        return;
    }

    while (($line = fgets($r)) !== false) {
        yield trim($line);
    }
}



/**
 * process an access file 
 */
function process_access_file(string $file_name): array
{
    if (!file_exists($file_name)) {
        return array();
    }
    $batch_size = 0;
    $batch = array();
    $exceptions = array();
    foreach (line_at_a_time($file_name) as $line) {
        if ($batch_size++ >= 200) {
            $exceptions = array_merge($exceptions, process_batch($batch));
            $batch_size = 0;
            $batch = array();
        }
        $batch[] = $line;
    }

    return array_merge($exceptions, process_batch($batch));
}

function block_to_exception(?\BitFire\Block $block): ?\BitFire\Exception
{
    if (!$block) {
        return NULL;
    }
    $exception = new \BitFire\Exception();
    $exception->code = $block->code;
    $exception->url = \BitFire\Bitfire::get_instance()->_request->path;
    $exception->parameter = $block->parameter;
    //$exception->ip = \BitFire\BitFire::get_instance()->_request->ip;

    return $exception;
}


function process_batch(array $lines)
{
    $requests = array_map('\BitFireSvr\process_access_line', $lines);
    $requests = array_filter($requests, function (?\BitFire\Request $x) {
        return $x === NULL ? false : true;
    });
    $browser_requests = array_filter($requests, '\BitFireSvr\is_browser_request');

    $batch_req = array_filter($requests, function ($r) use ($browser_requests) {
        foreach ($browser_requests as $r2) {
            if ($r2->ip === $r->ip) {
                return true;
            }
        }
        return false;
    });


    $bitfire = \BitFire\BitFire::get_instance();
    $exceptions = array_reduce($batch_req, function ($carry, $request) use ($bitfire) {
        $bitfire->_request = $request;
        $maybe_block = $bitfire->inspect();
        $maybe_block->then('\BitFireSvr\block_to_exception');
        $maybe_block->then(function ($x) use (&$carry) {
            $carry[] = $x;
        });
        return $carry;
    }, array());

    return $exceptions;
}
