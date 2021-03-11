<?php declare(strict_types=1);
namespace BitFireSvr;

use BitFire\BitFire;

use function TF\ends_with;

const ACCESS_URL = 5;
const ACCESS_CODE = 6;
const ACCESS_ADDR = 0;
const ACCESS_REFERER = 8;
const ACCESS_AGENT = 9;
const ACCESS_URL_PROTO = 2;
const ACCESS_QUERY = 10;
const ACCESS_HOST = 11;
const ACCESS_URL_METHOD = 12;
const ACCESS_URL_URI = 13;


/**
 * return a single line from a file at a time
 */
function line_at_a_time(string $filename) : iterable {
    $r = fopen($filename, 'r');
    while (($line = fgets($r)) !== false) {
        yield trim($line);
    }
}

/**
 * recursively reduce list by fn, result is an array of output of fn for each list item
 * fn should output an array list for each list item, the result will be all items appended
 */
function append_reduce(callable $fn, array $list) : array {
    return array_reduce($list, function ($carry, $x) use ($fn) {
        return array_reduce($fn($x), function ($carry, $x) {
            $carry[] = $x;
            return $carry;
        }, $carry);
    }, array());
}

/**
 * returns output of $fn if $fn output evaluates to true
 */
function if_it(callable $fn, $item) : mixed {
    $r = $fn($item);
    return ($r) ? $r : NULL;
}


function get_server_config_file_list() :array {
    return array(
        "/etc/nginx/*.conf", 
        "/usr/local/etc/nginx/*.conf", 
        "/usr/local/nginx/*.conf", 
        "/opt/homebrew/etc/nginx/*.conf", 
        "/etc/httpd/*.conf",
        "/etc/httpd/conf/*.conf",
        "/etc/apache/*.conf",
        "/etc/apache2/*.conf",
        "/usr/local/apache2/*.conf",
        "/usr/local/etc/apache2/*.conf",
        "/usr/local/etc/httpd/*.conf"
    );
}

function pattern_to_list_1(array $patterns) :array {

    $all_files = array();
    foreach ($patterns as $pattern) {
        $pattern_files = glob($pattern);
        foreach ($pattern_files as $file) {
            $all_files[] = $file;
        }
    }
    return $all_files;
}


function pattern_to_list_2(array $patterns) :array {
    $result = array_reduce($patterns, function ($carry, $x)  {
        return array_reduce(glob($x), function ($carry, $x) {
            $carry[] = $x;
            return $carry;
        }, $carry);
    }, array());

    return $result;
}

function pattern_to_list_3(array $patterns) :array {
    return append_reduce('glob', $patterns);
}


/**
 * get a list of all http configuration files on the target system 
 */
function get_all_http_confs() : array {
    return \BitFireSvr\pattern_to_list(\BitFireSvr\get_server_config_file_list());
}

/**
 * process an access line into request object
 */
function process_access_line_orig(string $line) : ?\BitFire\Request {
    $parts = str_getcsv($line, " ", '"');

    if ($parts[ACCESS_CODE] > 399) { return NULL; }

    $url_parts = explode(" ", $parts[ACCESS_URL]);
    $url = parse_url($url_parts[ACCESS_URL_URI]);

    $server = array(
        "REMOTE_ADDR" => $parts[ACCESS_ADDR], 
        "REQUEST_METHOD" => $url_parts[ACCESS_URL_METHOD], 
        "QUERY_STRING" => $url['query'], 
        "HTTP_HOST" => $url['host'],
        "HTTP_REFERER" => $parts[ACCESS_REFERER],
        "HTTP_USER_AGENT" => $parts[ACCESS_AGENT],
        "HTTP_REQUEST_URI" => $url_parts[ACCESS_URL_URI]
    );

    parse_str($url['query'], $get);
    $r = \BitFire\process_request2($get, array(), $server, array());
    return $r;
}



/**
 * test for valid http return code
 */
function have_valid_http_code(array $access_line) : bool {
    assert(isset($access_line[ACCESS_CODE]));

    return $access_line[ACCESS_CODE] < 399;
}

/**
 * take access line and break up ACCESS_URL "GET host://path?query HTTP/1.1"
 * add method and url to input data and return result
 */
function split_request_url(array $access_line) : array {
    assert(isset($access_line[ACCESS_URL]));

    // split the initial line to get METHOD and URI (ignore protocol)
    $url_parts = \explode(" ", $access_line[ACCESS_URL]);
    $access_line[ACCESS_URL_METHOD] = $url_parts[0];
    $access_line[ACCESS_URL_URI] = $url_parts[1];

    // split host and query string from the access line URI
    $url = \parse_url($access_line[ACCESS_URL_URI]);
    $access_line[ACCESS_HOST] = $url['host'] ?? 'localhost';
    $access_line[ACCESS_QUERY] = $url['query'] ?? '';

    // print_r($access_line);
    return $access_line;
}

/**
 * map an http access line into a PHP $_SERVER structured array
 */
function map_access_line_to_server_array(array $access_line) : array {
    assert(count($access_line) >= ACCESS_URL_URI);

    return array(
        "REMOTE_ADDR" => $access_line[ACCESS_ADDR], 
        "REQUEST_METHOD" => $access_line[ACCESS_URL_METHOD], 
        "QUERY_STRING" => $access_line[ACCESS_QUERY], 
        "HTTP_HOST" => $access_line[ACCESS_HOST],
        "HTTP_REFERER" => $access_line[ACCESS_REFERER],
        "HTTP_USER_AGENT" => $access_line[ACCESS_AGENT],
        "REQUEST_URI" => $access_line[ACCESS_URL_URI],
        "QUERY_STRING" => $access_line[ACCESS_QUERY]
    );
}

/**
 * map an nginx access line to a request object
 */
function process_access_line(string $line) : ?\BitFire\Request {
    // parse quoted strings in access log line
    $data = \TF\Maybe::of(\str_getcsv($line, " ", '"'));

    $data->if('\BitFireSvr\have_valid_http_code');
    $data->then('\BitFireSvr\split_request_url');
    $data->then('\BitFireSvr\map_access_line_to_server_array');
    $data->then(function (array $server) {
        parse_str($server['QUERY_STRING']??'', $get); // parse get params into array of parameters
        return \BitFire\process_request2($get, array(), $server, array());
    });

/*
    if ($data->empty()) {
        print_r($data->errors());
    }
*/

    return $data->empty() ? NULL : $data->value();
}


function block_to_exception(\BitFire\Block $block) : ?\BitFire\Exception {
    $exception = new \BitFire\Exception();
    $exception->code = $block->code;
    $exception->url = \BitFire\Bitfire::get_instance()->_request->path;
    $exception->parameter = $block->parameter;
    $exception->ip = \BitFire\BitFire::get_instance()->_request->ip;

    return $exception;
}

function is_browser_request(?\BitFire\Request $request) {
    $path = $request->path ?? '/';
    $info = pathinfo($path);
/*
    ($z = strrchr($path, '.'));
    $idx = ($z !== false) ? $z : 0;
    echo "path: ($path) [$idx]\n";
    $extension = substr($path, strrchr($request->path, '.'), strlen($request->path));
    echo "EXT [$path] = ($extension)\n";
    die();
*/
    return in_array($info['extension'] ?? '', array("css", "js", "jpeg", "jpeg", "png", "gif"));
}


/**
 * process an access file 
 */
function process_access_file(string $file_name) : array {

    $batch_size = 0;
    $batch = array();
    foreach(line_at_a_time($file_name) as $line) {
        if ($batch_size++ >= 500) {
            process_batch($batch);
            $batch_size = 0;
        }
        $batch[] = $line;
    }

    process_batch($batch);

    return $batch;
}

function process_batch(array $lines) {
    $requests = array_map('\BitFireSvr\process_access_line', $lines);
    $requests = array_filter($requests, function (?\BitFire\Request $x) { return $x === NULL ? false : true ;} );
    $browser_requests = array_filter($requests, '\BitFireSvr\is_browser_request');

    $batch_req = array_filter($requests, function ($r) use ($browser_requests) {
        foreach ($browser_requests as $r2) {
            if ($r2->ip === $r->ip) { return true; }
        }
        return false;
    });

    
    $bitfire = \BitFire\BitFire::get_instance();
    $exceptions = array_reduce($batch_req, function ($carry, $request) use ($bitfire) {
        $bitfire->_request = $request;
        print_r($request);
        $maybe_block = $bitfire->inspect();
        $carry[] = $maybe_block->if('block_to_exception')();
        return $carry;
    }, array());
print_r($exceptions);
    //$maybe_block = $bitfire->inspect();

    

    //print_r($batch_req);
    /*
    foreach ($browser_requests as $b) {
        echo "ip : " . $b->ip . "\n";
    }

    echo "count - " . count($browser_requests) . "\n";
    echo "count - " . count($batch_req) . "\n";
    echo "count - " . count($requests) . "\n";
*/

    
/*
    foreach ($requests as $r) {
        echo "path: " . $r->path . "\n";
    }
*/

    //print_r($browser_requests);
    die("HERE\n");
//echo "======\n";
//    print_r($browser_requests);
    die("find out\n");
}

/*
    $bitfire = \BitFire\BitFire::get_instance();
    $exceptions = array();
    $good_browsers = array();
    foreach(line_at_a_time($file_name) as $line) {
        $bitfire->_request = process_access_line($line);
        $maybe_block = $bitfire->inspect();
        $exceptions[] = $maybe_block->if('block_to_exception')();
        if (is_browser_request($bitfire->_request)) {
            $good_browsers[$bitfire->_request->ip] = true;
        }
    }

    return array_filter($exceptions, function($item) { return ($item == false) ? false : true; } );
}
*/
