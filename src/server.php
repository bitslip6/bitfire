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
 * convert string version number to unsigned 32bit int
 */
function text_to_int(string $ver) {
    $result = 0;
    $ctr = 1;
    $parts = array_reverse(explode(".", $ver));
    foreach ($parts as $part) {
        $p2 = intval($part) * ($ctr);
        $result += $p2;
        $ctr*=100;
    }
    return $result;
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

// strip the wordpress or plugin root from the filename
function strip_root(string $file) : string {
    return str_replace(trim($_SERVER['DOCUMENT_ROOT'], '/'), 'src', trim($file, '/'));
}


// run the hash functions on a file
function hash_file(string $filename, string $sym_ver) : ?array {
    $filename = str_replace("//", "/", $filename);
    $i = pathinfo($filename);
    if ($i['extension'] !== "php") { return null; }
    $result = array();
    $shortname  = strip_root($filename);

    $result['e'] = $i['extension'];
    $t = "/{$sym_ver}/{$shortname}";
	$result['t'] = crc32(join('', array_map('trim', file($filename))));
    $result['p'] = crc32($t);
    $result['f'] = $t;

    return $result;
}

function find_wordpress_root(string $root_dir) : array {
    $roots = \TF\file_recurse($root_dir, function($file) : string {
        $d = dirname(realpath($file), 2);
        //echo "\n\n - $d -\n\n";
        return $d;
    }, '/wp-includes\/version.php$/');
    //\TF\dbg($roots);
    return $roots;
}

function get_wordpress_version(string $root_dir) : string {
    $full_path = "$root_dir/wp-includes/version.php";
    $wp_version = "0";
    include_once $full_path;
    if ($wp_version === "0") { die("WTF?\n"); }
    return \TF\trim_off($wp_version, "-");
}


/**
 * return an array of ('filename', size, crc32(path), crc32(space_trim_content))
 */
function get_wordpress_hashes(string $root_dir) : array {

    $version = get_wordpress_version($root_dir);
    if (version_compare($version, "5.0.0") < 0) { return array("ver" => $version, "int" => "too low", "files" => array()); }

    $r = \TF\file_recurse($root_dir, function($file) use ($root_dir, $version) : array {
        $path = str_replace($root_dir, "/$version/src", $file);
        $nospace_data = join('', array_map('trim', file($file)));
        // is plugin
        if (stripos($path, "/wp-content/plugins/") !== false) {
            if (preg_match("/\/plugins\/(\w+)/", $path, $matches)) {
                $plugin = $matches[1];
                $path = str_replace("/$version/src/wp-content/plugins/$plugin", "", $path);
                return array($plugin, filesize($file), crc32($path), crc32($nospace_data));//, basename($path));
            }
        }
        return array('', filesize($file), crc32($path), crc32($nospace_data), basename($path));
    }, "/.*\.php$/");

    return array("ver" => $version, "root" => $root_dir, "int" => text_to_int($version), "files" => array_splice($r, 0, 1000));
}


/**
 * returns output of $fn if $fn output evaluates to true
 */
function if_it(callable $fn, $item) {
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


function pattern_to_list_3(array $patterns) :array {
    return append_reduce('glob', $patterns);
}


/**
 * get a list of all http configuration files on the target system 
 */
function get_all_http_confs() : array {
    return \BitFireSvr\pattern_to_list_3(\BitFireSvr\get_server_config_file_list());
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


    return $data->empty() ? NULL : $data->value();
}


function block_to_exception(?\BitFire\Block $block) : ?\BitFire\Exception {
    if (!$block) { return NULL; }
    $exception = new \BitFire\Exception();
    $exception->code = $block->code;
    $exception->url = \BitFire\Bitfire::get_instance()->_request->path;
    $exception->parameter = $block->parameter;
    //$exception->ip = \BitFire\BitFire::get_instance()->_request->ip;

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
    $exceptions = array();
    foreach (line_at_a_time($file_name) as $line) {
        if ($batch_size++ >= 500) {
            $exceptions = array_merge($exceptions, process_batch($batch));
            $batch_size = 0;
            $batch = array();
        }
        $batch[] = $line;
    }

    return array_merge($exceptions, process_batch($batch));
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
        $maybe_block = $bitfire->inspect();
        $maybe_block->then('\BitFireSvr\block_to_exception');
        $maybe_block->then(function($x) use (&$carry) { $carry[] = $x; });
        return $carry;
    }, array());

    return $exceptions;
}

