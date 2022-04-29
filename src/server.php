<?php
namespace BitFireSvr;

use BitFire\BitFire;
use BitFire\Config as CFG;
use RuntimeException;

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
 * call replace function $fn if config $param = $value.  replace with $new_value
 */
function replace_if_config(string $param, string $value, callable $fn, string $new_value) : bool {
    if (CFG::str($param) == $value) { return $fn("$param = '$value'", "$param = '$new_value'"); }
    return false;
}

/**
 * update all system config values from defaults
 */
function update_config(string $ini_src) {
    $info = $_SERVER;
    $info["writeable"] = false;
    $info["cookie"] = 0;
    $info["robot"] = false;
    @chmod($ini_src, 0644);
    if (is_writeable($ini_src)) {
        $info["writeable"] = true;

        $replace_fn = \TF\partial('\TF\file_replace', $ini_src);
        $info["encryption"] = replace_if_config("encryption_key", "default_encryption_key", $replace_fn, \TF\random_str(32));
        $info["secret"] = replace_if_config("secret", "default_secret_value", $replace_fn, \TF\random_str(32));
        $info["cookie"] = replace_if_config("browser_cookie", "_bitfire", $replace_fn, '_' . \TF\random_str(5));

        // configure wordpress root path
        $root = \BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']);
        if (!empty($root)) {
            $info["wp_root_path"] = $root;
            $info["wp_root"] = \TF\file_replace($ini_src, "wp_root = \"\"", "wp_root = \"$root\"");
            $info["password"] = replace_if_config("password", "_bitfire", $replace_fn, '_' . \TF\random_str(5));
        } else {
            $info["wp_root"] = "WordPress not found.";
        }

        // configure caching
        if (CFG::str("cache_type") === "nop") {
            if (function_exists('shmop_open')) {
                $info["cache_type"] = "shmop " . \TF\b2s(\TF\file_replace($ini_src, "cache_type = \"nop\"", "cache_type = \"shmop\""));
            }
            else if (function_exists('apcu')) {
                $info["cache_type"] = "acpu " . \TF\b2s(\TF\file_replace($ini_src, "cache_type = \"nop\"", "cache_type = \"apcu\""));
            }
            else if (function_exists('shm_get_var')) {
                $info["cache_type"] = "shm " . \TF\b2s(\TF\file_replace($ini_src, "cache_type = \"nop\"", "cache_type = \"shm\""));
            }
        } 
        // log what the setting is/was
        if (!isset($info["cache_type"])) {
            $info["cache_type"] = CFG::str("cache_type");
        }


        // X forwarded for header
        if (isset($_SERVER['X-FORWARDED-FOR'])) {
            $info["x-forward"] = \TF\b2s(\TF\file_replace($ini_src, "ip_header = \"REMOTE_ADDR\"", "ip_header = \"X-FORWARDED-FOR\""));
        } else {
            $info["x-forward"] = "no";
        }

        // new forwarded for header
        if (isset($_SERVER['FORWARDED'])) {
            $info["forward"] = \TF\b2s(\TF\file_replace($ini_src, "ip_header = \"REMOTE_ADDR\"", "ip_header = \"FORWARDED\""));
        } else {
            $info["forward"] = "no";
        }

        
        // are any cookies set?
        if (count($_COOKIE) > 1) {
            $info["cookies"] = count($_COOKIE);
            $info["cookie"] = \TF\b2s(\TF\file_replace($ini_src, "cookies_enabled = false", "cookies_enabled = true"));
        } else {
            $info["cookies"] = "< 2";
        }

        $domain = \TF\take_nth($_SERVER['HTTP_HOST'], ":", 0);
        $info["domain_value"] = $domain;
        $domain = join(".", array_slice(explode(".", $domain), -2));

        $info["domain"] = \TF\b2s(\TF\file_replace($ini_src, "valid_domains[] = \"\"", "valid_domains[] = \"$domain\""));
        $info["configured"] = \TF\b2s(\TF\file_replace($ini_src, "configured = false", "configured = true"));

        $url = CFG::str("honeypot_url");
        if (!empty($url)) {
            $robot_file = $_SERVER['DOCUMENT_ROOT']."/robots.txt";
            $robot_content =  "User-agent: *\nDisallow: ".CFG::str("honeypot_url", "/supreme/contact")."\n";
            if (file_exists($robot_file)) {
                $info["robot_file"] = "exists";
                $content = file_get_contents($robot_file);
                if (strstr($content, CFG::str("honeypot_url")) == false) {
                    $info["robot"] = file_put_contents($robot_file, $robot_content, FILE_APPEND);
                } else {
                    $info["robot"] = "already added";
                }
            } else {
                $info["robot_file"] = "missing";
                $info["robot"] = file_put_contents($robot_file, $robot_content, FILE_APPEND);
            }
        } else {
            $info["robot"] = "no path";
        }

        require_once WAF_DIR."src/bitfire.php";
        $info["cache_keys"] = update_raw(WAF_DIR."cache/keys2.raw", WAF_DIR."cache/values2.raw");
        file_put_contents(WAF_DIR."/cache/install.log", json_encode($info, JSON_PRETTY_PRINT));

        \TF\bit_http_request("POST", "https://bitfire.co/zxf.php", base64_encode(json_encode($info))); // save server config info
    }
    // ping back home that we are unable to edit config
    else if (mt_rand(1,30) == 2) {
        \TF\bit_http_request("POST", "https://bitfire.co/zxf.php", base64_encode(json_encode($info))); // save server config info
    }
}

/**
 * return a single line from a file at a time
 */
function line_at_a_time(string $filename) : iterable {
    $r = fopen($filename, 'r');
    if (!$r) { return; }

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
function hash_file(string $filename, string $root_dir, string $plugin_id, string $plugin_name) : ?array {
    if (is_dir($filename)) { return null; }
    if (!is_readable($filename)) { return null; }
    $filename = str_replace("//", "/", $filename);
    $i = pathinfo($filename);
    $input = @file($filename);
    if (!isset($i['extension']) || $i['extension'] !== "php" || empty($input)) { return null; }

    $shortname = str_replace($root_dir, "", $filename);
    if (strpos($filename, "wp-content/")) {
        if (strpos($filename, "/plugins/") !== false) {
            //$shortname = preg_replace("#$root_dir/wp-content/plugins#", "", $filename);
            //$shortname = str_replace("$root_dir/wp-content/plugins", "", $filename);
            $shortname = str_replace("$root_dir", "", $filename);
        } else if (strpos($filename, "/themes/") !== false) {
            //$shortname = preg_replace("#$root_dir/wp-content/themes#", "", $filename);
            //$shortname = str_replace("$root_dir/wp-content/themes", "", $filename);
            $shortname = str_replace("$root_dir", "", $filename);
        }
    }

    if (strpos($shortname, "/home/wp-hashes") !== false) { file_put_contents("/tmp/path_err.log", print_r(array($root_dir, $filename, $plugin_id, $plugin_name), true), FILE_APPEND); }

    $result = array();
	$result['crc_trim'] = crc32(join('', array_map('trim', $input)));
    $result['crc_path'] = crc32($shortname);
    $result['path'] = substr($shortname, 0, 255);
    $result['name'] = $plugin_name;
    $result['plugin_id'] = $plugin_id;
    $result['size'] = filesize($filename);

    if (function_exists('find_malware')) {
        $result['malware'] = find_malware($input);
    }

    return $result;
}

/**
 * return the wordpress root directory
 * @param string $root_dir the path to search for wordpress in
 * @return null|string absolute path to wordpress root dir or NULL
 */
function find_wordpress_root(string $root_dir) : ?string {
    $cfgpath = CFG::str("wp_root");
    if (strlen($cfgpath) > 5) { return $cfgpath; }
    $roots = \TF\file_recurse($root_dir, function($file) : string {
        return dirname(realpath($file), 2);
    }, '/wp-includes\/version.php$/');

    return (isset($roots[0])) ? $roots[0] : NULL;
}

/**
 * get the wordpress version from a word press root directory
 */
function get_wordpress_version(string $root_dir) : string {
    $full_path = "$root_dir/wp-includes/version.php";
    $wp_version = "0";
    if (file_exists($full_path)) {
        include $full_path;
    }
    return \TF\trim_off($wp_version, "-");
}


function hash_dir(string $dir) : array {
    return \TF\file_recurse($dir, function($file) use ($dir) : ?array {

        if (is_link($file)) { return NULL; }
        if (strpos($file, "wp-content") !== false) {
            if (preg_match('#wp-content/(plugins|themes)/([^\/]+)#', $file, $matches)) {
                $type = strpos($file, '/plugins/') !== false ? 1 : 2;
                return hash_file($file, $dir, $type, $matches[2]);
            }
            return NULL;
        }

        return hash_file($file, $dir, 0, "");

    }, "/.*\.php$/");
}


/**
 * return an array of ('filename', size, crc32(path), crc32(space_trim_content))
 */
function get_wordpress_hashes(string $root_dir) : ?array {

    $version = get_wordpress_version($root_dir);
    if (version_compare($version, "4.1") < 0) { return array("ver" => $version, "int" => "too low", "files" => array()); }

    $r = hash_dir($root_dir);

    return array("ver" => $version, "root" => $root_dir, "int" => text_to_int($version), "files" => $r);//array_splice($r, 0, 1000));
}


/**
 * returns output of $fn if $fn output evaluates to true
 */
function if_it(callable $fn, $item) {
    $r = $fn($item);
    return ($r) ? $r : NULL;
}


function get_server_config_file_list() :array {
    return [
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
    ];
}



function pattern_to_list_3(array $patterns) : array {
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

    if (!file_exists($file_name)) { return array(); }
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

/**
 * @return bool true on success, false on any failure
 */
function update_raw(string $keyfile, string $valuefile) : bool {
    $data = \TF\MaybeStr::of(\TF\bit_http_request("GET", "https://bitfire.co/encode.php", array("v" => 0, "md5"=>md5(CFG::str("encryption_key")))));
    $data->then(\TF\partial('\file_put_contents', $keyfile));
    $data = \TF\MaybeStr::of(\TF\bit_http_request("GET", "https://bitfire.co/encode.php", array("v" => 1, "md5"=>md5(CFG::str("encryption_key")))));
    $data->then(\TF\partial('\file_put_contents', $valuefile));
    return !$data->empty();
}

