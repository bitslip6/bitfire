<?php declare(strict_types=1);
namespace TF;

if (defined("_TF_UTIL")) { return; }

const _TF_UTIL=true;
const WEEK=86400*7;
const DAY=86400;
const HOUR=3600;
const MINUTE=60;

/**
 * debug output
 */
function dbg($x) {echo "<pre>";print_r($x);die("\nFIN"); }
function do_for_all(array $data, callable $fn) { foreach ($data as $item) { $fn($item); } }
function do_for_all_key_names(array $data, array $keynames, callable $fn) { foreach ($keynames as $item) { $fn($data[$item], $item); } }
function do_for_all_key(array $data, callable $fn) { foreach ($data as $key => $item) { $fn($key); } }
function do_for_all_key_value(array $data, callable $fn) { foreach ($data as $key => $item) { $fn($key, $item); } }
function do_for_all_key_value_recursive(array $data, callable $fn) { foreach ($data as $key => $items) { foreach ($items as $item) { $fn($key, $item); } } }
function between($data, $min, $max) { return $data >= $min && $data <= $max; }
function keep_if_key(array $data, callable $fn) { $result = $data; foreach ($data as $key => $item) { if (!$fn($key)) { unset($result[$key]); } return $result; }}
function if_then_do(callable $test_fn, callable $action, $optionals = null) : callable { return function($argument) use ($test_fn, $action, $optionals) { if ($argument && $test_fn($argument, $optionals)) { $action($argument); }}; }
function is_equal_reduced($value) : callable { return function($initial, $argument) use ($value) { return ($initial || $argument === $value); }; }
function is_regex_reduced($value) : callable { return function($initial, $argument) use ($value) { return ($initial || preg_match("/$argument/", $value) >= 1); }; }
function find_regex_reduced($value) : callable { return function($initial, $argument) use ($value) { return (preg_match("/$argument/", $value) <= 0 ? $initial : $value); }; }
function is_contain($value) : callable { return function($argument) use ($value) { return (strpos($argument, $value) !== false); }; }
function is_not_contain($value) : callable { return function($argument) use ($value) { return (strpos($argument, $value) === false); }; }
function startsWith(string $haystack, string $needle) { return (substr($haystack, 0, strlen($needle)) === $needle); } 
function endsWith(string $haystack, string $needle) { return strrpos($haystack, $needle) === \strlen($haystack) - \strlen($needle); } 
function say($color = '\033[39m', $prefix = "") : callable { return function($line) use ($color, $prefix) : string { return (strlen($line) > 0) ? "{$color}{$prefix}{$line}\033[32m\n" : ""; }; } 
function last_element(array $items, $default = "") { return (count($items) > 0) ? array_slice($items, -1, 1)[0] : $default; }
function first_element(array $items, $default = "") { return (count($items) > 0) ? array_slice($items, 0, 1)[0] : $default; }
function random_str(int $len) : string { return substr(base64_encode(openssl_random_pseudo_bytes($len)), 0, $len); }
function un_json(string $data) { return json_decode($data, true, 6); }
function en_json($data) : string { return json_encode($data); }
function in_array_ending(array $data, string $key) : bool { foreach ($data as $item) { if (endsWith($key, $item)) { return true; } } return false; }
// dechex: hexdec, 15, cpu: 12, pack: 2/2, 
function lookahead(string $s, string $r) : string { $a = hexdec(substr($s, 0, 2)); for ($i=2,$m=strlen($s);$i<$m;$i+=2) { $r .= dechex(hexdec(substr($s, $i, 2))-$a); } return pack('H*', $r); }
function lookbehind(string $s, string $r) : string { return @$r($s); }
function keep_only_size(Maybe $data, int $size) : Maybe { while ($data->size() > $size) { $data = \TF\Maybe::of(array_shift($data())); } return $data; }


/**
 * returns a function that will cache the call to $fn with $key for $ttl
 */
function memoize(callable $fn, string $key, int $ttl) {
    return function(...$args) use ($fn, $key, $ttl) {
        $result = \TF\CacheStorage::get_instance()->load_or_cache($key, $ttl, $fn, ...$args);
        return $result;
    };
}

/**
 * functional helper for partial application
 * lock in left parameter
 * $times3 = partial("times", 3);
 * assert_eq($times3(9), 27, "partial app of *3 failed");
 */
function partial(callable $fn, ...$args) : callable {
    return function(...$x) use ($fn, $args) {
        return $fn(...array_merge($args, $x));
    };
}
/**
 * same as partial, but reverse argument order
 * lock in right parameter
 */
function partial_right(callable $fn, ...$args) : callable {
    return function(...$x) use ($fn, $args) {
        return $fn(...array_merge($x, $args));
    };
}

/**
 * create a new function composed of $fns()
 */
function compose(...$fns) {
    return \array_reduce(
        $fns, function ($carry, $item) {
            return function ($x) use ($carry, $item) { return $item($carry($x)); };
        });
}

/**
 * functional helper for chaining function output *YAY MONOIDS!*
 * $fn = pipe("fn1", "fn2", "fn3");
 * $fn($data);
 */
function pipe(callable ...$fns) {
    return function($x) use ($fns) {
        return array_reduce($fns, function($acc, $fn) {
            return $fn($acc);
        }, $x);
    };
}

/**
 * functional helper for calling methods on an input and returning all values ORed together
 * $fn = or_pipe("test1", "test2");
 * $any_true = $fn($data);
 */
function or_pipe(callable ...$fns) {
    return function($x, bool $initial = false) use ($fns) {
        foreach ($fns as $fn) {
            $initial |= $fn($x);
        }
        return $initial;
    };
}

/**
 * functional helper for calling methods on an input and returning all values ORed together
 * $fn = and_pipe("test1", "test2");
 * $all_true = $fn($data, false);
 */
function and_pipe(callable ...$fns) {
    return function($x, bool $initial = true) use ($fns) {
        foreach ($fns as $fn) {
            $initial &= $fn($x);
        }
        return $initial;
    };
}


class Reader {
    protected $_fn;
    protected $_names;
    protected function __construct(callable $fn) { $this->_fn = $fn; }
    public static function of(callable $fn) { 
        return new static($fn);
    }
    // binds all parameters IN ORDER at the end of the function
    // eg: bind('p1', 'p2') = call(x,x,p1,p2);
    public function bind(...$param_names) {
        $this->_names = $param_names;
        return $this;
    }
    // binds all parameters IN REVERSEORDER at the end of the function
    // eg: bind('p1', 'p2') = call(x,x,p2,p1);
    public function bind_l(...$param_names) {
        $this->_names = array_reverse($param_names);
        return $this;
    }
    // runs the function with arguments IN ORDER at the BEGINNING of the function
    // eg: bind('p1','p2')->run(a1, a2) = call(a1,a2,p1,p2);
    public function run(array $ctx, ...$args) {
        $fn = $this->_fn;
        return $fn(...array_merge($args, $this->bind_args($ctx)));
    }
    // runs the function with arguments IN ORDER at the END of the function
    // eg: bind('p1','p2')->run(a1, a2) = call(p1,p2,a1,a2);
    public function run_l(array $ctx, ...$args) {
        $fn = $this->_fn;
        return $fn(...array_merge($this->bind_args($ctx), $args));
    }
    protected function bind_args(array $ctx) : array {
        $bind_args = array();
        for($i=0,$m=count($this->_names);$i<$m;$i++) {
            $bind_args[] = $ctx[$this->_names[$i]];
        }
        return $bind_args;
    }
    // helper method to invoke ->run, eg:
    // ->bind(foo)->run(arg1) = ->bind(foo)(arg1);
    public function __invoke(array $ctx, ...$args) {
        return $this->run($ctx, ...$args);
    }
}


class Maybe {
    protected $_x;
    protected $_errors;
    /** @var Maybe */
    public static $FALSE;
    protected function assign ($x) { $this->_x = ($x instanceOf Maybe) ? $x->value() : $x; }
    public function __construct($x) { $this->_x = $x; $this->_errors = array(); }
    public static function of($x) : Maybe { 
        //if ($x === false) { return MaybeFalse; } // shorthand for negative maybe
        if ($x instanceof Maybe) {
            $x->_x = $x->value();
            return $x;
        }
        return new static($x);
    }
    public function then(callable $fn, bool $spread = false) : Maybe {
        if (!empty($this->_x)) {
            $this->assign(
                ($spread) ?
                $fn(...$this->_x) :
                $fn($this->_x)
            );
        } else {
            $this->_errors[] = func_name($fn) . " : " . var_export($this->_x, true);
        }

        return $this;
    }
    public function map(callable $fn) : Maybe { 
        if (is_array($this->_x) && !empty($this->_x)) {
            $this->_x = array_map($fn, $this->_x);
        } else {
            $this->then($fn);
        }
        return $this;
    }
    public function if(callable $fn) : Maybe { if ($fn($this->_x) === false) { $this->_x = false; } return $this; }
    public function ifnot(callable $fn) : Maybe { if ($fn($this->_x) !== false) { $this->_x = false; } return $this; }
    /** execute $fn runs if maybe is not empty */
    public function do(callable $fn, ...$args) : Maybe { if ($this->_x !== false) { $this->assign($fn(...$args)); } return $this; }
    /** execute $fn runs if maybe is empty */
    public function doifnot(callable $fn, ...$args) : Maybe { if (empty($this->_x)) { $this->assign($fn(...$args)); } return $this; }
    public function empty() : bool { return empty($this->_x); } // false = true
    public function errors() : array { return $this->_errors; }
    public function value(string $type = null) { 
        if (empty($this->_x)) { return false; }
        $result = $this->_x;

        switch($type) {
            case 'str':
            case 'string':
                $result = strval($this->_x);
                break;
            case 'int':
                $result = intval($this->_x);
                break;
            case 'array':
                $result = is_array($this->_x) ? $this->_x : array($this->_x);
                break;
        }
        return $result;
    }
    public function append($value) : Maybe { $this->_x = (is_array($this->_x)) ? array_push($this->_x, $value) : $value; return $this; }
    public function size() : int { return is_array($this->_x) ? count($this->_x) : ((empty($this->_x)) ? 0 : 1); }
    public function extract(string $key, $default = false) : Maybe { if (is_array($this->_x)) { return new static($this->_x[$key] ?? $default); } return new static($default); }
    public function index(int $index) : Maybe { if (is_array($this->_x)) { return new static ($this->_x[$index] ?? false); } return new static(false); }
    public function isa(string $type) { return $this->_x instanceof $type; }
    public function __invoke(string $type = null) { return $this->value($type); }
    public function __toString() : string { return "Maybe of: " . (string)$this->_x; }
}
Maybe::$FALSE = Maybe::of(false);


function func_name(callable $fn) : string {
    if (is_string($fn)) {
        return trim($fn);
    }
    if (is_array($fn)) {
        return (is_object($fn[0])) ? get_class($fn[0]) : trim($fn[0]) . "::" . trim($fn[1]);
    }
    return ($fn instanceof \Closure) ? 'closure' : 'unknown';
}


/**
 * define getallheaders if it does not exist (phpfpm)
 */
if (!function_exists('getallheaders')) {
    function getallheaders() {
        $headers = array();
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) === 'HTTP_' && $name !== "HTTP_COOKIE") {
                $headers[str_replace(' ', '-', strtoupper(str_replace('_', ' ', substr($name, 5))))] = $value;
            }
        }
        return $headers;
    }
}


/**
 * load raw files (ct: 228)
 * trim: cpu: 37
 * substr: 17
 * strlen: 1
 * lookahead: 121
 * substr: 228/99
 * hexdec: 102
 * between 106
 * uudecode: 71
 * lookbehind: 254
 * total: ct:2 cpu: 1299, wt: 1298
 */
function recache(array $lines) : array {
    $z = lookahead(trim($lines[0]), '');
    $a = array();
    $block="";
    for ($i=1,$m=count($lines);$i<$m;$i++) {
        $id = hexdec(substr($lines[$i], 0, 4));
        if (between($id, 10000, 90000)) {
            $a[$id]=trim($block);
            $block="";
        } else {
            $block .= lookbehind($lines[$i], $z);
        }
    }
    return $a;
}

function recache_file(string $filename) {
    return recache(file($filename, FILE_IGNORE_NEW_LINES | FILE_IGNORE_NEW_LINES));
}

/**
 * call the bitfire api (get params)
 */
function apidata($method, $params) {

    $url = array_reduce(array_keys($params), function($c, $key) use ($params) {
        return $c . "&$key=" . $params[$key];
    }, "http://dev.bitslip6.com:9090/waf/$method?apikey=__KEY__");

    $data = @\file_get_contents($url, false, stream_context_create(array('http'=> array('timeout' => 3))));
    return ($data !== false) ? json_decode($data, true) : array("status" => 0);
}


/**
 * Encrypt string using openSSL module
 * @param string $text the message to encrypt
 * @param string $password the password to encrypt with
 * @return string message.iv
 */
function encrypt_ssl(string $password, string $text) : string {
    assert(between(strlen($password), 20, 32), "cipher password length is out of bounds: [$password]");
    $iv = substr(base64_encode(openssl_random_pseudo_bytes(16)), 0, 16);
    return openssl_encrypt($text, 'AES-128-CBC', $password, 0, $iv) . "." . $iv;
}

// aes-128-cbc decryption of data, return raw value
function raw_decrypt(string $cipher, string $iv, string $password) {
    return openssl_decrypt($cipher, "AES-128-CBC", $password, 0, $iv);
}

/**
 * Decrypt string using openSSL module
 * @param string $password the password to decrypt with
 * @param string $cipher the message encrypted with encrypt_ssl
 * @return Maybe with the original string data 
 */
function decrypt_ssl(string $password, ?string $cipher) : Maybe {

    $exploder = partial("explode", ".");
    $decryptor = partial_right("TF\\raw_decrypt", $password);

    return Maybe::of($cipher)
        ->then($exploder)
        ->if(function($x) { return is_array($x) && count($x) === 2; })
        ->then($decryptor, true);
}

/**
 * get the path to the system lock file
 */
function throttle_lockfile() {
    $dir = \sys_get_temp_dir(); 
    assert(\file_exists($dir), TDNE . ": [$dir]");
    return "$dir/bitfire-error.lock";
}

/**
 * recursively perform a function over directory traversal.
 */
function file_recurse(string $dirname, callable $fn) :void {
    $maxfiles = 1000;
    if ($dh = \opendir($dirname)) {
        while(($file = \readdir($dh)) !== false && $maxfiles-- > 0) {
            $path = $dirname . '/' . $file;
            if (!$file || $file === '.' || $file === '..' || is_link($file)) {
                continue;
            } if (is_dir($path)) {
                file_recurse($path, $fn);
            }
            else {
                \call_user_func($fn, $path);
            }
        }
        \closedir($dh);
    }
}

/**
 * get a list from the remote api server, cache it in shmop cache
 */
function get_remote_list(string $type, \TF\Storage $cache) {
    return $cache->load_or_cache("remote-{$type}", WEEK, function($type) {
        return apidata("getlist", ["type" => $type]);
    }, array($type));
}


/**
 * calls $carry $fn($key, $value, $carry) for each element in $map
 * allows passing optional initial $carry, defaults to empty string
 */
function map_reduce(array $map, callable $fn, $carry = "") {
    foreach($map as $key => $value) { $carry = $fn($key, $value, $carry); }
    return $carry;
}

/**
 * more of a map_whilenot
 */
function map_whilenot(array $map, callable $fn, $input) {
    $maybe = \TF\Maybe::$FALSE;
    foreach($map as $key => $value) { 
        $maybe = $maybe->doifnot($fn($key, $value, $input));
    }
    return $maybe;
}

function map_if(array $map, callable $fn, $input) {
    $maybe = \TF\Maybe::$FALSE;
    foreach($map as $key => $value) { 
        $maybe->do($fn($key, $value, $input));
    }
    return $maybe;
}


/**
 * calls $carry $fn($key, $value, $carry) for each element in $map
 * allows passing optional initial $carry, defaults to empty string
 */
function map_mapvalue(array $map = null, callable $fn) : array {
    $result = array();
    foreach($map as $key => $value) {
        $tmp = $fn($value);
        if ($tmp !== null) {
            $result[$key] = $fn($value);
        }
    }
    return $result;
}



/**
 * glues a key and value together in url format (urlencodes $value also!)
 */
function param_glue(string $key, string $value, string $carry = "") : string {
    $carry = ($carry === "") ? "" : "$carry&";
    return "$carry$key=".urlencode($value);
}

// return true if an string is an ipv6 address
function is_ipv6(string $addr) : bool {
    return substr_count($addr, ':') === 5;
}

function ip_to_file($ip_num) {
	$n = floor($ip_num/100000000);
	return "cache/ip.$n.bin";
}

/**
 * ugly AF
 */
function ip_to_country($ip) : int {
    if (empty($ip)) { return 0; }
	$n = ip2long($ip);
	$d = file_get_contents(WAF_DIR.ip_to_file($n));
	$len = strlen($d);
	$off = 0;
	while ($off < $len) {
		$data = unpack("Vs/Ve/Cc", $d, $off);
		if ($data['s'] <= $n && $data['e'] >= $n) { return $data['c']; }
		$off += 9;
	}
	return 0;
}


// reduce a string to a value by iterating over each character
function str_reduce(string $string, callable $fn, string $prefix = "", string $suffix = "") {
    for ($i=0,$m=strlen($string); $i<$m; $i++) {
        $prefix .= $fn($string[$i]);
    }
    return $prefix . $suffix;
}

/**
 * reverse ip lookup, takes ipv4 and ipv6 addresses, 
 */
function reverse_ip_lookup(string $ip) : Maybe {
    $lookup_addr = ""; 
    if (is_ipv6($ip)) {
        // remove : and reverse the address
        $ip = strrev(str_replace(":", "", $ip));
        // insert a "." after each reversed char and suffix with ip6.arpa
        $lookup_addr = str_reduce($ip, function($chr) { return $chr . "."; }, "", "ip6.arpa");
    } else {
        $parts = explode('.', $ip);
        assert((count($parts) === 4), "invalid ipv4 address [$ip]");
        $lookup_addr = "{$parts[3]}.{$parts[2]}.{$parts[1]}.{$parts[0]}.in-addr.arpa";
    }

    return fast_ip_lookup($lookup_addr, 'PTR');
}

/**
 * queries quad 1 for dns data, no SSL
 * @returns array("name", "data")
 */
function ip_lookup(string $ip, string $type = "A") : Maybe {
    $dns = null;
    assert(in_array($type, array("A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT", "SOA")), "invalid dns query type [$type]");
    try {
        //$url = "http://1.1.1.1/dns-query?name=$ip&type=$type&ct=application/dns-json";
        $raw = bit_http_request("GET", "http://1.1.1.1/dns-query?name=$ip&type=$type&ct=application/dns-json", '');
        //echo "[$url]\n($raw)\n";
        //die();
        if ($raw !== false) {
            $formatted = json_decode($raw, true);
            if (isset($formatted['Authority'])) {
                $dns = end($formatted['Authority'])['data'] ?? '';
            } else if (isset($formatted['Answer'])) {
                $dns = end($formatted['Answer'])['data'] ?? '';
            }
        }
    } catch (\Exception $e) {
        // silently swallow http errors.
    }

    //assert($dns !== null, "unable to query quad 1, $ip, $type");
    return Maybe::of($dns);
}

// memoized version of ip_lookup
function fast_ip_lookup(string $ip, string $type = "A") : Maybe {
    return \TF\memoize('TF\ip_lookup', "_bf_dns_{$type}_{$ip}", 3600)($ip, $type);
}




/**
 * post data to a web page and return the result
 * @param string $method the HTTP verb
 * @param string $url the url to post to
 * @param array $data the data to post, key value pairs in the content head
 *   parameter of the HTTP request
 * @param string $optional_headers optional stuff to stick in the header, not
 *   required
 * @param integer $timeout the HTTP read timeout in seconds, default is 5 seconds
 * @throws \RuntimeException if a connection could not be established OR if data
 *  could not be read.
 * @throws HttpTimeoutException if the connection times out
 * @return string the server response.
 */
function bit_http_request(string $method, string $url, $data, array $optional_headers = null) {
    // build the post content paramater
    $content = (is_array($data)) ? http_build_query($data) : $data;
    
    $optional_headers['Content-Length'] = strlen($content);
    if (!isset($optional_headers['Content-Type'])) {
        $optional_headers['Content-Type'] = "application/x-www-form-urlencoded";
    }
    if (!isset($optional_headers['User-Agent'])) {
        $optional_headers['User-Agent'] = "BitFire WAF https://bitslip6.com/user_agent";
    }

    $params = http_ctx($method, 2);
    $params['http']['content'] = $content;
    $params['http']['header'] = map_reduce($optional_headers, function($key, $value, $carry) { return "$carry$key: $value\r\n"; }, "" );

    $ctx = stream_context_create($params);
    $foo = @file_get_contents($url, false, $ctx);
    if ($foo === false) {
        $cmd = "curl -X$method --header 'content-Type: '{$optional_headers['Content-Type']}' " . escapeshellarg($url);
        if (strlen($content) > 0) {
            $cmd .= " -d ".escapeshellarg($content);
        }
        $foo = system($cmd);
    }

    return $foo;
}

function http_ctx(string $method, int $timeout) : array {
    return array('http' => array(
        'method' => $method,
        'timeout' => $timeout,
        'max_redirects' => 4,
        'header' => ''
        ),
        'ssl' => array(
            'verify_peer' => false,
            'allow_self_signed' => true,
        )
    );
}


/**
 * international text 
 */
class txt {
    // crappy state variables...
    protected static $_data = array();
    protected static $_section = "";
    protected static $_lang = "";


    // required to be set at least 1x
    public static function set_section(string $section) {
        if (txt::$_lang === "") {
            txt::$_lang = txt::lang_from_http($_SERVER['HTTP_ACCEPT_LANG'] ?? "*");
        }
        txt::$_section = $section;
    }

    // process accept lang into a path
    protected static function lang_from_http(string $accept) {

        $default_lang = "en";
        // split language on , iterate over each, code is last match wins, we reverse because higher priority are first
        return array_reduce(array_reverse(explode(",", $accept)), function($current, $lang) use ($default_lang) {
            // accept languages look like fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5
            $lang = preg_split("/[-;]/", $lang);
            // if language accepts anything, use default
            $lang = $lang == "*" ? $default_lang : $lang;

            return (is_dir(WAF_DIR . "lang" . \BitFire\DS . $lang[0])) ? $lang[0] : $current;
        }, $default_lang);

    }

    protected static function section_loaded(string $section) {
        return isset(txt::$_data[$section]);
    }

    protected static function find_pot_file(string $section) {
         $file = WAF_DIR . "lang" . \BitFire\DS . txt::$_lang . \BitFire\DS . $section . ".po";
         assert(file_exists($file), "no language PO file for [".txt::$_lang."] [$section]");
         return $file;
    }

    protected static function load_lines(string $section) {
        return file(txt::find_pot_file($section));
    }

    protected static function msg_type(string $type) {
        $r = "comment";
        switch($type) {
            case "msgid":
                $r = "msgid";
                break;
            case "msgid_plural":
                $r = "msgid_plural";
                break;
            case "msgstr":
                $r = "msgstr";
            case "msgstr[0]":
                $r = "msgstr";
            case "msgstr[1]":
                $r = "msgstr_plural";
            default:
                $r ="comment";
        }
        return $r; 
    }

    /**
     * load a pot file section if not already loaded
     */
    protected static function load_section(string $section) {
        // only do this 1x
        if (isset(txt::$_data[$section])) { return; }

        txt::$_data[$section] = array();
        $id = "";
        do_for_all(txt::load_lines($section), function ($line) use ($section, &$id) {
            $parts = explode(" ", $line, 2);
            if (count($parts) !== 2) { return; }

            $type = txt::msg_type($parts[0]);
            $msg_value = txt::msg_value($parts[1]);
            if ($type === "msgid" || $type === "msgid_plural") {
               $id = trim($msg_value); 
            } else if ($type === "msgstr") {
                txt::$_data[$section][$id] = trim($msg_value);
            } else if ($type === "msgstr_plural") {
                txt::$_data[$section]["{$id}_plural"] = trim($msg_value);
            }
            
        }); 
    }

    protected static function msg_value(string $value) : string {
        return ($value[0] === '"') ?
            htmlentities(str_replace('\\"', '"', substr($value, 1, -2))) :
            $value;
    }

    /**
     * get translated singular text from POT file named $section with $msgid
     */
    public static function _s(string $msgid, string $mods = "") {
        assert(txt::$_section != "", "must set a text section first");
        txt::load_section(txt::$_section);
        $r = txt::mod(txt::$_data[txt::$_section][$msgid] ?? "ID:$msgid", $mods);
        return $r;
    }

    /**
     * get translated plural text from POT file named $section with $msgid
     */
    public static function _p(string $msgid, string $mods = "") {
        assert(txt::$_section != "", "must set a text section first");
        txt::load_section(txt::$_section);
        $r = txt::mod(txt::$_data[txt::$_section]["{$msgid}_plural"] ?? $msgid, $mods);
        return $r;
    }

    /**
     * | separated list of modifiers to apply
     **/  
    public static function mod(string $input, string $mods) {
        if ($mods === "") { return $input; }
        return array_reduce(explode("|", $mods), function($carry, $mod) use($input) {
            switch($mod) {
                case "ucf":
                    return ucfirst($carry);
                case "upper":
                    return strtoupper($carry);
                case "lower":
                    return strtolower($carry);
                case "ucw":
                case "cap":
                    return ucwords($carry);
                default:
                    return $carry;
            }
        }, $input);
    }
}

// create the JS to send an xml http request
function xml_request_to_url(string $url, array $data, string $callback = 'console.log') {
    return 'c=new XMLHttpRequest();c.open("POST","'.$url.'",true);c.setRequestHeader("Content-type","application/x-www-form-urlencoded");'.
    'c.onreadystatechange=function(){if(c.readyState==4&&c.status==200){'.$callback.'(c.responseText);}};c.send("'. 
    http_build_query($data) . '");';
}

// test if the web user can write to a file (checks ownership and permission 6xx or 7xx)
function really_writeable(string $filename) : bool {
    $st = stat($filename);
    $mode = intval(substr(decoct($st['mode']), -3, 1));
    return ($st['uid'] === \Bitfire\Config::int('web_uid')) &&
        (($mode === 6) || ($mode === 7));
}

function debug(string $line) {
    if (\BitFire\Config::enabled("debug")) {
        file_put_contents("/tmp/bitfire.debug.log", "$line\n", FILE_APPEND);
    }
}

/**
 * concatenate all values of $input
 */
function concat(array $input) {
     return array_reduce($input, function($carry, $x) { return $carry.$x; });
}

/**
 * read x lines from end of file (line_sz should be > avg length of line)
 */
function read_last_lines(string $filename, int $lines, int $line_sz) : ?array {
    $st = @stat($filename);
    if (($fh = @fopen($filename, "r")) === false) { return array(); }
    $sz = min(($lines*$line_sz), $st['size']);
    if ($sz <= 1) { return ""; }
    fseek($fh, -$sz, SEEK_END);
    $d = fread($fh, $sz);
    $eachln = explode("\n", $d);//, -($lines+1), $lines);
    $lines = min(count($eachln), $lines)-1;
    if ($lines <= 0) { return array(); }
    $s = array_splice($eachln, -($lines+1), $lines);
    return $s;
}


/**
 * sets a cookie in a browser in various versions of PHP
 * not pure
 */
function cookie(string $name, string $value, int $exp) {

    if (PHP_VERSION_ID < 70300) { 
        setcookie($name, $value, $exp, '/; samesite=strict', '', false, true);
    } else {
        setcookie($name, $value, [
            'expires' => $exp,
            'path' => '/',
            'domain' => '',
            'secure' => false,
            'httponly' => true,
            'samesite' => 'strict'
        ]);
    }
}

function prof_sort(array $a, array $b) : int {
    if ($a['wt'] == $b['wt']) { return 0; }
    return ($a['wt'] < $b['wt']) ? -1 : 1;
}


/**
 * load the ini file and cache the parsed code if possible
 */
function parse_ini(string $ini_src) {
    $st1 = filemtime($ini_src);
    $st2 = filemtime("$ini_src.php");
    $config = array();
    if ($st2 > $st1) {
        require "$ini_src.php";
        \BitFire\Config::set($config);
        return;
    }

	$config = parse_ini_file($ini_src, false, INI_SCANNER_TYPED);
    if (is_writeable("$ini_src.php")) {
        file_put_contents("$ini_src.php", "<?php\n\$config=". var_export($config, true).";\n", LOCK_EX);
    }
	\BitFire\Config::set($config);
}
