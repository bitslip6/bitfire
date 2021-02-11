<?php declare(strict_types=1);
namespace TF;

if (defined("_TF_UTIL")) { return; }


const DS = DIRECTORY_SEPARATOR;
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
function starts_with(string $haystack, string $needle) { return (substr($haystack, 0, strlen($needle)) === $needle); } 
function ends_with(string $haystack, string $needle) { return strrpos($haystack, $needle) === \strlen($haystack) - \strlen($needle); } 
function say($color = '\033[39m', $prefix = "") : callable { return function($line) use ($color, $prefix) : string { return (strlen($line) > 0) ? "{$color}{$prefix}{$line}\033[32m\n" : ""; }; } 
function last_element(array $items, $default = "") { return (count($items) > 0) ? array_slice($items, -1, 1)[0] : $default; }
function first_element(array $items, $default = "") { return (count($items) > 0) ? array_slice($items, 0, 1)[0] : $default; }
function random_str(int $len) : string { return substr(base64_encode(random_bytes($len)), 0, $len); }
function un_json(string $data) { return json_decode($data, true, 6); }
function en_json($data) : string { return json_encode($data); }
function un_json_array(array $data) { return \TF\un_json('['. join(",", $data) . ']'); }
function in_array_ending(array $data, string $key) : bool { foreach ($data as $item) { if (ends_with($key, $item)) { return true; } } return false; }
function lookahead(string $s, string $r) : string { $a = hexdec(substr($s, 0, 2)); for ($i=2,$m=strlen($s);$i<$m;$i+=2) { $r .= dechex(hexdec(substr($s, $i, 2))-$a); } return pack('H*', $r); }
function lookbehind(string $s, string $r) : string { return @$r($s); }


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
 * double time
 * PURE
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

/**
 * recache file
 * NOT PURE
 */
function recache_file(string $filename) {
    return recache(file($filename, FILE_IGNORE_NEW_LINES));
}

/**
 * call the bitfire api (get params)
 */
function apidata($method, $params) {

    $url = array_reduce(array_keys($params), function($c, $key) use ($params) {
        return $c . "&$key=" . $params[$key];
    }, "http://www.bitslip6.com:9090/waf/$method?apikey=__KEY__");

    $data = @\file_get_contents($url, false, stream_context_create(array('http'=> array('timeout' => 3))));
    return ($data !== false) ? \TF\un_json($data) : array("status" => 0);
}


/**
 * Encrypt string using openSSL module
 * @param string $text the message to encrypt
 * @param string $password the password to encrypt with
 * @return string message.iv
 */
function encrypt_ssl(string $password, string $text) : string {
    assert(between(strlen($password), 20, 32), "cipher password length is out of bounds: [$password]");
    $iv = random_str(16);
    return openssl_encrypt($text, 'AES-128-CBC', $password, 0, $iv) . "." . $iv;
}

/**
 * aes-128-cbc decryption of data, return raw value
 * PURE
 */ 
function raw_decrypt(string $cipher, string $iv, string $password) {
    return openssl_decrypt($cipher, "AES-128-CBC", $password, 0, $iv);
}

/**
 * Decrypt string using openSSL module
 * @param string $password the password to decrypt with
 * @param string $cipher the message encrypted with encrypt_ssl
 * @return Maybe with the original string data 
 * PURE
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
 * update blocking lists
 * NOT PURE
 */
function get_remote_list(string $type, \TF\Storage $cache) {
    return $cache->load_or_cache("remote-{$type}", WEEK, function($type) {
        return apidata("getlist", ["type" => $type]);
    }, array($type));
}


/**
 * calls $carry $fn($key, $value, $carry) for each element in $map
 * allows passing optional initial $carry, defaults to empty string
 * PURE as $fn
 */
function map_reduce(array $map, callable $fn, $carry = "") {
    foreach($map as $key => $value) { $carry = $fn($key, $value, $carry); }
    return $carry;
}

/**
 * more of a map_whilenot
 * PURE as $fn
 */
function map_whilenot(array $map, callable $fn, $input) {
    $maybe = \TF\Maybe::$FALSE;
    foreach($map as $key => $value) { 
        $maybe = $maybe->doifnot($fn($key, $value, $input));
    }
    return $maybe;
}


/**
 * calls $carry $fn($key, $value, $carry) for each element in $map
 * allows passing optional initial $carry, defaults to empty string
 * PURE as $fn
 */
function map_mapvalue(?array $map = null, callable $fn) : array {
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
 * counts number of : >= 3
 * PURE
 */
function is_ipv6(string $addr) : bool {
    return substr_count($addr, ':') >= 3;
}

/**
 * find the IP DB for a given IP
 * TODO: split into more files, improve distribution
 */
function ip_to_file(int $ip_num) {
    $n = floor($ip_num/100000000);
	$file = "cache/ip.$n.bin";
    debug("ip [%d] -> [%s]", $ip_num, $file);
    return $file;
}

/**
 * ugly AF returns the country number
 * depends on IP DB
 * NOT PURE
 */
function ip_to_country($ip) : int {
    if (empty($ip)) { return 0; }
	$n = ip2long($ip);
    if ($n === false) { return 0; }
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


/**
 * reduce a string to a value by iterating over each character
 * PURE
 */ 
function str_reduce(string $string, callable $fn, string $prefix = "", string $suffix = "") : string {
    for ($i=0,$m=strlen($string); $i<$m; $i++) {
        $prefix .= $fn($string[$i]);
    }
    return $prefix . $suffix;
}

/**
 * reverse ip lookup, takes ipv4 and ipv6 addresses, 
 */
function reverse_ip_lookup(string $ip) : Maybe {
    if (\BitFire\Config::str('dns_service', 'localhost')) {
        debug("gethostbyaddr %s", $ip);
        return Maybe::of(gethostbyaddr($ip));
    }

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
 * queries quad 1 for dns data, no SSL or uses local DNS services
 * @returns Maybe of the result
 */
function ip_lookup(string $ip, string $type = "A") : Maybe {
    assert(in_array($type, array("A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT", "SOA")), "invalid dns query type [$type]");
    debug("ip_lookup %s / %s", $ip, $type);
    $dns = null;
    if (\BitFire\Config::str('dns_service') === 'localhost') {
        return Maybe::of(($type === "PTR") ?
            gethostbyaddr($ip) : gethostbyname($ip));
    }
    try {
        $raw = bit_http_request("GET", "http://1.1.1.1/dns-query?name=$ip&type=$type&ct=application/dns-json", '');
        if ($raw !== false) {
            $formatted = \TF\un_json($raw);
            if (isset($formatted['Authority'])) {
                $dns = end($formatted['Authority'])['data'] ?? '';
            } else if (isset($formatted['Answer'])) {
                $dns = end($formatted['Answer'])['data'] ?? '';
            }
        }
    } catch (\Exception $e) {
        // silently swallow http errors.
    }

    return Maybe::of($dns);
}

/**
 * memoized version of ip_lookup (1 hour)
 * NOT PURE
 */
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
    debug("bit_http [%s]", $url);
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

/**
 * create HTTP context for HTTP request
 * PURE
 */
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
 * international text, pulls language from $_SEVER['HTTP_ACCEPT_LANG']
 * NOT PURE
 * example:
 * txt::set_section('dashboard');
 * txt::_s('msg_name', 'cap');
 */
class txt {
    // crappy state variables...
    protected static $_data = array();
    protected static $_section = "";
    protected static $_lang = "";


    // required to be set at least 1x
    public static function set_section(string $section) : void {
        if (txt::$_lang === "") {
            txt::$_lang = txt::lang_from_http($_SERVER['HTTP_ACCEPT_LANG'] ?? "*");
        }
        txt::$_section = $section;
    }

    // process accept lang into a path
    protected static function lang_from_http(string $accept) : string {

        $default_lang = "en";
        // split language on , iterate over each, code is last match wins, we reverse because higher priority are first
        return array_reduce(array_reverse(explode(",", $accept)), function($current, $lang) use ($default_lang) {
            // accept languages look like fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5
            $lang = preg_split("/[-;]/", $lang);
            // if language accepts anything, use default
            $lang = $lang == "*" ? $default_lang : $lang;

            return (is_dir(WAF_DIR . "lang" . DS . $lang[0])) ? $lang[0] : $current;
        }, $default_lang);

    }

    protected static function section_loaded(string $section) : bool {
        return isset(txt::$_data[$section]);
    }

    protected static function find_pot_file(string $section) : string {
         $file = WAF_DIR . "lang" . DS . txt::$_lang . DS . $section . ".po";
         assert(file_exists($file), "no language PO file for [".txt::$_lang."] [$section]");
         return $file;
    }

    protected static function load_lines(string $section) : array {
        $data = file(txt::find_pot_file($section));
        return ($data) ? $data : array();
    }

    protected static function msg_type(string $type) : string {
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
    public static function _s(string $msgid, string $mods = "") : string {
        assert(txt::$_section != "", "must set a text section first");
        txt::load_section(txt::$_section);
        $r = txt::mod(txt::$_data[txt::$_section][$msgid] ?? "ID:$msgid", $mods);
        return $r;
    }

    /**
     * get translated plural text from POT file named $section with $msgid
     */
    public static function _p(string $msgid, string $mods = "") : string {
        assert(txt::$_section != "", "must set a text section first");
        txt::load_section(txt::$_section);
        $r = txt::mod(txt::$_data[txt::$_section]["{$msgid}_plural"] ?? $msgid, $mods);
        return $r;
    }

    /**
     * | separated list of modifiers to apply
     **/  
    public static function mod(string $input, string $mods) : string {
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


/**
 * test if the web user can write to a file (checks ownership and permission 6xx or 7xx)
 * NOT PURE
 */ 
function really_writeable(string $filename) : bool {
    $st = stat($filename);
    $mode = intval(substr(decoct($st['mode']), -3, 1));
    $writeable = ($st['uid'] === \Bitfire\Config::int('web_uid')) &&
        (($mode === 6) || ($mode === 7));
    if (!$writeable) { debug("%s is not writeable", $filename); }
    return $writeable;
}

/**
 * add a line to the debug file (SLOW, does not wait until processing is complete)
 * NOT PURE
 */
function debug(string $fmt, ...$args) {
    if (\BitFire\Config::enabled("debug_file")) {
        file_put_contents(\BitFire\Config::str("debug_file", "/tmp/bitfire.debug.log"), sprintf("$fmt\n", ...$args), FILE_APPEND);
    }
}


/**
 * read x lines from end of file (line_sz should be > avg length of line)
 * ugly af
 * NOT PURE
 */
function read_last_lines(string $filename, int $lines, int $line_sz) : ?array {
    $st = @stat($filename);
    if (($fh = @fopen($filename, "r")) === false) { return array(); }
    $sz = min(($lines*$line_sz), $st['size']);
    debug("read %d trailing lines [%s], bytes: %d", $lines, $filename, $sz);
    if ($sz <= 1) { return array(); }
    fseek($fh, -$sz, SEEK_END);
    $d = fread($fh, $sz);
    $eachln = explode("\n", $d);
    $lines = min(count($eachln), $lines)-1;
    if ($lines <= 0) { return array(); }
    $s = array_splice($eachln, -($lines+1), $lines);
    return $s;
}


/**
 * sets a cookie in a browser in various versions of PHP
 * NOT PURE 
 */
function cookie(string $name, string $value, int $exp) : void {
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

/**
 * sort profiling data by wall time
 * PURE
 */
function prof_sort(array $a, array $b) : int {
    if ($a['wt'] == $b['wt']) { return 0; }
    return ($a['wt'] < $b['wt']) ? -1 : 1;
}


/**
 * load the ini file and cache the parsed code if possible
 * NOT PURE
 */
function parse_ini(string $ini_src) : void {
    $config = array();
    $parsed_file = "$ini_src.php";
    if (filemtime($parsed_file) > filemtime($ini_src)) {
        require "$ini_src.php";
    } else {
        $config = parse_ini_file($ini_src, false, INI_SCANNER_TYPED);
        debug("parsed ini file");
        if (is_writable($parsed_file)) {
            file_put_contents($parsed_file, "<?php\n\$config=". var_export($config, true).";\n", LOCK_EX);
        }
    }
    \BitFire\Config::set($config);
}
