<?php
/**
 * TODO: remove bitfire specific code, refactor into bitfire utils 
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * all functions are called via api_call() from bitfire.php and all authentication 
 * is done there before calling any of these methods.
 */

namespace ThreadFin;

use const BitFire\BITFIRE_VER;
use const BitFire\CONFIG_CACHE_TYPE;
use const BitFire\CONFIG_COOKIES;
use const BitFire\CONFIG_ENCRYPT_KEY;
use const BitFire\CONFIG_USER_TRACK_COOKIE;
use const BitFire\FILE_R;
use const BitFire\FILE_RW;
use const BitFire\FILE_W;
use const BitFire\STATUS_OK;
use const BitFire\WAF_ROOT;
use const BitFire\WAF_SRC;

use \BitFire\Config as CFG;
use \BitFire\Block as Block;
use RuntimeException;

use function BitFire\on_err;
use function BitFireSvr\update_ini_value;
use function \ThreadFin\partial as BINDL;
use function \ThreadFin\partial_right as BINDR;

if (defined("BitFire\_TF_UTIL")) { return; }
define("BitFire\_TF_UTIL", 1);


const DS = DIRECTORY_SEPARATOR;
const WEEK=86400*7;
const DAY=86400;
const HOUR=3600;
const MINUTE=60;

const ENCODE_RAW=1;
const ENCODE_SPECIAL=2;
const ENCODE_HTML=3;
const ENCODE_BASE64=4;

require_once WAF_SRC . "const.php";

/**
 * Complete filesystem abstraction
 * @package ThreadFin
 */
class FileData {
    /** @var string $filename - full path to file on disk */
    public $filename;
    /** @var int $num_lines - number of lines of content */
    public $num_lines;
    /** @var array $lines - file content array of lines */
    public $lines = array();
    public $debug = false;
    public $size = 0;
    public $content = "";
    /** @var bool $exists - true if file or mocked content exists */
    public $exists = false;
    /** @var bool $readable - true if file is readable */
    public $readable = false;
    /** @var bool $readable - true if file is writeable */
    public $writeable = false;

    protected static $fs_data = array();
    protected $errors = array();

    /**
     * mask file system with mocked $content at $filename
     * @param string $filename 
     * @param string $content 
     */
    public static function mask_file(string $filename, string $content) {
        FileData::$fs_data[$filename] = $content;
    }

    /**
     * @return array of any errors that may have occurred
     */
    public function get_errors() : array { return $this->errors; }

    /**
     * @param bool $enable enable or disable debug mode
     * @return FileData 
     */
    public function debug_enable(bool $enable) : FileData { $this->debug = $enable; return $this; }

    /**
     * preferred method of creating a FileData object
     */
    public static function new(string $filename) : FileData {
        return new FileData($filename);
    }

    public function __construct(string $filename) {
        $this->filename = $filename;
        if (isset(FileData::$fs_data[$filename])) {
            $this->exists = $this->writeable = $this->readable = true;
            $this->size = strlen(FileData::$fs_data[$filename]);
        } else {
            $this->exists = file_exists($filename);
            $this->writeable = is_writable($filename);
            $this->readable = is_readable($filename);
            if ($this->exists) {
                $this->size = filesize($filename);
            }
        }
    }

    /**
     * This could be improved by marking content clean/dirty and joining only dirty content
     * @return string the raw file contents
     */
    public function raw() : string {
        if (empty($this->lines)) {
            if (isset(FileData::$fs_data[$this->filename])) {
                return FileData::$fs_data[$this->filename];
            } else {
                return file_exists($this->filename) ? file_get_contents($this->filename) : "";
            }
        }
        return join("", $this->lines);
    }


    /**
     * read the data from disk and store in lines
     * @return FileData 
     */
    public function read($with_newline = true) : FileData {
        // mock data, and raw reads
        if (isset(FileData::$fs_data[$this->filename])) {
            $this->lines = explode("\n", FileData::$fs_data[$this->filename]);
            $this->num_lines = count($this->lines);
        }
        else {
            $disabled = false;
            if ($this->exists) {
                $size = filesize($this->filename);
                if ($size > 1024*1024*10) {
                    $this->errors[] = "File too large to read: $this->filename";
                    return $this;
                }

                $s = @stat($this->filename);
                $ctr = 0;
                // split raw reads by line, and read in files line by line if no content
                $mode = ($with_newline) ? 0 : FILE_IGNORE_NEW_LINES;
                $done = false;

                while (!is_readable($this->filename) && $ctr++ < 10) {
                    usleep(2000);
                    $disabled = $s['mode']??FILE_W;
                    @chmod($this->filename, FILE_RW);
                }

                $ctr = 0;
                while (!$done && $ctr++ < 10) {
                    $this->lines = @file($this->filename, $mode);
                    if ($this->lines === false) {
                        usleep(2000);
                        @chmod($this->filename, FILE_RW);
                    } else { $done = true; }
                }

                // count lines and handle any error cases...
                if ($this->lines === false) {
                    debug("unable to read %s", $this->filename);
                    $this->lines = [];
                    $this->num_lines = 0;
                } else {
                    $this->num_lines = count($this->lines);
                }
                //debug(basename($this->filename) . " read num lines: " . $this->num_lines);

                if ($this->debug) {
                    debug("FS(r) [%s] (%d)lines", $this->filename, $this->num_lines);
                }

                // make sure lines is a valid value
                if ($size > 0 && $this->num_lines < 1) { debug("empty file %s", $this->filename); $this->lines = array(); }
                if ($disabled !== false) {
                    if (!chmod($this->filename, $disabled)) {
                        debug("unable to set permission on %s to [%d]", $this->filename, $disabled);
                    }
                }
            } else {
                debug("file does not exist: %s", $this->filename);
                $this->errors[] = "unable to read, file does not exist";
            }
        }
        return $this;
    }

    /**
     * MUTATE $lines
     * @param callable $fn apply function to every line in file.
     * @return FileData 
     */
    public function apply_ln(callable $fn) : FileData {
        if ($this->num_lines > 0) {
            $this->lines = $fn($this->lines);
            $this->num_lines = count($this->lines);
        } else {
            $this->errors[] = "unable to apply fn[".func_name($fn)."] has no lines";
        }
        return $this;
    }

    /**
     * return the number of bytes in all lines (excluding newlines...)
     * @return int 
     */
    public function count_bytes() : int {
        $bytes = 0;
        foreach ($this->lines as $line) { $bytes += strlen($line); }
        return $bytes;
    }

    /**
     * MUTATE $lines
     * @return FileData with lines joined and json decoded
     */
    public function un_json() : FileData {
        // UGLY, refactor this
        if (count($this->lines) > 0) {
            $data = join("\n", $this->lines);
            $result = false;
            if (!empty($data) && is_string($data)) {
                $result = un_json($data);
            }
            if (is_array($result)) {
                $this->lines = $result;
                $this->num_lines = count($this->lines);
            }
            else {
                $this->lines = array();
                $this->errors[] = "json decode failed";
            }
        }
        return $this;
    }
    /**
     * MUTATE $lines
     * @param callable $fn apply function to $this, must return a FileData objected
     * @return FileData FileData mutated FileData with data from returned $fn($this)
     */
    public function apply(callable $fn) : FileData {
        if ($this->num_lines > 0) {
            $tmp = $fn($this);
            $this->lines = $tmp->lines;
            $this->num_lines = count($tmp->lines);
            $this->filename = $tmp->filename;
            $this->exists = $tmp->exists;
        }
        return $this;
    }
    /**
     * @param callable $fn array_filter on $this->lines with $fn
     * @return FileData 
     */
    public function filter(callable $fn) : FileData {
        $this->lines = array_filter($this->lines, $fn);
        $this->num_lines = count($this->lines);
        //if (!empty($this->content)) { $this->content = join("\n", $this->lines); }
        return $this;
    }

    /**
     * @param string $text test to append to FileData
     * @return FileData 
     */
    public function append(string $text) : FileData {
        $lines = explode("\n", $text);
        if (!in_array($lines[0], $this->lines)) {
            $this->lines = array_merge($this->lines, $lines);
        }
        return $this;
    }

    /**
     * MUTATES $lines
     * @param callable $fn array_map on $this->lines with $fn
     * @return FileData 
     */
    public function map(callable $fn) : FileData {
        if ($this->num_lines > 0) {
            $this->lines = array_map($fn, $this->lines);
            $this->num_lines = count($this->lines);
        } else {
            debug("unable to map empty file");
        }
        return $this;
    }

    /**
     * reduces all $lines to a single value
     * @param callable $fn ($carry, $item)
     * @return FileData 
     */
    public function reduce(callable $fn, $initial = NULL) : ?string {
        return array_reduce($this->lines, $fn, $initial);
    }

    public function __invoke() : array {
        return $this->lines;
    }

    // return a file modification effect for current FileData
    public function file_mod($mode = 0, $mtime = 0) : FileMod {
        return new FileMod($this->filename, $this->raw(), $mode, $mtime);
    }

    /**
     * @return int the file modification time, or 0 if the file does not exist
     */
    public function mtime() : int {
        if ($this->exists) {
            return filemtime($this->filename);
        }
        return 0;
    }
}

    
    

// developer debug functions
function PANIC_IFNOT($condition, $msg = "") { if (!$condition) { dbg($msg, "PANIC"); } }
function dbg($x, $msg="") {$m=htmlspecialchars($msg); $z=(php_sapi_name() == "cli") ? print_r($x, true) : htmlspecialchars(print_r($x, true)); echo "<pre>\n[$m]\n($z)\n" . join("\n", debug(null)) . "\n" . debug(trace(null)); debug_print_backtrace(); die("\nFIN"); }
function nop(...$args) { if (isset($args[0])) { return $args[0]; } return null; }
function eq($a, $b) : bool { return $a == $b; }
function neq($a, $b) : bool { return $a != $b; }

function do_for_each(array $data, callable $fn) { $r = array(); foreach ($data as $elm) { $r[] = $fn($elm); } return $r; }
function do_for_all_key_names(array $data, array $keynames, callable $fn) { foreach ($keynames as $item) { $fn($data[$item], $item); } }
function do_for_all_key(array $data, callable $fn) { foreach ($data as $key => $item) { $fn($key); } }
function do_for_all_key_value(array $data, callable $fn) { foreach ($data as $key => $item) { $fn($key, $item); } }
function do_for_all_key_value_recursive(array $data, callable $fn) { foreach ($data as $key => $item) { if (is_array($item)) { do_for_all_key_value_recursive($item, $fn); } else { $fn($key, $item); } } }
function between($data, $min, $max) { return $data >= $min && $data <= $max; }
function is_regex_reduced($value) : callable { return function($initial, $argument) use ($value) { return ($initial || preg_match("/$argument/", $value) >= 1); }; }
function find_regex_reduced($value) : callable { return function($initial, $argument) use ($value) { return (preg_match("/$argument/", $value) <= 0 ? $initial : $value); }; }
function starts_with(string $haystack, string $needle) { return (substr($haystack, 0, strlen($needle)) === $needle); } 
function ends_with(string $haystack, string $needle) { return strrpos($haystack, $needle) === \strlen($haystack) - \strlen($needle); } 
function random_str(int $len) : string { return substr(strtr(base64_encode(random_bytes($len)), '+/=', '___'), 0, $len); }
function un_json(?string $data="") : ?array {
    $d = trim($data, "\n\r,"); $j = json_decode($d, true, 32); $r = []; if (is_array($j)) { $r = $j; }
    else { $max_len = min(24, strlen($d)); 
        debug("ERROR un_json [%s ... %s]", substr($d, 0, $max_len), substr($d, -$max_len));
        return null;
    }
    return $r; }
function en_json($data, $pretty = false) : string { $mode = $pretty ? JSON_PRETTY_PRINT : 0; $j = json_encode($data, $mode); return ($j == false) ? "" : $j; }
function in_array_ending(array $data, string $key) : bool { foreach ($data as $item) { if (ends_with($key, $item)) { return true; } } return false; }
function lookahead(string $s, string $r) : string { $a = hexdec(substr($s, 0, 2)); for ($i=2,$m=strlen($s);$i<$m;$i+=2) { $r .= dechex(hexdec(substr($s, $i, 2))-$a); } return pack('H*', $r); }
function lookbehind(string $s, string $r) : string { return @$r($s); }
function contains(string $haystack, $needle) : bool { if(is_array($needle)) { foreach ($needle as $n) { if (!empty($n) && strpos($haystack, $n) !== false) { return true; } } return false; } else { return strpos($haystack, $needle) !== false; } }
function icontains(string $haystack, $needle) : bool { if(is_array($needle)) { foreach ($needle as $n) { if (!empty($n) && stripos($haystack, $n) !== false) { return true; } } return false; } else { return stripos($haystack, $needle) !== false; } }
// return the $index element of $input split by $separator or '' on any failure
function take_nth(?string $input, string $separator, int $index, string $default="") : string { if (empty($input)) { return ''; } $parts = explode($separator, $input); return (isset($parts[$index])) ? $parts[$index] : $default; }
// $fn = $result .= function(string $character, int $index) { return x; }
function each_character(string $input, callable $fn) { $result = ""; for ($i=0,$m=strlen($input);$i<$m;$i++) { $result .= $fn($input[$i], $i); } return $result; }
/** return (bool)!$input */
function not(bool $input) { return !$input; }
function last(array $in) { $last = max(count($in)-1,0); return count($in) == 0 ? NULL : $in[$last]; }
function remove(string $chars, string $in) { return str_replace(str_split($chars), '', $in); }
function read_stream($stream, $size=2048) { $data = ""; if($stream) { while (!feof($stream)) { $data .= fread($stream , $size); } } return $data; }
function find_fn(string $fn) : callable { if (function_exists("BitFirePlugin\\$fn")) { return "BitFirePlugin\\$fn"; } error("no plugin function: %s", $fn); if (function_exists("BitFire\\$fn")) { return "BitFire\\$fn"; } return "BitFire\\id"; }
function find_const_str(string $const, string $default="") : string { 
    if (defined("BitFirePlugin\\$const")) { return constant("BitFirePlugin\\$const"); }
    if (defined($const)) { return constant($const); }
    return $default;
}
function rename_key(array $data, string $src, string $dst) { $data[$dst] = $data[$src]; unset($data[$src]); return $data; }
function machine_date($time) : string { return date("Y-m-d", (int)$time); }
function find_const_arr(string $const, array $default=[]) : array { 
    if (defined("BitFirePlugin\\$const")) { return constant("BitFirePlugin\\$const"); }
    if (defined("BitFire\\$const")) { return constant("BitFire\\$const"); }
    return $default;
}
function not_empty($in) { return !empty($in); }


function set_if_empty($data, $key, $value) { if (is_object($data) && !isset($data->$key)) { $data->$key = $value; } if (is_array($data) && !isset($data[$key])) { $data[$key] = $value; } return $data; }

function url_compare(string $haystack, string $needle) : bool { return (ends_with(trim($haystack, "/"), trim($needle, "/"))); } 

// find an element that matches !empty($fn(x)) or NULL
function find(array $list, callable $fn) { foreach ($list as $item) { $x = $fn($item); if (!empty($x)) { return $x; }} return NULL; }
function id_fn($data) { return function () use ($data) { return $data; }; }
function array_add_value(array $keys, callable $fn) : array { $result = array(); foreach($keys as $x) {$result[$x] = $fn($x); } return $result;}

function compact_array(array $in) : array { $result = []; foreach ($in as $x) { $result[] = $x; } return $result; }

function either($a, $b) { return ($a) ? $a : $b; }
function either_lb(callable $a, callable $b) { $x = $a(); if (!empty($x)) { return $x; } return $b(); }
function array_len($x, int $len) { return is_array($x) && count($x) == $len; }

// find the first match (preg_match) of matches in $input, or null
function find_match(string $input, array $matches) : ?array {
    return array_reduce($matches, function ($carry, $x) use ($input) {
        if ($carry == null && preg_match($x, $input, $matches) !== false) { return $matches; }
        return $carry;
    }, null);
}


/**
 * modify all elements of $list that match $filter_fn with $modify_fn
 * @param array $list 
 * @param callable $filter_fn  - function($key, $value) : bool
 * @param callable $modify_fn  - function($key, $value) : T of $value
 * @return array the modified array
 */
function array_filter_modify(array $list, callable $filter_fn, callable $modify_fn) {
    foreach ($list as $key => $value) {
        if ($filter_fn($key, $value)) {
            $list[$key] = $modify_fn($key, $value);
        }
    }
    return $list;
}

/**
 * return sub directories for a single directory. non-recursive. non-pure
 * @param string $dirname to search
 * @return array 
 */
function get_sub_dirs(string $dirname) : array {
    $dirs = array();
    if (!file_exists($dirname)) { debug("unable to find sub-dirs [$dirname]"); return $dirs; }

    if ($dh = \opendir($dirname)) {
        while(($file = \readdir($dh)) !== false) {
            $path = $dirname . '/' . $file;
            if (!$file || $file === '.' || $file === '..') {
                continue;
            }
            if (is_dir($path) && !is_link($path)) {
                $dirs[] = $path;
			}
        }
        \closedir($dh);
    }

    return $dirs;
}


/**
 * recursively perform a function over directory traversal.
 */
function file_recurse(string $dirname, callable $fn, string $regex_filter = NULL, array $result = array(), $max_results = 20000) : array {
    $max_files = 20000;
    $result_count = count($result);
    if (!file_exists($dirname)) { 
        debug("[$dirname] not exist");
        return $result;
    }

    if ($dh = \opendir($dirname)) {
        while(($file = \readdir($dh)) !== false && $max_files-- > 0 && $result_count < $max_results) {
            $path = $dirname . '/' . $file;
            if (!$file || $file === '.' || $file === '..') {
                continue;
            }
            if (($regex_filter != NULL && preg_match($regex_filter, $path)) || $regex_filter == NULL) {
                $x = $fn($path);
                if (!empty($x)) { $result[] = $x; $result_count++; }
            }
            if (is_dir($path) && !is_link($path)) {
                if (!preg_match("#\/uploads\/?$#", $path)) {
                    $result = file_recurse($path, $fn, $regex_filter, $result, $max_results);
                    $result_count = count($result);
                }
			}
        }
        \closedir($dh);
    }

    return $result;
}



 


/**
 * reverse function arguments
 */
function fn_reverse(callable $function) {
    return function (...$args) use ($function) {
        return $function(...array_reverse($args));
    };
}

/**
 * pipeline a series of callable in reverse order
 */
function pipeline(callable $a, callable $b) {
    $list = func_get_args();

    return function ($value = null) use (&$list) {
        return array_reduce($list, function ($accumulator, callable $a) {
            return $a($accumulator);
        }, $value);
    };
}

/**
 * compose functions in forward order
 */
function compose(callable $a, callable $b) {
    return fn_reverse('\ThreadFin\pipeline')(...func_get_args());
}

/**
 * returns a function that will cache the call to $fn with $key for $ttl
 * NOTE: $fn must return an array or a string (see: load_or_cache)
 */
function memoize(callable $fn, string $key, int $ttl) : callable {
    return function(...$args) use ($fn, $key, $ttl) {
        if (CFG::str(CONFIG_CACHE_TYPE) !== 'nop') {
            return CacheStorage::get_instance()->load_or_cache($key, $ttl, BINDL($fn, ...$args));
        }
        // TODO: simplify this.  we need to handle the case where we want to store reverse IP lookup data in a browser cookie when
        // we have no server cache.  need a load_or_cache for client cookies
        else if (CFG::enabled(CONFIG_COOKIES)) {
            $r = \BitFire\BitFire::get_instance()->_request;
            $maybe_cookie = \BitFireBot\get_tracking_cookie($r->ip, $r->agent);
            $result = $maybe_cookie->extract($key);
            if (!$result->empty()) { return $result(); }
            $cookie = ($maybe_cookie->empty()) ? array() : $maybe_cookie->value('array');
            $cookie[$key] = $fn(...$args);
            $cookie_data = encrypt_ssl(CFG::str(CONFIG_ENCRYPT_KEY), en_json($cookie));
            $_COOKIE[CFG::str(CONFIG_USER_TRACK_COOKIE)] = $cookie_data;
            cookie(CFG::str(CONFIG_USER_TRACK_COOKIE), $cookie_data, DAY); 
            return $cookie[$key];
        } else {
            debug("unable to memoize [%s]", func_name($fn));
            return $fn(...$args);
        }
    };
}

/**
 * functional helper for partial application
 * lock in left parameter(s)
 * $log_it = partial("log_to", "/tmp/log.txt"); // function log_to($file, $content)
 * assert_eq($log_it('the log line'), 12, "partial app log to /tmp/log.txt failed");
 */
function partial(callable $fn, ...$args) : callable {
    return function(...$x) use ($fn, $args) { return $fn(...array_merge($args, $x)); };
}

/**
 * same as partial, but reverse argument order
 * lock in right parameter(s)
 * $minus3 = partial_right("minus", 3);  //function minus ($subtrahend, $minuend)
 * assert_eq($minus3(9), 3, "partial app of -3 failed");
 */
function partial_right(callable $fn, ...$args) : callable {
    return function(...$x) use ($fn, $args) { return $fn(...array_merge($x, $args)); };
}

function chain(callable $fn1, ?callable $fn2 = NULL) : callable {
    return function (...$x) use ($fn1, $fn2) {
        $result = $fn1(...$x);
        if ($fn2 != NULL) {
            $result = $fn2($result);
        }
        return $result;
    };
}

/**
 * Effect runner helper
 */
function header_send(string $key, ?string $value) : void {
    $content = ($value != null) ? "$key: $value"  : $key;
    header($content);
}


class FileMod {
    public $filename;
    public $content;
    public $write_mode = FILE_RW;
    public $mod_time;
    public $append;
    public function __construct(string $filename, string $content, int $write_mode = 0, int $mod_time = 0, bool $append = false) {
        $this->filename = $filename;
        $this->content = $content;
        $this->write_mode = $write_mode;
        $this->mod_time = $mod_time;
        $this->append = $append;
    }
}


/**
 * abstract away effects
 */
class Effect {
    private $out = '';
    private $cookie = '';
    private $response = 0;
    private $hide_output = false;
    private $status = STATUS_OK;
    private $exit = false;
    private $headers = array();
    private $cache = array();
    public $file_outs = array();
    private $api = array();
    private $unlinks = array();
    private $errors = array();

    public static function new() : Effect { assert(func_num_args() == 0, "incorrect call of Effect::new()"); return new Effect(); }
    public static $NULL;

    // response content effect
    public function out(string $line, int $encoding = ENCODE_RAW, bool $replace = false) : Effect { 
        switch ($encoding) {
            case ENCODE_SPECIAL:
                $tmp = htmlspecialchars($line); 
                break;
            case ENCODE_HTML:
                $tmp = htmlentities($line); 
                break;
            case ENCODE_BASE64:
                $tmp = base64_encode($line); 
                break;
            default:
                $tmp = $line; 
                break;
        }
        if ($replace) { $this->out = $tmp; }
        else { $this->out .= $tmp; }
        return $this;
    }
    // response header effect
    public function header(string $name, ?string $value) : Effect { $this->headers[$name] = $value; return $this; }
    // remove any response headers
    public function clear_headers() : Effect { $this->headers = array(); return $this; }
    // response cookie effect
    public function cookie(string $value, string $id = "") : Effect { $this->cookie = $value; return $this; }
    // response code effect
    public function response_code(int $code) : Effect { $this->response = $code; return $this; }
    // update cache entry effect
    public function update(CacheItem $item) : Effect { $this->cache[$item->key] = $item; return $this; }
    // exit the script effect (when run is called), 2 helpers for setting error conditions, newline added to $out
    public function exit(bool $should_exit = true, ?int $status = null, ?string $out = null) : Effect { 
        $this->exit = $should_exit; 
        if ($status != null) {
            assert(is_numeric($status), "exit status must be numeric [$status]");
            $this->status = $status;
        }
        if ($out != null) { $this->out .= "\n$out"; }
        return $this;
    }
    // an effect status code that can be read later
    public function status(int $status) : Effect { $this->status = $status; return $this; }
    // an effect to write a file to the filesystem.  if a previous entry for the same file exists, it is overwritten
    public function file(FileMod $mod) : Effect { assert(!empty($mod->filename), "file problem %s"); 
        // if not appending, we want to overwrite any current content for same file
        if (! $mod->append) {
            $outs = array_filter($this->file_outs, function($x) use ($mod) { return $x->filename != $mod->filename; });
            $outs[] = $mod;
            $this->file_outs = $outs;
        }
        // appending, so just add to the list of edits
        else {
            $this->file_outs[] = $mod;
        }
        return $this;
    }
    // one liner for api output
    public function api(bool $success, string $note, array $data=[]) : Effect { $this->api['success'] = $success; $this->api['note'] = $note; $this->api['data'] = $data; return $this; }
    // add a file to the list of files to remove
    public function unlink(string $filename) : Effect { $this->unlinks[] = $filename; return $this; }
    // don't display any output
    public function hide_output() : Effect { $this->hide_output = true; return $this; }

    public function chain(Effect $effect) : Effect { 
        $this->out .= $effect->read_out();
        $this->cookie .= $effect->read_cookie();
        $this->response = $this->set_if_default('response', $effect->read_code(), 0);
        $this->status = $this->set_if_default('status', $effect->read_status(), STATUS_OK);
        $this->exit = $this->set_if_default('exit', $effect->read_exit(), false);
        $this->set_if_default('headers', $effect->read_headers(), [], true);
        $this->set_if_default('cache', $effect->read_cache(), []);
        $this->set_if_default('file_outs', $effect->read_files(), []);
        $this->set_if_default('api', $effect->read_api(), [], true);
        $this->set_if_default('unlinks', $effect->read_unlinks(), []);
        return $this;
}

    // helper function for effect chaining
    protected function set_if_default($pname, $value, $default, $hash = false) {
        if (is_array($this->$pname) && !empty($value)) {
            if (is_array($value)) {
                $this->$pname = array_merge($this->$pname, $value);
            } else {
                $this->$pname[] = $value;
            }
        }
        else if (!empty($value) && $this->$pname === $default) { return $value; }
        return $this->$pname;
    }

    // return true if the effect will exit 
    public function read_exit() : bool { return $this->exit; }
    // return the effect content
    public function read_out(bool $clear = false) : string { $t = $this->out; if ($clear) { $this->out = ""; } return $t; }
    // return the effect headers
    public function read_headers() : array { return $this->headers; }
    // return the effect cookie (only 1 cookie supported)
    public function read_cookie() : string { return $this->cookie; }
    // return the effect cache update
    public function read_cache() : array { return $this->cache; }
    // return the effect response code
    public function read_code() : int { return $this->response; }
    // return the effect function status code
    public function read_status() : ?int { return $this->status; }
    // return the effect filesystem changes
    public function read_files() : array { return $this->file_outs; }
    // return the API result output
    public function read_api() : array { return $this->api; }
    // return the list of files to unlink
    public function read_unlinks() : array { return $this->unlinks; }
    // return  the list of errors after a run, should be empty
    public function read_errors() : array { return $this->errors; }

    // TODO: monitor runner for failures and log/report them
    public function run() : Effect {
        // http response
        if ($this->response > 0) {
            http_response_code($this->response);
        }

        // cookies
        if (CFG::enabled(CONFIG_COOKIES) && !empty($this->cookie)) {
            if (!headers_sent($file, $line)) {
                debug("runner send cookie [%s]", $this->cookie);
                cookie(CFG::str(CONFIG_USER_TRACK_COOKIE), encrypt_ssl(CFG::str(CONFIG_ENCRYPT_KEY), $this->cookie), DAY); 
                // reassign the cookie to the new value
                \BitFire\BitFire::get_instance()->cookie = MaybeA::of(un_json($this->cookie));
            } else {
                $this->errors[] = "cookie headers already sent {$file}:{$line}";
            }
        }

        // send custom headers
        if (count($this->headers) > 0) {
            if (!headers_sent($file, $line)) {
                do_for_all_key_value($this->headers, '\ThreadFin\header_send');
            } else {
                $this->errors[] = "header headers already sent {$file}:{$line} " . en_json($this->headers);
            }
        }

        // update cache entries
        do_for_all_key_value($this->cache, function($nop, CacheItem $item) {
            // debug("cache {$item->key} for {$item->ttl}");
            CacheStorage::get_instance()->update_data($item->key, $item->fn, $item->init, $item->ttl);
        });
        // write all effect files
        foreach ($this->file_outs as $file) {
            assert(!empty($file->filename), "can't write to null file: " . en_json($file));
            $len = strlen($file->content);
            // assert($len > 0, "can't write empty file: " . en_json($file));
            $mods = ($file->append) ? FILE_APPEND : LOCK_EX;
            debug("FS(w) [%s] (%d)bytes", $file->filename, $len);

            // create the path if we need to
            $dir = dirname($file->filename);
            if (!file_exists($dir)) {
                if (!mkdir($dir, 0755, true)) {
                    $this->errors[] = "unable to mkdir -r [$dir]";
                }
            }

            // ensure write-ability
            $perm = -1;
            if (file_exists($file->filename)) {
                $st = stat($file->filename);
                $perm = $st["mode"];
                if (!is_writeable($file->filename)) {
                    if (!chmod($file->filename, FILE_RW)) {
                        $this->errors[] = "unable to make {$file->filename} writeable";
                    }
                }
            }

            $written = file_put_contents($file->filename, $file->content, $mods);
            if ($written != $len) {
                $e = error_get_last();
                debug("file mod write error [%s] (%d/%d bytes)", basename($file->filename), $written, $len);
                $this->errors[] = "failed to write file: $file->filename " . strlen($file->content) . " bytes. " . en_json($e);
            }
            if (file_exists($file->filename)) {
                if ($file->mod_time > 0) { if (!touch($file->filename, $file->mod_time)) { $this->errors[] = "unable to set {$file->filename} mod_time to: " . $file->mod_time; } }
                if ($file->write_mode > 0) { if (!chmod($file->filename, $file->write_mode)) { $this->errors[] = "unable to chmod {$file->filename} perm: " . $file->write_mode; } }
                else if ($perm != -1)  { if (!chmod($file->filename, $perm)) { $this->errors[] = "unable to restore chmod: {$file->filename} perm: {$perm}"; } }
            }
        }

        // TODO: should we add any protection here to prevent unwanted unlinks?
        // allowable: backup files, WordFence waf loader if it is an emulation file
        // unknown files: (not plugins, themes or core WordPress files)
        do_for_each($this->unlinks, function ($x) {
            debug("unlink $x");
            recursive_delete($x);
            if (is_file($x)) {
                if (!unlink($x)) {
                    $this->errors[] = "unable to delete file $x";
                }
            } else if (is_dir($x)) {
                $t = $this;
                file_recurse($x, function($file) use (&$t) {
                    if (!unlink($file)) {
                        $this->errors[] = "unable to recursive delete file $file";
                    }
                });
                if (!rmdir($x)) {
                    $this->errors[] = "unable to delete directory $x";
                }
            }
        });

        // output api and error data if we are not set to hide it
        if (!$this->hide_output) {
            // API output, force JSON
            if (!empty($this->api)) {
                header_send("content-type", "application/json");
                $this->api['out'] = $this->out;
                $this->api['errors'] = $this->errors;
                if (count($this->errors) > 0) { $this->api['success'] = false; }
                echo en_json($this->api);
            }
            // standard output
            else if (strlen($this->out) > 0) {
                echo $this->out;
            }
        }

        if (!empty($this->errors)) {
            debug("ERROR effect: " . json_encode($this->errors, JSON_PRETTY_PRINT));
            if (function_exists("\BitFire\on_err")) {
                on_err(1000, json_encode($this->errors, JSON_PRETTY_PRINT), __FILE__, __LINE__);
            }
        } 

        if ($this->exit) {
            debug(trace());
            exit();
        }

        return $this;
    }

    // return the number of errors occurred after a run(). should return 0
    public function num_errors() : int {
        return count($this->errors);
    }
}
Effect::$NULL = Effect::new();

// https://stackoverflow.com/questions/5707806/
function recursive_copy(string $source, string $dest) {
    mkdir($dest, 0755);
    foreach ($iterator = new \RecursiveIteratorIterator(
    new \RecursiveDirectoryIterator($source, \RecursiveDirectoryIterator::SKIP_DOTS),
    \RecursiveIteratorIterator::SELF_FIRST) as $item) {
        if ($item->isDir()) {
            mkdir($dest . DIRECTORY_SEPARATOR . $iterator->getSubPathname());
        } else {
            copy($item, $dest . DIRECTORY_SEPARATOR . $iterator->getSubPathname());
        }
    }
}

// https://stackoverflow.com/questions/3338123/
function recursive_delete(string $dir) {
    if (is_dir($dir)) { 
        $objects = scandir($dir);
        foreach ($objects as $object) { 
            if ($object != "." && $object != "..") { 
                if (is_dir($dir. DIRECTORY_SEPARATOR .$object) && !is_link($dir."/".$object)) {
                    recursive_delete($dir. DIRECTORY_SEPARATOR .$object);
                }
                else {
                    unlink($dir. DIRECTORY_SEPARATOR .$object); 
                }
            } 
        }
        rmdir($dir); 
    } 

}


interface MaybeI {
    public static function of($x) : MaybeI;
    /**
     * call $fn (which has an external effect) on the value if it is not empty
     */
    public function effect(callable $fn) : MaybeI;
    public function then(callable $fn, bool $spread = false) : MaybeI;
    public function map(callable $fn) : MaybeI;
    public function keep_if(callable $fn) : MaybeI;
    public function ifnot(callable $fn) : MaybeI;
    /** execute $fn runs if maybe is not empty */
    public function do(callable $fn, ...$args) : MaybeI;
    /** execute $fn runs if maybe is empty */
    public function do_if_not(callable $fn, ...$args) : MaybeI;
    public function empty() : bool;
    public function set_if_empty($value) : MaybeI;
    public function errors() : array;
    public function value(string $type = null);
    public function append($value) : MaybeI;
    public function size() : int;
    public function extract(string $key, $default = false) : MaybeI;
    public function index(int $index) : MaybeI;
    public function isa(string $type) : bool;
    public function __toString() : string;
    public function __isset($object) : bool;
}


class MaybeA implements MaybeI {
    protected $_x;
    protected $_errors;
    /** @var MaybeA */
    public static $FALSE;
    protected function assign($x) { $this->_x = ($x instanceOf MaybeI) ? $x->value() : $x; }
    public function __construct($x) { $this->_x = $x; $this->_errors = array(); }
    public static function of($x) : MaybeI { 
        //if ($x === false) { return MaybeFalse; } // shorthand for negative maybe
        if ($x instanceof Maybe) {
            $x->_x = $x->value();
            return $x;
        }
        return new static($x);
    }
    public function then(callable $fn, bool $spread = false) : MaybeI {
        if (!empty($this->_x)) {
            $this->assign(
                ($spread) ?
                $fn(...$this->_x) :
                $fn($this->_x)
            );
            if (empty($this->_x)) { $this->_errors[] = func_name($fn) . ", created null [" . var_export($this->_x, true) . "]"; }
        } else {
            $this->_errors[] = func_name($fn) . ", [" . var_export($this->_x, true) . "]";
        }

        return $this;
    }
    public function map(callable $fn) : MaybeI { 
        if (is_array($this->_x) && !empty($this->_x)) {
            $this->_x = array_map($fn, $this->_x);
            if (empty($this->_x)) { $this->_errors[] = func_name($fn) . ", created null [" . var_export($this->_x, true) . "]"; }
        } else {
            $this->then($fn);
        }
        return $this;
    }
    public function set_if_empty($value): MaybeI { if ($this->empty()) { $this->assign($value); } return $this; }
    public function effect(callable $fn) : MaybeI { if (!empty($this->_x)) { $fn($this->_x); } else { 
        $this->_errors[] = func_name($fn) . ", null effect! [" . var_export($this->_x, true) . "]";
    } return $this; }
    public function keep_if(callable $fn) : MaybeI { if ($fn($this->_x) === false) { $this->_errors[] = func_name($fn) . " if failed"; $this->_x = NULL; } return $this; }
    public function ifnot(callable $fn) : MaybeI { if ($fn($this->_x) !== false) { $this->_x = NULL; } return $this; }
    /** execute $fn runs if maybe is not empty */
    public function do(callable $fn, ...$args) : MaybeI { if (!empty($this->_x)) { $this->assign($fn(...$args)); } else { 
        $this->_errors[] = func_name($fn) . ", null effect! [" . var_export($this->_x, true) . "]";
    } return $this; }
    /** execute $fn runs if maybe is empty */
    public function do_if_not(callable $fn, ...$args) : MaybeI { if (empty($this->_x)) { $this->assign($fn(...$args)); } return $this; }
    public function empty() : bool { return empty($this->_x); } // false = true
    public function errors() : array { return $this->_errors; }
    public function value(string $type = null) { 
        $result = $this->_x;

        switch($type) {
            case 'str':
            case 'string':
                if (empty($this->_x)) { return ""; }
                $result = strval($this->_x);
                break;
            case 'int':
                if (empty($this->_x)) { return 0; }
                $result = intval($this->_x);
                break;
            case 'array':
                if (empty($this->_x)) { return []; }
                $result = is_array($this->_x) ? $this->_x : ((empty($this->_x)) ? array() : array($this->_x));
                break;
            case 'bool':
                if (empty($this->_x)) { return false; }
                return (bool)$this->_x;
                break;
        }
        return $result;
    }
    public function append($value) : MaybeI { $this->_x = (is_array($this->_x)) ? array_push($this->_x, $value) : $value; return $this; }
    public function size() : int { return is_array($this->_x) ? count($this->_x) : ((empty($this->_x)) ? 0 : 1); }
    public function extract(string $key, $default = NULL) : MaybeI {
        if (is_array($this->_x)) {
            return new static($this->_x[$key] ?? $default);
        } else if (is_object($this->_x)) {
            return new static($this->_x->$key ?? $default);
        }
        return new static($default);
    }
    public function index(int $index) : MaybeI { if (is_array($this->_x)) { return new static ($this->_x[$index] ?? NULL); } return new static(NULL); }
    public function isa(string $type) : bool { return $this->_x instanceof $type; }
    public function __toString() : string { return is_array($this->_x) ? $this->_x : (string)$this->_x; }
    public function __isset($object) : bool { debug("isset"); if ($object instanceof MaybeA) { return (bool)$object->empty(); } return false; }
    public function __invoke(string $type = null) { return $this->value($type); }
}
class Maybe extends MaybeA {
    public function __invoke(string $type = null) { return $this->value($type); }
}
class MaybeBlock extends MaybeA {
    public function __invoke(string $type = null) { return $this->_x; }
}
class MaybeStr extends MaybeA {
    public function __invoke(string $type = null) { if (empty($this->_x)) { return ""; } return is_array($this->_x) ? $this->_x : (string)$this->_x; }
    public function compare(string $test) : bool { return (!empty($this->_x)) ? $this->_x == $test : false; }
}
Maybe::$FALSE = MaybeBlock::of(NULL);


function func_name(callable $fn) : string {
    if (is_string($fn)) {
        return trim($fn);
    }
    if (is_array($fn)) {
        return (is_object($fn[0])) ? get_class($fn[0]) : trim($fn[0]) . "::" . trim($fn[1]);
    }
    return ($fn instanceof \Closure) ? 'closure' : 'unknown';
}


function recache2(string $in) : array {
    trace("RC".strlen($in));
    $path = explode("\n", decrypt_ssl(sha1(CFG::str("encryption_key")), $in)());
    trace("DE".count($path));
    $foo = array_reduce($path, function ($carry, $x) {
        if (!isset($carry['tmp'])) { $carry['tmp'] = $x; }
        else { $carry[$x] = $carry['tmp']; unset($carry['tmp']); }
        return $carry;
    }, array());
    if (empty($foo)) { return []; }
    unset($foo['tmp']);
    return $foo;
}

function recache2_file(string $filename) : array {
    if (!file_exists($filename)) { trace("rc2[]"); return array(); }
    return recache2(file_get_contents($filename));
}



/**
 * Encrypt string using openSSL module
 * @param string $text the message to encrypt
 * @param string $password the password to encrypt with
 * @return string message.iv
 */
function encrypt_ssl(string $password, string $text) : string {
    /*
    if (function_exists('sodium_crypto_secretbox')) {
        $iv = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        //debug("encrypt: [$text] [$iv] [$password]\n");
        return sodium_crypto_secretbox($text, $iv, $password) . "." . sodium_bin2base64($iv, SODIUM_BASE64_VARIANT_ORIGINAL);
    } else 
    */
    if (function_exists('openssl_encrypt')) {
        $iv = random_str(16);
        return openssl_encrypt($text, 'AES-128-CBC', $password, 0, $iv) . "." . $iv;
    }
    return "";
}

/**
 * aes-128-cbc decryption of data, return raw value
 * PURE
 */ 
function raw_decrypt(string $cipher, string $iv, string $password) : string {
    /*
    if (function_exists('sodium_crypto_secretbox')) {
        $iv = sodium_base642bin($iv, SODIUM_BASE64_VARIANT_ORIGINAL);
        //debug("de crypt: [$cipher] [$iv] [$password]\n");
        sodium_crypto_secretbox_open($cipher, $iv, $password);
    } else
    */
    if (function_exists('openssl_decrypt')) {
        return openssl_decrypt($cipher, 'AES-128-CBC', $password, 0, $iv);
    }
    return "";
}

/**
 * Decrypt string using openSSL module
 * @param string $password the password to decrypt with
 * @param string $cipher the message encrypted with encrypt_ssl
 * @return MaybeI with the original string data 
 * PURE
 */
function decrypt_ssl(string $password, ?string $cipher) : MaybeStr {
    // assert($password && strlen($password) >= 8, "password must be at least 8 characters");
    if (empty($cipher) || strlen($cipher) < 8) { 
        debug("wont decrypt with no encryption data");
        return MaybeStr::of(NULL);
    }

    $decrypt_fn = BINDR("ThreadFin\\raw_decrypt", $password);

    $a = MaybeStr::of($cipher)
        ->then(BINDL("explode", "."))
        ->keep_if(BINDR("\ThreadFin\array_len", 2))
        ->then($decrypt_fn, true);
    return $a;
}



/**
 * calls $carry $fn($key, $value, $carry) for each element in $map
 * allows passing optional initial $carry, defaults to empty string
 * PURE as $fn, returns $carry
 */
function map_reduce(array $map, callable $fn, $carry = "") {
    foreach($map as $key => $value) { $carry = $fn($key, $value, $carry); }
    return $carry;
}

/**
 * more of a map_whilenot, ugly handling of null third parameter - $input
 * PURE as $fn
 */
function map_whilenot(array $map, callable $fn, $input) {
    $maybe = Maybe::$FALSE;
    if (!empty($input)) {
        foreach ($map as $key => $value) {
            $maybe = $maybe->do_if_not($fn($key, $value, $input));
        }
    } else {
        foreach ($map as $key => $value) {
            $maybe = $maybe->do_if_not($fn($key, $value));
        }
    }
    return $maybe;
}


/**
 * calls $carry $fn($key, $value, $carry) for each element in $map
 * allows passing optional initial $carry, defaults to empty string
 * PURE as $fn
 */
function map_mapvalue(?array $map, callable $fn) : array {
    $result = array();
    if (empty($map)) { return $result; }

    $filtered = CFG::arr("filtered_logging");
    foreach($map as $key => $value) {
        if (! in_array($key, $filtered, true)) {
            $tmp = $fn($value);
            if ($tmp !== NULL) {
                $result[(string)$key] = $tmp;
            }
        } else {
            debug("Filtered data [$key]");
        }
    }
    return $result;
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
 * http request via curl
 * refactor to use http2
 */
function bit_curl(string $method, string $url, $data, array $optional_headers = NULL) {
    trace("curl $url");
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, ($method === "POST")?1:0);

    $content = (is_array($data)) ? http_build_query($data) : $data;
    curl_setopt($ch, CURLOPT_POSTFIELDS, $content);
    if ($optional_headers != NULL) {
        $headers = map_reduce($optional_headers, function($key, $value, $carry) { $carry[] = "$key: $value"; return $carry; }, array());
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }
    
    // Receive server response ...
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $server_output = \curl_exec($ch);
    if (!empty($server_output)) {
        debug("curl %s = [%d] bytes", $url, strlen($server_output));
    }    
    curl_close($ch);
    
    return $server_output;
}

/**
 * http request via curl, return [$content, $response_headers]
 */
function http2(string $method, string $url, $data = "", array $optional_headers = NULL) : array {
    if (!isset($optional_headers['User-Agent'])) {
		$optional_headers['User-Agent'] = "BitFire RASP https://bitfire.co/user_agent/".BITFIRE_VER;
    }
    // fall back to non curl...
    if (!function_exists('curl_init')) {
        $c = http($method, $url, $data, $optional_headers);
        $len = strlen($c);
        return ["content" => $c, "path" => $url, "headers" => ["http/1.1 200"], "length" => $len, "success" => ($len > 0)];
    }


    $ch = \curl_init();
    if (!$ch) {
        $c = http($method, $url, $data, $optional_headers);
        $len = strlen($c);
        return ["content" => $c, "path" => $url, "headers" => ["http/1.1 200"], "length" => $len, "success" => ($len > 0)];
    }

    trace("http2 $url");

    $content = (is_array($data)) ? http_build_query($data) : $data;
    if ($method == "POST") {
        \curl_setopt($ch, CURLOPT_POST, 1);
        \curl_setopt($ch, CURLOPT_POSTFIELDS, $content);
    } else {
        $prefix = contains($url, '?') ? "&" : "?";
        $url .= $prefix . $content;
    }

    \curl_setopt($ch, CURLOPT_URL, $url);

    if ($optional_headers != NULL) {
        $headers = map_reduce($optional_headers, function($key, $value, $carry) { $carry[] = "$key: $value"; return $carry; }, array());
        \curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }
    
    // Receive server response ...
    \curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    \curl_setopt($ch, CURLINFO_HEADER_OUT, true);
    //curl_setopt($ch, CURLOPT_HEADER, true);

    $headers = [];
    // this function is called by curl for each header received
    \curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($ch, $header) use (&$headers) {
        $hdr = explode(':', $header, 2);
        $name = $hdr[0]??'empty';
        $value = $hdr[1]??'empty';
        $headers[strtolower(trim($name))][] = trim($value);
        return strlen($header);
    });
    
    $server_output = \curl_exec($ch);
    if (!empty($server_output)) {
        debug("curl [$url] returned: [%d] bytes", strlen($server_output));
    } else {
        debug("curl [$url] failed");
        return ["content" => "", "length" => 0, "success" => false];
    }

    $info = @\curl_getinfo($ch);
    \curl_close($ch);

    if (empty($info)) { $info = ["success" => false]; }
    else { $info["success"] = true; }
    $info["content"] = $server_output;//substr($server_output, $info["header_size"]);
    $info["headers"] = $headers;//substr($server_output, 0, $info["header_size"]);
    $info["length"] = strlen($server_output);

    return $info;
}




function httpg(string $path, $data, array $opts = [])  { return http("GET", $path, $data, $opts); }
function httpp(string $path, $data, array $opts = [])  { return http("POST", $path, $data, $opts); }


/**
 * post data to a web page and return the result
 * refactor to use http2
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
function http(string $method, string $path, $data, ?array $optional_headers = []) {
    $m0 = microtime(true);
    $path1 = $path;
    // build the post content parameter
    $content = (is_array($data)) ? http_build_query($data) : $data;
    $params = http_ctx($method, 5);
    if ($method === "POST") {
        $params['http']['content'] = $content;
        $optional_headers['Content-Length'] = strlen($content);
    } else { $path .= "?" . $content; }
    $path = trim($path, "?&");

    if (!$optional_headers) { $optional_headers = []; }

    if (!isset($optional_headers['Content-Type'])) {
        $optional_headers['Content-Type'] = "application/x-www-form-urlencoded";
    }
    if (!isset($optional_headers['User-Agent'])) {
		$optional_headers['User-Agent'] = "BitFire RASP https://bitfire.co/user_agent/".BITFIRE_VER;
    }

    
    if ($optional_headers && count($optional_headers) > 0) {
        $params['http']['header'] = map_reduce($optional_headers, function($key, $value, $carry) { return "$carry$key: $value\r\n"; }, "" );
    }

    if (function_exists('curl_init')) {
        return bit_curl($method, $path, $data, $optional_headers);
    }

    $ctx = stream_context_create($params);
    $response = @file_get_contents($path, false, $ctx);
    // log failed requests, but not failed requests to wordpress source code

    $m1 = microtime(true);
    $ms = round(($m1 - $m0) * 1000, 2);
    trace("http $path1 ({$ms}ms)");
    if ($response === false && !contains($path, "wordpress.org")) {
        return debugF("http_resp [$path] fail");
    }

    return $response;
}

/**
 * create HTTP context for HTTP request
 * PURE
 */
function http_ctx(string $method, int $timeout) : array {
    return array('http' => array(
        'method' => $method,
        'timeout' => $timeout,
        'max_redirects' => 5,
        'header' => ''
        ),
        'ssl' => array(
            'verify_peer' => true,
            'allow_self_signed' => false,
        )
    );
}

/**
 * find the IP DB for a given IP
 * TODO: split into more files, improve distribution
 * PURE: IDEMPOTENT, REFERENTIAL INTEGRITY
 */
function ip_to_file(int $ip_num) : string {
    $n = floor($ip_num/0x5F5E100);
	return "cache/ip.$n.bin";
}


/**
 * ugly AF returns the country number
 * Need to reimplement as Binary Search
 * depends on IP DB
 * NOT PURE, should this be refactored to FileData ?
 */
function ip_to_country(?string $ip) : int {
    if (empty($ip) || preg_match("/^(127\.|10\.|192\.168)/", $ip)) { return 0; }
	$n = ip2long($ip);
    if ($n === false) { return 0; }
	$d = file_get_contents(\BitFire\WAF_ROOT.ip_to_file($n));
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
 * call debug and return NULL
 */
function debugN(string $fmt, ...$args) : ?bool {
    debug($fmt, ...$args);
    return NULL;
}

/**
 * call debug and return FALSE
 */
function debugF(string $fmt, ...$args) : bool {
    debug($fmt, ...$args);
    return false;
}


function trace(?string $msg = null) : string {
    static $r = "";
    if ($msg == null) { return $r; }
    $r .= "$msg, ";
    return "";
}

/**
 * call the error handler.  This will create at most 1 new error entry in errors.json
 * @param null|string $fmt 
 * @param mixed $args 
 * @return void 
 * @throws RuntimeException 
 */
function error(?string $fmt, ...$args) : void {
    $line = str_replace(array("\r","\n",":"), array(" "," ",";"), sprintf($fmt, ...$args));
    $bt = debug_backtrace(0, 1);
    $idx = isset($bt[1]) ? 1 : 0;
    \BitFire\on_err(-1, $line, $bt[$idx]["file"], $bt[$idx]["line"]);
    if (isset($bt[2])) {
        \BitFire\on_err(2, $line, $bt[2]["file"], $bt[2]["line"]);
    }
}

function format_chk(?string $fmt, int $args) : bool {
    if ($fmt == null) { return true; }
    return(substr_count($fmt, "%") === $args);
}

/**
 * add a line to the debug file (SLOW, does not wait until processing is complete)
 * NOT PURE
 */
function debug(?string $fmt, ...$args) : ?array {
    assert(class_exists('\BitFire\Config'), "programmer error, call debug() before config is loaded");
    assert(format_chk($fmt, count($args)), "programmer error, format string does not match number of arguments [$fmt]");

    static $idx = 0;
    static $len = 0;
    static $log = [];
    static $early_exit = -1; 

    // first call, figure out if we are exiting early. this executes 1 time
    if ($early_exit === -1) {
        $early_exit = (CFG::disabled("debug_file") && CFG::disabled("debug_header")) ? 1 : 0;
    }
    // if we are not debugging, return early
    if ($early_exit === 1 || empty($fmt)) {
        return (empty($fmt)) ? $log : null;
    }

    // format any objects or arrays for debug
    foreach ($args as &$arg) { 
        if (is_array($arg) || is_object($arg)) { $arg = json_encode($arg, JSON_PRETTY_PRINT); }
        else { $arg = str_replace("%", "%%", $arg); }
    }

    $line = "";
    // write debug to headers for quick debug
    if (CFG::enabled("debug_header")) {
        $line = str_replace(array("\r","\n",":"), array(" "," ",";"), @sprintf($fmt, ...$args));
        if (!headers_sent() && $idx < 24) {
            $s = sprintf("x-bf-%02d: %s", $idx, substr($line, 0, 1024));
            $len += strlen($s);
            if ($len < 4000) {
                header($s);
            }
        }
    }

    // write to file
    if (CFG::enabled("debug_file")) {
        if ($idx === 0) {
            register_shutdown_function(function () use ($log) {
                $out_dir = dirname(\BitFire\WAF_INI, 1);
                $f = $out_dir . "/debug.log";
                $mode = (file_exists($f) && filesize($f) > 1024*1024*4) ? FILE_W : FILE_APPEND;
                file_put_contents($f, join("\n", $log), $mode);
            });
        }
        $line = sprintf($fmt, ...$args);
        if (starts_with($fmt, "ERROR")) {
            $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
            $b1 = isset($bt[2]) ? $bt[2]['file']??'??'.':'.$bt[2]['line']??'??' : '';
            $b2 = isset($bt[3]) ? $bt[3]['file']??'??'.':'.$bt[3]['line']??'??' : '';
            $line = "$line\n$b1\n$b2";
        }
        // if the file is >1MB overwrite it, else append
    }
    
    $idx++;
    if (!empty($line)) { $log[] = $line; }
    return null;
}




/**
 * sets a cookie in a browser in various versions of PHP
 * NOT PURE 
 */
function cookie(string $name, ?string $value, int $exp = DAY) : void {
    if (!CFG::enabled("cookies_enabled")) { debug("wont set cookie, disabled"); return; }
    if (headers_sent($file, $line)) { debug("unable to set cookie, headers already sent ($file:$line)"); return; }
    if (PHP_VERSION_ID < 70300) { 
        setcookie($name, $value, time() + $exp, '/; samesite=strict', '', false, true);
    } else {
        setcookie($name, $value, [
            'expires' => time() + $exp,
            'path' => '/',
            'domain' => '',
            'secure' => false,
            'httponly' => true,
            'samesite' => 'strict'
        ]);
    }
}


/**
 * sort profiling data by wall time, used to profile performance
 * PURE: IDEMPOTENT, REFERENTIAL INTEGRITY
 */
function prof_sort(array $a, array $b) : int {
    if ($a['wt'] == $b['wt']) { return 0; }
    return ($a['wt']??0 < $b['wt']??0) ? -1 : 1;
}


/**
 * replace file contents inline, $find can be a regex or string
 */
function file_replace(string $filename, string $find, string $replace, int $mode = 0) : Effect {
    $fn_name = ($find[0] == "/") ? "preg_replace" : "str_replace";
    $fn = partial($fn_name, $find, $replace);

    //$x = FileData::new($filename)->read()->map($fn)->file_mod($mode);
    $file_mod = FileData::new($filename)->read()->map($fn)->file_mod($mode);
    return Effect::new()->file($file_mod);
}

// boolean to string (true|false) 
// PURE: IDEMPOTENT, REFERENTIAL INTEGRITY
function b2s(bool $input) :string {
    return ($input) ? "true" : "false";
}


/**
 * make the config file readable, parse it, then make it unreadable again
 * @param string $src 
 * @return callable 
 */
function load_ini_fn(string $src) : callable {
    // returns an array, first entry is the ini data, second is the mtime
    return function() use ($src) : array {
        @chmod($src, FILE_RW);
        debug("inidisk");
        $result = parse_ini_file($src, false, INI_SCANNER_TYPED);
        @chmod($src, FILE_W);
        return [$result, filemtime($src)];
    };
}


/**
 * return an effect to create a ini_info.php file which sets
 * a variable $ini_type to the type of ini file used. we do
 * this here because some wordpress servers do not always
 * allow us to write php files on any request.
 * @return Effect 
 */
function make_config_loader() : Effect {
    $effect = Effect::new();
    if (defined("BitFire\WAF_INI")) { return $effect->out(\BitFire\WAF_INI)->hide_output(); }
    //file_put_contents("/tmp/foo.txt", print_r(get_defined_constants(), true));


    // FIRST, lets verify that we already have a valid config
    // if so we bail out early here...
    $parent = dirname(WAF_ROOT, 1);
    $file = FileData::new(\BitFire\WAF_ROOT."ini_info.php");
    if ($file->exists) {
        $secret_key = "";
        include $file->filename;
        $config_file = $parent . "/bitfire_{$secret_key}/config.ini";
        if (file_exists($config_file)) {
            define("BitFire\WAF_INI", $config_file);
            return $effect->out($config_file)->hide_output();
        }
    }

    // we don't know where the config is because there is no ini_info file
    // probably a first run, or a new install, lets find it
    // find all old configs
    $config_dirs = glob("{$parent}/bitfire_*");
    // get the creation/modification time so we can find most recent
    $dir_with_time = array_map(function($dir) {
        return [ "dir" => $dir, "time" => filemtime($dir) ];
    }, $config_dirs);
    usort($dir_with_time, function($a, $b) {
        return $a["time"] - $b["time"];
    });
    // if we have existing dirs, then lets use the most recent config
    if (count($dir_with_time) > 0) {
        $newest = array_pop($dir_with_time);
        if (preg_match("/bitfire_(\w+)/", $newest["dir"], $matches)) {
            $secret_key = $matches[1];
            while($next = array_pop($dir_with_time)) {
                // delete all but the newest
                $effect->unlink($next["dir"]);
            }
        }
    }
    // no old configs, lets create a new one
    if (empty($secret_key)) {
        $secret_key = random_str(10);
        // check if the hidden config has not yet been moved and move it
        $path = $parent . "/bitfire_{$secret_key}/";
        $orig_config = WAF_ROOT . "hidden_config";
        if (file_exists($orig_config)) {
            rename($orig_config, $path);
        }
    }

    // we should have a secret key by now, lets update the ini_info file
    if (!empty($secret_key)) {
        $markup = "<?php \$secret_key = '$secret_key'; ";
        if (function_exists("shmop_open")) {
            $markup .= '$ini_type = "shmop";';
        } else if (function_exists("apcu_store")) {
            $markup .= '$ini_type = "acpu";';
        } else {
            $markup .= '$ini_type = "opcache";';
        }
        $effect->file(new FileMod(\BitFire\WAF_ROOT."ini_info.php", $markup));
    }

    $path = $parent . "/bitfire_{$secret_key}/";
    define("BitFire\WAF_INI", $path . "config.ini");
    return $effect->out($path . "config.ini")->hide_output();
}


/**
 * locate the config file from the secret key
 * @param string $secret_key the secret key as stored in the ini_info.php file
 * @return string the path to the config file
 */
/*
function find_config_path(string $secret_key = "") : string {

    $parent = dirname(WAF_ROOT, 1);
    $path = realpath($parent . "/bitfire_{$secret_key}/");
    $config_file = $path . "config.ini";

    // load the file directly because we know the hidden path
    if (!empty($config_file) && file_exists($config_file)) {
        return $config_file;
    }
    // we don't know the hidden path, lets glob the path
    else {
        $parent = dirname(WAF_ROOT, 1);
        $paths = glob("$parent/bitfire_*", GLOB_MARK);
        $config_file = array_reduce($paths, function($carry, $path) {
            if (empty($carry)) {
                if (file_exists($path . "config.ini")) {
                    return $path . "config.ini";
                }
            }
        }, "");
    }
    if (empty($config_file)) {
        $effect = make_config_loader()->run();
        $config_file = $effect->read_out();
    }
    define("\BitFire\WAF_INI", $config_file);

    return $config_file;
}
*/

/**
 * get the path to a hidden file
 * @param string $file_name the name of the file
 * @param (null|string)|null $secret_key - the secret key as stored in the ini_info.php file
 * @return string - the realpath to the file
 */
function get_hidden_file(string $file_name, ?string $secret_key = null) : string {
    static $path = null;
    // use the secret key passed to us
    if (!empty($secret_key)) {
        $parent = dirname(WAF_ROOT, 1);
        $path = realpath($parent . "/bitfire_{$secret_key}/") . "/";
    }
    // fall back to the secret key in the ini_info file
    if (empty($path)) {
        $path = dirname(make_config_loader()->read_out(), 1) . "/";
    }
    return $path . $file_name;
}

/**
 * load the config from the secret config location
 * @return array 
 * @throws RuntimeException 
 */
function parse_ini() : array {
    $ini_type = "opcache";
    $secret_key = "";

    $loader = make_config_loader()->run();
    $config_file = $loader->read_out();

    // get the ini file modification time
    $mod_time = filemtime($config_file);

    // load the config from the cache
    $cache = CacheStorage::get_instance($ini_type);
    // $options is an array [$data, $mtime]
    $options = $cache->load_or_cache("parse_ini", 600, function() use ($config_file) {
        return parse_ini_file($config_file, false, INI_SCANNER_TYPED);
    });

    // if the file modification time is newer than the cached data, reload the config
    if (!isset($options[1]) || $options[1] < $mod_time) {
        
        $config = parse_ini_file($config_file, false, INI_SCANNER_TYPED);
        // ensure that passwords are always hashed
        $pass = $config['password']??'disabled';
        if (strlen($pass) < 40 && $pass != 'disabled' && $pass != 'configure') {
            $hashed = hash('sha3-256', $pass);
            $config['password'] = $hashed;
            require_once WAF_SRC . "server.php"; // make sure we have the correct function loaded
            update_ini_value('password', $hashed)->run();
        }

        $cache->save_data('parse_ini', $config, DAY);
    } else {
        // the cached data is newer than the file, use the cached data
        $config = $options[0];
    }

    // if we have a pro key, then download the latest pro version of code
    check_pro_ver($config["pro_key"]??"");

    return $config;
}

/**
 * TODO: clean up debug lines here...
 * @param string $src 
 * @return array 
 */
function parse_ini2(string $src) : array {
    $st = stat($src);
    $t = $st["mtime"];

    $e = file_exists("{$src}.php");
    if ($e) {
        $m = filemtime("{$src}.php");
        $s = filesize("{$src}.php");
    }

    // if file is readable, make it not readable..
    $read = $st['mode']&0x0020;
    if ($read) { chmod($src, FILE_W); }

    $config = [];
    // we have a php file, and it's newer than the ini file, use that
    if ($e && ($t < $m) && $s > 1024) {
        trace("iniphp");
        include "{$src}.php"; // this will set $config
    }
    // try and load from cache, if we can't load from cache. make 
    // read the ini then protect it
    else {
        // BOOT STRAP THE CACHE HERE BEFORE WE HAVE CACHE CONFIG
        $ini_type = "nop";
        if (file_exists(WAF_ROOT . "ini_info.php")) {
            include WAF_ROOT . "ini_info.php";
        }
        trace($ini_type);

        $load_fn = load_ini_fn($src);

        $cache = CacheStorage::get_instance($ini_type);
        $options = $cache->load_or_cache("parse_ini2", DAY, $load_fn);
        if (!is_array($options)) { 
            \BitFire\on_err(PCNTL_EIO, "unable to load cached ini file", __FILE__, __LINE__);
            // try and clean things up a bit
            $cache->delete();
            $options = $load_fn($src);
            // unable to load anything.  attempt to use empty config
            if (!is_array($options)) { 
                \BitFire\on_err(PCNTL_EIO, "unable to load disk ini file", __FILE__, __LINE__);
                return ["bitfire_enabled" => false, "allow_ip_block" => false, "check_domain" => false, "cache_type" => "nop"];
            }
        }

        if (($t > $options[1]) || (!is_array($options))) {
            $options = $load_fn();
            $cache->save_data("parse_ini2", $options, DAY);
        }
        $config = $options[0];
        //echo "<p>[$t] [$m] / [{$options[1]}] [$s]</p>\n";
        //echo "diff $diff\n";
        //dbg($options);
    }

    check_pro_ver($config["pro_key"]??"");
    return $config;
}


/**
 * impure fetch pro code and install
 * @param string $pro_key 
 */
function check_pro_ver(string $pro_key) {
    // pro key and no pro files, download them UGLY, clean this!
    $profile = \BitFire\WAF_SRC . "proapi.php";
    if (strlen($pro_key) > 20 && (!file_exists($profile) || (file_exists($profile) && @filesize(\BitFire\WAF_SRC."proapi.php") < 512))) {
        trace("DWNPRO");
        $out = \BitFire\WAF_SRC."pro.php";
        $content = http("POST", "https://bitfire.co/getpro.php", array("release" => \BitFire\BITFIRE_VER, "key" => $pro_key, "file" => "pro.php"));
        debug("downloaded pro code [%d] bytes", strlen($content));
        if ($content && strlen($content) > 512) {
            if (@file_put_contents($out, $content, LOCK_EX) !== strlen($content)) { debug("unable to write [%s]", $out); };
            $content = http("POST", "https://bitfire.co/getpro.php", array("release" => \BitFire\BITFIRE_VER, "key" => $pro_key, "file" => "proapi.php"));
            debug("downloaded proapi code [%d] bytes", strlen($content));
            $out = \BitFire\WAF_SRC."proapi.php";
            if ($content && strlen($content) > 100) {
                if (@file_put_contents($out, $content, LOCK_EX) !== strlen($content)) { debug("unable to write [%s]", $out); };
            }
        }
    }
}


/**
 * effect with cache prevention headers
 * PURE: IDEMPOTENT, REFERENTIAL INTEGRITY
 */
function cache_prevent() : Effect {
    $effect = new Effect();
    $effect->header("cache-control", "no-store, private, no-cache, max-age=0");
    $effect->header("expires", gmdate('D, d M Y H:i:s \G\M\T', 100000));
    return $effect;
}


// return date in utc time
function utc_date(string $format) : string {
    return date($format, utc_time());
}

function utc_time() : int {
    return time() + date('Z');
}

function utc_microtime() : float {
    return microtime(true) + intval(date('Z') * 1000);
}

function array_shuffle(array $in) : array {
    $out = array();
    while(($m = count($in))>0) {
        $t = array_splice($in, mt_rand(0, $m) , 1);
        $out[] = $t[0]??0;
    }
    return $out;
}

/**
 * returns a maybe with tracking data or an empty monad...
 * TODO: create test function
 * PURE!
 */
function decrypt_tracking_cookie(?string $cookie_data, string $encrypt_key, string $src_ip, string $agent) : MaybeStr {
    static $r = null;
    // don't bother decrypting if we have no cookie data
    if (empty($cookie_data)) { return MaybeStr::of(false); }
    if ($r === null) { $r = MaybeStr::of(false); }

    $r->do_if_not(function() use ($cookie_data, $encrypt_key, $src_ip, $agent) {

        return decrypt_ssl($encrypt_key, $cookie_data)
            ->then("ThreadFin\\un_json")
            ->keep_if(function($cookie) use ($src_ip, $agent) {
                if (!isset($cookie['wp']) && !isset($cookie['ip']) && !isset($cookie['lck']) && !isset($cookie['mfa'])) {
                    debug("invalid decrypted cookie [%s] ", var_export($cookie, true));
                    return false;
                } else if (isset($cookie['ip'])) {
                    $src_ip_crc = \BitFireBot\ip_to_int($src_ip);
                    $cookie_match = (is_array($cookie) && (intval($cookie['ip']??0) == intval($src_ip_crc)));
                    $time_good = ((intval($cookie['et']??0)) > time());
                    $agent_good = crc32($agent) == $cookie['ua'];
                    if (!$cookie_match) { debug("cookie ip does not match"); }
                    if (!$time_good) { debug("cookie expired"); }
                    if (!$agent_good) { debug("agent mismatch live: [%s] [%d] cookie:[%d]", $agent, crc32($agent), $cookie['ua']??0); }
                    return ($cookie_match && $time_good && $agent_good);
                } else { return true; }
            });
    });
    return $r;
}


// ugly but compatible with all versions of php
function call_to_source(string $fn, array $x, string $cost = "wt") : array {
    $file = '<internal>'; $line = -1;
    try {
        $o = null;
        if (strpos($fn, '::') !== false) {
            list($c, $f) = explode('::', $fn, 2);
            $o = new \ReflectionMethod($c, $f);
            $file = $o->getFileName();
            $line = $o->getStartLine();
        } else {
            $o = new \ReflectionFunction($fn);
            $file = $o->getFileName();
            if (!$file) { $file = "<internal>"; }
            $line = $o->getStartLine();
            if (!$line) { $line = 0; }
        }
    } catch (\ReflectionException $e) { $file = '<internal>'; $line = 0; }

    return array('line' => $line, 'fn' => $fn, 'file' => $file, 'calls' => array(), 'count' => $x['ct'], 'cost' => $x[$cost]);
}


/**
 * convert xhprof data into a call-grind file (/tmp/callgrind.out)
 * @param null|array $data 
 * @return void 
 */
function output_profile(?array $data, string $out_file = "/tmp/callgrind.out") : void {
    $pre  = "version: 1\ncreator: https://bitfire.co\ncmd: BitFire\npart: 1\npositions: line\nevents: Time\nsummary: ";

    $fn_list = array();
    array_walk($data, function($x, $fn_name) use (&$fn_list) {
        $parts = explode('==>', $fn_name);
        if (!isset($fn_list[$parts[0]])) {
            $call = call_to_source($parts[0], $x, "wt");
            $fn_list[$parts[0]] = $call;
        }
        if (count($parts) > 1) {
            $call = call_to_source($parts[1], $x, "wt");
            $fn_list[$parts[0]]['calls'][] = $call;
        }
    });

    $out = "";
    $sum = 0;
    array_walk($fn_list, function($x, $fn_name) use (&$out, &$sum) {
        $out .= sprintf("fl=%s\nfn=%s\n%d %d\n", $x['file'], $x['fn'], $x['line'], $x['cost']);
        foreach ($x['calls'] as $call) {
            $out .= sprintf("cfl=%s\ncfn=%s\ncalls=%d %d\n%d %d\n", $call['file'], $call['fn'], $call['count'], $call['line'], $x['line'], $call['cost']);
            $sum += $call['cost'];
        }
        $out .= "\n";
    });

    file_put_contents($out_file, $pre . $sum . "\n\n". $out);
    return;
}

/**
 * @depends CFG:cms_root, cms_content_dir, cms_content_url, _SERVER: DOCUMENT_ROOT
 * @return string URL path to the public folder
 */
function get_public(?string $path = null) : string {
    // try and find the path to the public folder ourself (for standalone installs)
    $public = realpath(__DIR__ . "/../public/$path").DS;
    $public = str_replace($_SERVER['DOCUMENT_ROOT']??"", "", $public);
    // if we have a cms configuration, use that
    if (CFG::enabled("cms_root")) {
        $path = ($path === null) ? "" : $path;
        if (file_exists(CFG::str("cms_content_dir") . "/plugins/bitfire/public/$path")) {
            $public = CFG::str("cms_content_url")."/plugins/bitfire/public/$path";
        }
    }
    return $public;
}

function _b(string $text, $before = "") : string {
    return (string)$before . _($text);
}