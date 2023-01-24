<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * all functions are called via api_call() from bitfire.php and all authentication 
 * is done there before calling any of these methods.
 */

namespace BitFire;

use ThreadFin\CacheStorage;
use BitFire\Config as CFG;
use BitFire\StringResult as BitFireStringResult;
use RuntimeException;
use ThreadFin\Effect;
use ThreadFin\FileMod;
use ThreadFin\Maybe;
use ThreadFin\MaybeA;
use ThreadFin\MaybeBlock;

use const ThreadFin\DAY;

use function ThreadFin\dbg;
use function ThreadFin\ends_with;
use function ThreadFin\http2;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\map_reduce;
use function ThreadFin\partial as BINDL;

const MIN_SQL_CHARS=8;

const SQL_WORDS = array('add', 'all', 'alter', 'ascii', 'between', 'benchmark', 'case', 'contains', 'concat',
'distinct', 'drop', 'delay', 'except', 'exists', 'exec', 'from', 'lower', 'upper', 'outer', 'order', 'null', 
'md5', 'hex', 'like', 'true', 'false', 'function', 'or', 'and', 'left', 'join', 'group', 'having', 'right', 'substring', 'select', 'pg_sleep', 'sleep',
'update', '(', ')', ',', '=', '!', 'insert', 'union', 'while', 'where', 'waitfor', 'is null');
const SQL_CONTROL_CHARS = array(35 => 1, 39 => 1, 40 => 1, 41 => 1, 44 => 1, 45 => 1, 61 => 1);
const SQL_IMPORTANT_CHARS = array("\n", "\r", "  ", "\t", '(', ')');

const FAIL_SQL_LITE=14000;
const FAIL_SQL_SELECT=14001;
const FAIL_SQL_UNION=14002;
const FAIL_SQL_FOUND=14004;
const FAIL_SQL_OR=14005;
const FAIL_SQL_BENCHMARK=14007;
const FAIL_SQL_ORDER=14006;



const SPAM = "100%\s+free|100%\s+satisfied|50%\s+off|all\s+new|best\s+price|discount|for\s+free|be\s+your\sown\sboss|fast\s+cash|for\s+just|for\s+you|for\s+only|free\s+gift|free\s+sample|give\s+away|lowest\s+price|luxury|percent+free|prize|sale|click\s+here|click\s+below|deal|meet\s+single|double\s+your|earn\s+per|make\s+money|blockchain|interested\s+in\s+the\s+latest|einkommen";

const FAIL_SPAM = 18000;
const FAIL_FILE_UPLOAD = 21000;
const FAIL_FILE_PHP_EXT = 21001;
const FAIL_FILE_PHP_MIME = 21002;
const FAIL_FILE_PHP_TAG = 21003;
const FAIL_FILE_POLYGLOT = 21004;

class StringResult {
    public $len;
    public $value;
    public function __construct(string $v, int $l) {
        $this->len = $l;
        $this->value = $v;
    }
}

class WebFilter {


    public function __construct() {
    }
    
    
    public function inspect(\BitFire\Request $request, MaybeA $cookie) : MaybeBlock {
        $block = MaybeBlock::$FALSE;
        if ((count($request->get) + count($request->post)) == 0) {
            return $block;
        } 


        if (Config::enabled(CONFIG_WEB_FILTER_ENABLED)) {
            trace("web");
            $cache = CacheStorage::get_instance();
            
            // update keys and values
            $keyfile = \BitFire\WAF_ROOT."cache/keys2.raw";
            $valuefile = \BitFire\WAF_ROOT."cache/values2.raw";
            $update = -1; // file does not exist
            if (file_exists($keyfile)) { 
                $mtime = filemtime($keyfile);
                if ($mtime < time()-DAY) { $update = 2; }
                else if (filesize($keyfile) < 256) { $update = 3; }
                else { $update = 0; }
            }
            if ($update != 0) { trace("UP[$update]"); update_raw($keyfile, $valuefile)->run(); }

            // the reduction
            $keys = $cache->load_or_cache("webkeys2", DAY, BINDL('\ThreadFin\recache2_file', $keyfile));
            $values = $cache->load_or_cache("webvalues2", DAY, BINDL('\ThreadFin\recache2_file', $valuefile));
            $c1 = count($keys); $c2 = count($values);

            if ($c1 <= 1 || $c2 <= 1) { update_raw($keyfile, $valuefile)->run(); }
            if ($c1 <= 5) {
                // looks like encryption is broken here ...
                $keys = \ThreadFin\recache2_file($keyfile);
                trace("keys: " . count($keys));
                $cache->save_data("webkeys2", $keys, DAY);
            }
            if ($c2 <= 5) {
                $values = \ThreadFin\recache2_file($valuefile);
                trace("values: " . count($values));
                $cache->save_data("webvalues2", $values, DAY);
            }
            trace("KEY.".count($keys)." VAL.".count($values));
            // CONTINUE HERE, if keys or values are empty, then clear cache and reload...
            $reducer = BINDL('\\BitFire\\generic_reducer', $keys, $values);

            $x = $cookie->extract("x")->value("int");
            // always check on get params
            $block->do_if_not('\ThreadFin\map_whilenot', $request->get, $reducer, NULL);
            // don't check for post if user can
            if (empty($x) || $x < 2) {
                $block->do_if_not('\ThreadFin\map_whilenot', $request->post, $reducer, NULL);
            }
            $block->do_if_not('\ThreadFin\map_whilenot', $request->cookies, $reducer, NULL);
        }


        if (Config::enabled(CONFIG_SPAM_FILTER)) {
            $block = $block->do_if_not('\BitFire\search_spam', http_build_query($request->get) . http_build_query($request->post));
        }


        // SQL injection filter
        if (Config::enabled(CONFIG_SQL_FILTER)) {
            $block = $block->do_if_not('\BitFire\sql_filter', $request);
        }


        if (Config::enabled(CONFIG_FILE_FILTER)) {
            $a = $cookie->extract("wp")->value("int");
            // don't block core wordpress updates
            if ((empty($a) || intval($a) <= 2) && !ends_with($request->path, "admin/update.php")) {
                $block->do_if_not('\\BitFire\\file_filter', $_FILES);
            }
        }

        return $block;
    }
}

/**
 * filter for SQL injections
 */
function sql_filter(\BitFire\Request $request) : MaybeBlock {
    trace("sql");
    foreach ($request->get as $key => $value) {
        $maybe = search_sql($key, flatten($value), $request->get_freq[$key]);
        if (!$maybe->empty()) { return $maybe; }
    }
    foreach ($request->post as $key => $value) {
        $maybe = search_sql($key, flatten($value), $request->post_freq[$key]);
        if (!$maybe->empty()) { return $maybe; }
    }
    return Maybe::$FALSE;
}


/**
 * check file names, extensions and content for php scripts
 */
function file_filter(array $files) : MaybeBlock { 
    $block = Maybe::$FALSE;
    trace("file1:".count($files).":".$block->empty());
    
    foreach ($files as $file) {
        $block->do_if_not('\BitFire\check_ext_mime', $file);
        $block->do_if_not('\BitFire\check_php_tags', $file);
    }
    trace("file2:".count($files).":".$block->empty());

    return $block;
}

/**
 * look for php tags in file uploads
 */
function check_php_tags(array $file) : MaybeA {
    // check for <?php tags
    if (empty($file['tmp_name'])) { return Maybe::$FALSE; }
    $data = file_get_contents($file["tmp_name"]);
    if (stripos($data, "<?php") !== false) {
        if (preg_match('/<\?php\s/i', $data)) {
            return MaybeBlock::of(BitFire::new_block(FAIL_FILE_PHP_TAG, "file upload", $file["name"], ".php", BLOCK_SHORT));
        }
    }
    // check for phar polyglots (tar)
    if (substr($data, -4) === "GBMB") {
        return MaybeBlock::of(BitFire::new_block(FAIL_FILE_POLYGLOT, "file upload", $file["name"], "phar polyglot", BLOCK_SHORT));
    }

    return Maybe::$FALSE;
}

// basic file upload checks
function check_ext_mime(array $file) : MaybeA {

    // dbg($file, "FILE");
    
    if (!empty($file["tmp_name"]??"")) {
        // check file extensions...
        if (file_exists($file["tmp_name"])) {
            $p_info = pathinfo($file["tmp_name"]);
            if (ends_with(strtolower($file["name"]), "php") ||
                in_array(strtolower($p_info['extension']??''), array("php", "phtml", "php5", "php6", "php7", "php8", "phar"))) {
                return MaybeBlock::of(BitFire::new_block(FAIL_FILE_PHP_EXT, "file upload", $file["name"], ".php", BLOCK_SHORT));
            }
                
            // check mime types
            $ctx = finfo_open(FILEINFO_MIME_TYPE | FILEINFO_CONTINUE);
            $f_info = finfo_file($ctx, $file["tmp_name"]);
            if (stripos($f_info, "php") !== false || stripos($file["type"], "php") !== false) {
                return MaybeBlock::of(BitFire::new_block(FAIL_FILE_PHP_MIME, "file upload", $file["name"], ".php", BLOCK_SHORT));
            }
        }
    }

    return Maybe::$FALSE;
}


/**
 * find sql injection for short strings
 */
function search_short_sql(string $name, string $value) : MaybeA {
    if (preg_match('/\s*(or|and)\s+(\d+|true|false|\'\w+\'|)\s*!?=(\d+|true|false|\'\w+\'|)/sm', $value, $matches)) {
        return BitFire::get_instance()->new_block(FAIL_SQL_OR, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE);
    }
    /*
    if (preg_match('/\'?.*?(or|and|where|order\s+by)\s+[^\s]+(;|--|#|\'|\/\*)/sm', $value)) {
        return BitFire::get_instance()->new_block(FAIL_SQL_ORDER, $name, $value, ERR_SQL_INJECT, BLOCK_NONE);
    }
    */
    if (preg_match('/select\s+(all|distinct|distinctrow|high_priority|straight_join|sql_small_result|sql_big_result|sql_buffer_result|sql_no_cache|sql_calc_found_rows)*\s*[^\s]+\s+(into|from)/sm', $value, $matches)) {
        return BitFire::get_instance()->new_block(FAIL_SQL_ORDER, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE);
    }
    if (preg_match('/benchmark\s*\([^,]+\,[^\)]+\)/sm', $value) || preg_match('/waitfor\s+delay\s+[\'"]/sm', $value, $matches) || preg_match('/sleep\s*\(\d+\)/sm', $value, $matches)) {
        return BitFire::get_instance()->new_block(FAIL_SQL_BENCHMARK, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE);
    }
    if (preg_match('/union[\sal]+select\s+([\'\"0-9]|null|user|subs)/sm', $value, $matches)) {
        return BitFire::new_block(FAIL_SQL_UNION, $name, $matches[0], 'sql identified', 0);
    }
    if (preg_match('/\s+select\s+substr(ing)?\s+/', $value, $matches)) {
        return BitFire::get_instance()->new_block(FAIL_SQL_ORDER, $name, $matches[0], ERR_SQL_INJECT, BLOCK_NONE);
    }

    return Maybe::$FALSE;
}


/**
 * find sql looking things...
 * this could be way more functional, but it would be slower, choices...
 */
function search_sql(string $name, string $value, ?array $counts) : MaybeA {
    $p1 = strpos($value, "union");
    if ($p1 !== false) {
        $p2 = strpos($value, "select", $p1);
        if ($p2 > $p1) {
            $p3 = strpos($value, "from", $p2);
            if ($p3 > $p2) {
                return BitFire::new_block(FAIL_SQL_UNION, $name, $value, 'union SQL injection', 0);
            }
        }
    }


    if (preg_match('/(select\s+[\@\*])/sm', $value, $matches)) {
        return BitFire::new_block(FAIL_SQL_SELECT, $name, $value, ERR_SQL_INJECT, BLOCK_NONE);
    }

    // block short sql,
    $total_control = sum_sql_control_chars($counts);

    $stripped_comments = strip_comments($value);

    if (preg_match('/(select\s+[\@\*])/sm', $stripped_comments->value, $matches) || preg_match('/(select[^a-zA-Z0-9]+(from|if))/sm', $stripped_comments->value, $matches)) {
        return BitFire::new_block(FAIL_SQL_SELECT, $name, $value, ERR_SQL_INJECT, BLOCK_NONE);
    }
        
    $block = Maybe::$FALSE;
    // look for the short injection types
	if ($total_control > 0) { 
		$block->do_if_not('\BitFire\search_short_sql', $name, $value);
		$block->do_if_not('\BitFire\search_short_sql', $name, $stripped_comments->value);
	}
    $block->do_if_not('\BitFire\check_removed_sql', $stripped_comments, $total_control, $name, $value);

    return $block;
}

/**
 * check if removed sql was found
 */
function check_removed_sql(StringResult $stripped_comments, int $total_control, string $name, string $value) : MaybeA {
 

    $sql_removed = str_replace(SQL_WORDS, "", $stripped_comments->value);
    $sql_removed_len = strlen($sql_removed);

    // if we have enough sql like syntax
    if ($sql_removed_len + MIN_SQL_CHARS <= $stripped_comments->len + $total_control) {
        // ugly but fast, remove temp variables ...
        $result = strip_strings($sql_removed);

        // we removed at least half of the input, look like sql to me..
        if (in_array($name, Config::arr("filtered_logging")) == false) {
            $removed_len = strlen($sql_removed);
            if ($result->len < ($removed_len / 2) || $result->len < ($removed_len - 20)) {
                return BitFire::new_block(FAIL_SQL_FOUND, $name, $value, 'sql identified', 0);
            } else if ($result->len < 15) {
                return search_short_sql($name, $result->value);
            }
        }
    }
    
    return Maybe::$FALSE;
}

/**
 * remove sql strings 
 */
function strip_strings(string $value) : StringResult {
    $stripped = map_reduce(array("/\s+/sm" => ' ', "/'[^']+$/sm" => '', "/'[^']*'/sm" => '', "/as\s\w+/sm" => ''), function($search, $replace, $carry) {
        return preg_replace($search, $replace, $carry);
    }, $value);
    return new StringResult($stripped, strlen($stripped));
}

/**
 * remove sql comments 
 */
function strip_comments(string $value) : StringResult {
    $s1 = str_replace(SQL_IMPORTANT_CHARS, " ", $value);
    $s2 = preg_replace("/\/\*.*?\*\//sm", '', $s1);
    $s3 = preg_replace("/(#|--\s)[^\n]+/", '', $s2);
    return new StringResult($s3, strlen($s1)); // only return len of s1
}

/**
 * search for likely spam
 */ 
function search_spam(string $all_content) : MaybeA {
    trace("spam");
    if (preg_match('/[^a-z]('.SPAM.')[^a-z$]/', $all_content, $matches)) {
        return BitFire::get_instance()->new_block(FAIL_SPAM, 'GET/POST input parameters', $matches[1][0] ?? '', 'static match');
    }
    return Maybe::$FALSE;
}

/**
 * reduce key / value with fn
 */
function trivial_reducer(callable $fn, string $key, string $value, $ignore) : MaybeA {
    if (strlen($value) > 0) {
        return $fn($key, $value);
    }
    return Maybe::$FALSE;
}

/**
 * reduce key / value with fn
 */
function generic_reducer(array $keys, array $values, $name, ?string $value) : MaybeA {
    // don't reduce these empty values
    if (strlen($value) < 4) {
        return Maybe::$FALSE;
    }

    $c1 = count($keys);
    $c2 = count($values);
    assert($c1 > 10, "unable to load keys [$c1:$c2]");
    assert($c2 > 60, "unable to load values [$c1:$c2]");

    return \BitFire\generic((string)$name, $value, $values, $keys);
}

/**
 * generic search function for keys and values
 */
function generic(string $name, string $value, array $values, array $keys) : MaybeA {
    $block = Maybe::$FALSE;

    foreach ($values as $key => $needle) {
        if (!is_int($key) || empty($needle)) { debug("key $key, need $needle"); continue; }
        if ((strpos($value, $needle) !== false || strpos($name, $needle) !== false)) { 
            return BitFire::new_block($key, $name, $value, "static match: $needle");
        }
    }

    foreach ($keys as $key => $needle) {
        $block = \BitFire\dynamic_match($key, $needle, $value, $name);
        if ($block != Maybe::$FALSE) {
            return $block;
        }
    }

    return $block;
}

/**
 * dynamic analysis
 */
function dynamic_match($key, string $needle, string $value, string $name) : MaybeA {
    assert(! empty($needle), "generic block list error: needle:[$needle] - code[$key]");
    assert(! ctype_digit($needle), "generic block list error: needle code swap");
    assert($needle[0] === "/", "generic block list error: no regex_identifier");
    static $list = null;

    if (empty($needle) == false && preg_match($needle, $value) === 1) {
        // extra special case here
        if ($key == 10101) {
            if ($list == null) { $list = file(WAF_ROOT . "cache/events.txt", FILE_IGNORE_NEW_LINES); debug("load events sz %d", count($list)); }
            if (!\ThreadFin\contains($value, $list)) {
                debug("found non event ($value)");
                return Maybe::$FALSE;
            }
        }
        return BitFire::new_block($key, $name, $value, 'dynamic match');
    }
    return Maybe::$FALSE;
}

/**
 * static analysis
 */
function static_match($key, $needle, string $value, string $name) : MaybeA {
    if (empty($needle) == false && (strpos($value, $needle) !== false || strpos($name, $needle) !== false)) { 
        return BitFire::new_block($key, $name, $value, 'static match');
    }
    return Maybe::$FALSE;
}

/**
 * take character counts and return number which are sql control chars
 */
function sum_sql_control_chars(array $counts) : int {
    return array_sum(array_intersect_key($counts, SQL_CONTROL_CHARS));
}

/**
 * update encoded data files
 * @param string $keyfile 
 * @param string $valuefile 
 * @return Effect 
 */
function update_raw(string $keyfile, string $valuefile) : Effect {
    trace("up_raw");
    $key_data = (http2("GET", APP."encode.php", array("v" => 0, "md5"=>sha1(CFG::str("encryption_key")))));
    $value_data = (http2("GET", APP."encode.php", array("v" => 1, "md5"=>sha1(CFG::str("encryption_key")))));
    return Effect::new()
        ->file(new FileMod($keyfile, $key_data["content"]??""))
        ->file(new FileMod($valuefile, $value_data["content"]??""));
}

