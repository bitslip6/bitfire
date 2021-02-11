<?php
namespace BitFire;
use function TF\map_reduce;

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
const FAIL_SQL_ORDER=14006;
const FAIL_SQL_COMMENT=14007;



const SPAM = "100%\s+free|100%\s+satisfied|50%\s+off|all\s+new|best\s+price|discount|for\s+free|fast\s+cash|for\s+just|for\s+you|for\s+only|free\s+gift|free\s+sample|give\s+away|lowest\s+price|luxury|percent+free|prize|sale|click\s+here|click\s+below|deal|meet\s+single|double\s+your|earn\s+per|make\s+money|blockchain|interested\s+in\s+the\s+latest|einkommen";

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

    protected $_reducer;

    public function __construct(\TF\CacheStorage $cache) {
        $this->_reducer = \TF\partial('\\BitFIRE\\generic_reducer', 
            $cache->load_or_cache("webkeys2", \TF\DAY, '\TF\recache_file', WAF_DIR.'cache/keys.raw'),
            $cache->load_or_cache("webvalues2", \TF\DAY, '\TF\recache_file', WAF_DIR.'cache/values.raw'));
    }

    public function inspect(\BitFire\Request $request) : \TF\Maybe {

        $block = \TF\Maybe::$FALSE;
        if (Config::enabled(CONFIG_WEB_FILTER_ENABLED)) {
            $block->doifnot('\TF\map_whilenot', $request->get, $this->_reducer, false);
            $block->doifnot('\TF\map_whilenot', $request->post, $this->_reducer, false);
            $block->doifnot('\TF\map_whilenot', $request->cookies, $this->_reducer, false);
        }

        if (Config::enabled(CONFIG_SPAM_FILTER)) {
            $block = $block->doifnot('\BitFire\search_spam', http_build_query($request->get) . http_build_query($request->post));
        }

        // no easy way to pass these three parameters, a bit ugly for now...
        if (Config::enabled(CONFIG_SQL_FILTER)) {
            $block = $block->doifnot('\BitFire\sql_filter', $request);
        }

        if (Config::enabled(CONFIG_FILE_FILTER)) {
            $block->doifnot('\\BitFire\\file_filter', $_FILES);
        }

        return $block;
    }
}

/**
 * filter for SQL injections
 */
function sql_filter(\BitFire\Request $request) : \TF\Maybe {
    foreach ($request->get as $key => $value) {
        $maybe = search_sql($key, $value, $request->get_freq[$key]);
        if (!$maybe->empty()) { return $maybe; }
    }
    foreach ($request->post as $key => $value) {
        $maybe = search_sql($key, $value, $request->post_freq[$key]);
        if (!$maybe->empty()) { return $maybe; }
    }
    return \TF\Maybe::$FALSE;
}


/**
 * check file names, extensions and content for php scripts
 */
function file_filter(array $files) : \TF\Maybe { 
    $block = \TF\Maybe::$FALSE;
    
    foreach ($files as $file) {
        $block->do('check_ext_mime', $file);
        $block->doifnot('check_php_tags', $file);
    }

    return $block;
}

/**
 * look for php tags in file uploads
 */
function check_php_tags(array $file) : \TF\Maybe {

    // check for <?php tags
    $data = file_get_contents($file["tmp_name"]);
    if (stripos($data, "<?php") !== false) {
        if (preg_match('/<\?php\s/i', $data)) {
            return \TF\Maybe::of(BitFire::new_block(FAIL_FILE_PHP_TAG, "file upload", $file["name"], ".php", BLOCK_SHORT));
        }
    }
    // check for phar polyglots (tar)
    if (substr($data, -4) === "GBMB") {
        return \TF\Maybe::of(BitFire::new_block(FAIL_FILE_POLYGLOT, "file upload", $file["name"], "phar polyglot", BLOCK_SHORT));
    }

    return \TF\Maybe::$FALSE;
}

function check_ext_mime(array $file) : \TF\Maybe {
     // check file extensions...
    $info = pathinfo($file["tmp_name"]);
    if (\TF\ends_with(strtolower($file["name"]), "php") ||
        in_array(strtolower($info['extension']), array("php", "phtml", "php3", "php4", "php5", "php6", "php7", "php8", "phar"))) {
        return \TF\Maybe::of(BitFire::new_block(FAIL_FILE_PHP_EXT, "file upload", $file["name"], ".php", BLOCK_SHORT));
    }
        
    // check mime types
    $ctx = finfo_open(FILEINFO_MIME_TYPE | FILEINFO_CONTINUE);
    $info = finfo_file($ctx, $file["tmp_name"]);
    if (stripos($info, "php") !== false || stripos($file["type"], "php") !== false) {
        return \TF\Maybe::of(BitFire::new_block(FAIL_FILE_PHP_MIME, "file upload", $file["name"], ".php", BLOCK_SHORT));
    }

    return \TF\Maybe::$FALSE;
}


/**
 * find sql injection for short strings
 */
function search_short_sql(string $name, string $value) : \TF\Maybe {
    if (preg_match('/\s*(or|and)\s+(\d+|true|false|\'\w+\'|)\s*!?=(\d+|true|false|\'\w+\'|)/sm', $value)) {
        return BitFire::get_instance()->new_block(FAIL_SQL_OR, $name, $value, ERR_SQL_INJECT, BLOCK_NONE);
    }
    if (preg_match('/\'?.*?(or|and|where|order\s+by)\s+[^\s]+(;|--|#|\'|\/\*)?/sm', $value)) {
        return BitFire::get_instance()->new_block(FAIL_SQL_ORDER, $name, $value, ERR_SQL_INJECT, BLOCK_NONE);
    }
    if (preg_match('/select\s+(all|distinct|distinctrow|high_priority|straight_join|sql_small_result|sql_big_result|sql_buffer_result|sql_no_cache|sql_calc_found_rows)*\s*[^\s]+\s+(into|from)/sm', $value)) {
        return BitFire::get_instance()->new_block(FAIL_SQL_ORDER, $name, $value, ERR_SQL_INJECT, BLOCK_NONE);
    }

    return \TF\Maybe::$FALSE;
}


/**
 * find sql looking things...
 * this could be way more functional, but it would be slower, choices...
 */
function search_sql(string $name, string $value, array $counts) : \TF\Maybe {

    // block super basic
    if (strpos($value, "from", strpos($value, "select", strpos($value, "union")))) {
        return BitFire::new_block(FAIL_SQL_UNION, $name, $value, 'sql identified', 0);
    }
    if (preg_match('/(select\s+[\@\*])/sm', $value, $matches) || preg_match('/(select\s+.*?from)/sm', $value, $matches)) {
        return BitFire::new_block(FAIL_SQL_SELECT, $name, $value, ERR_SQL_INJECT, BLOCK_NONE);
    }

    // block short sql,
    $total_control = sum_sql_control_chars($counts);
    if ($total_control <= 0) { return search_short_sql($name, $value); }

    $stripped_comments = strip_comments($value);
        
    // look for the short injection types
    $block = search_short_sql($name, $stripped_comments->value);
    $block->doifnot('\BitFire\check_removed_sql', $stripped_comments, $total_control, $name, $value);

    return $block;
}

/**
 * check if removed sql was found
 */
function check_removed_sql(StringResult $stripped_comments, int $total_control, string $name, string $value) : \TF\Maybe {
 
    $sql_removed = str_replace(SQL_WORDS, "", $stripped_comments->value);
    $sql_removed_len = strlen($sql_removed);

    // if we have enough sql like syntax
    if ($sql_removed_len + MIN_SQL_CHARS <= $stripped_comments->len + $total_control) {
        // ugly but fast, remove temp variables ...
        $result = strip_strings($sql_removed);

        // we removed at least half of the input, look like sql to me..
        if ($result->len < ($stripped_comments->len / 2) || $result->len < ($stripped_comments->len - 20)) {
            return BitFire::new_block(FAIL_SQL_FOUND, $name, $value, 'sql identified', 0);
        } else if ($result->len < 15) {
            return search_short_sql($name, $result->value);
        }
    }
    
    return \TF\Maybe::$FALSE;
}

/**
 * remove sql strings 
 */
function strip_strings(string $value) : StringResult {
    $stripped = map_reduce(array("/\s+/sm" => ' ', "/^[^']+/sm" => '', "/'[^']+$/sm" => '', "/'[^']*'/sm" => '', "/as\s\w+/sm" => ''), function($search, $replace, $carry) {
        return preg_replace($search, $replace, $carry);
    }, $value);
    return new StringResult($stripped, strlen($stripped));
}

/**
 * remove sql comments 
 */
function strip_comments(string $value) {
    $s1 = str_replace(SQL_IMPORTANT_CHARS, " ", $value);
    $s2 = preg_replace("/\/\*.*?\*\//sm", '', $s1);
    $s3 = preg_replace("/(#|--\s)[^\n]+/", '', $s2);
    return new StringResult($s3, strlen($s1)); // only return len of s1
}

/**
 * search for likely spam
 */ 
function search_spam(string $all_content) : \TF\Maybe {
    $fail = (preg_match('/[^a-z]('.SPAM.')[^a-z$]/', $all_content, $matches)) ? FAIL_SPAM : FAIL_NOT;
    return BitFire::get_instance()->new_block($fail, 'GET/POST input parameters', $matches[1][0] ?? '', 'static match');
}

/**
 * reduce key / value with fn
 */
function trivial_reducer(callable $fn, string $key, string $value, $ignore) : \TF\Maybe {
    if (strlen($value) > 0) {
        return $fn($key, $value);
    }
    return \TF\Maybe::$FALSE;
}

/**
 * reduce key / value with fn
 */
function generic_reducer(array $keys, array $values, string $name, string $value) : \TF\Maybe {
    if (strlen($value) > 0) {
        return \BitFire\generic($name, $value, $values, $keys);
    }
    return \TF\Maybe::$FALSE;
}

/**
 * generic search function for keys and values
 */
function generic(string $name, string $value, array $values, array $keys) : \TF\Maybe {
    $block = \TF\Maybe::$FALSE;

    foreach ($values as $key => $needle) {
        $block->doifnot('\BitFire\static_match', $key, $needle, $value, $name);
    }

    foreach ($keys as $key => $needle) {
        $block->doifnot('\BitFire\dynamic_match', $key, $needle, $value, $name);
    }
    
    return $block;
}

/**
 * dynamic analysis
 */
function dynamic_match(int $key, string $needle, string $value, string $name) : \TF\Maybe {
    if (preg_match($needle, $value) === 1) {
        return BitFire::new_block($key, $name, $value, 'static match');
    }
    return \TF\Maybe::$FALSE;
}

/**
 * static analysis
 */
function static_match(int $key, string $needle, string $value, string $name) : \TF\Maybe {
    if (empty($needle) == false && (strpos($value, $needle) !== false || strpos($name, $needle) !== false)) { 
        return BitFire::new_block($key, $name, $value, 'static match');
    }
    return \TF\Maybe::$FALSE;
}

/**
 * take character counts and return number which are sql control chars
 */
function sum_sql_control_chars(array $counts) : int {
    return array_sum(array_intersect_key($counts, SQL_CONTROL_CHARS));
}

