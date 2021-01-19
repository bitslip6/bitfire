<?php
namespace BitFire;

use finfo;
use TF\CacheStorage;

if (defined("BIT_FILTER")) { return; }
define ("BIT_FILTER", 1);

include_once("english.php");
const MIN_SQL_CHARS=8;

const SQL_WORDS = array('add', 'all', 'alter', 'ascii', 'between', 'benchmark', 'case', 'contains', 'concat',
'distinct', 'drop', 'delay', 'except', 'exists', 'exec', 'from', 'lower', 'upper', 'outer', 'order', 'null', 
'md5', 'hex', 'like', 'true', 'false', 'function', 'or', 'and', 'left', 'join', 'group', 'having', 'right', 'substring', 'select', 'pg_sleep', 'sleep',
'update', '(', ')', ',', '=', '!', 'insert', 'union', 'while', 'where', 'waitfor', 'is null');
const SQL_CONTROL_CHARS = array(35 => 1, 39 => 1, 40 => 1, 41 => 1, 44 => 1, 45 => 1, 61 => 1);

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

class WebFilter {

    protected $_search_sql;
    protected $_reducer;

    public function __construct(\TF\CacheStorage $cache) {
        
        $values = $cache->load_or_cache("webvalues2", 3600*24, '\TF\recache_file', WAF_DIR.'cache/values.raw');
        $keys = $cache->load_or_cache("webkeys2", 3600*24, '\TF\recache_file', WAF_DIR.'cache/keys.raw');

        //\TF\dbg($values);
        $this->_reducer = \TF\partial('\\BitFIRE\\generic_reducer', $keys, $values);
        $this->_search_sql = \TF\partial('\\BitFIRE\\trivial_reducer', '\\BitFire\\search_sql');
    }

    public function inspect(array $request) : \TF\Maybe {

        // TODO: make some helper functions...
        $block = \TF\Maybe::of(false);
        if (Config::enabled(CONFIG_WEB_FILTER_ENABLED)) {
            // TODO: refactor to take block as a Maybe....
            $block->doifnot('\TF\map_whilenot', $request['GET'], $this->_reducer, false);
            $block->doifnot('\TF\map_whilenot', $request['POST'], $this->_reducer, false);
            $block->doifnot('\TF\map_whilenot', $request['COOKIE'], $this->_reducer, false);
        }

        if (Config::enabled(CONFIG_SPAM_FILTER)) {
            $block = $block->doifnot('BitFire\search_spam', $request['FULL']);
        }

        // no easy way to pass these three parameters, a bit ugly for now...t re
        if (Config::enabled(CONFIG_SQL_FILTER)) {
            foreach ($request['GET'] as $key => $value) {
                $block->doifnot('\BitFire\search_sql', $key, $value, $request['GETC'][$key]);
            }
            foreach ($request['POST'] as $key => $value) {
                $block->doifnot('\BitFire\search_sql', $key, $value, $request['POSTC'][$key]);
            }
        }

        if (Config::enabled(CONFIG_FILE_FILTER)) {
            if (isset($_FILES) && count($_FILES) > 0) {
                $block->doifnot('\\BitFire\\file_filter', $_FILES);
            }
        }

        return $block;
    }
}


/**
 * check file names, extensions and content for php scripts
 * NOT PURE
 */
function file_filter(array $files) : \TF\Maybe {
    foreach ($files as $file) {
        // check file extensions...
        $info = pathinfo($file["tmp_name"]);
        if (\TF\endsWith(strtolower($file["name"]), "php") ||
            in_array(strtolower($info['extension']), array("php", "phtml", "php3", "php4", "php5", "php6", "php7", "php8", "phar"))) {
            return \TF\Maybe::of(BitFire::new_block(FAIL_FILE_UPLOAD, "file upload", $file["name"], ".php", BLOCK_SHORT));
        }
            
        // check mime types
        $ctx = finfo_open(FILEINFO_MIME_TYPE | FILEINFO_CONTINUE);
        $info = finfo_file($ctx, $file["tmp_name"]);
        if (stripos($info, "php") !== false || stripos($file["type"], "php") !== false) {
            return \TF\Maybe::of(BitFire::new_block(FAIL_FILE_UPLOAD, "file upload", $file["name"], ".php", BLOCK_SHORT));
        }

        // check for <?php tags
        $data = file_get_contents($file["tmp_name"]);
        if (stripos($data, "<?php") !== false) {
            if (preg_match('/<\?php\s/i', $data)) {
                return \TF\Maybe::of(BitFire::new_block(FAIL_FILE_UPLOAD, "file upload", $file["name"], ".php", BLOCK_SHORT));
            }
        }
        // check for phar polyglots (tar)
        if (substr($data, -4) === "GBMB") {
            return \TF\Maybe::of(BitFire::new_block(FAIL_FILE_UPLOAD, "file upload", $file["name"], ".php", BLOCK_SHORT));
        }
    }
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

    return \TF\Maybe::of(false);
}


/**
 * find sql looking things...
 * this could be way more functional, but it would be slower, choices...
 */
function search_sql(string $name, string $value, array $counts) : \TF\Maybe {
    //echo "[$name] = ($value) :". var_export($counts);


    $total_control = sum_sql_control_chars($counts);
    if ($total_control > 0) {
        if (preg_match('/(select\s+[\@\*])/sm', $value, $matches) || preg_match('/(select\s+.*?from)/sm', $value, $matches)) {
            return BitFire::get_instance()->new_block(FAIL_SQL_SELECT, $name, $value, ERR_SQL_INJECT, BLOCK_NONE);
        }

        // remove sql stuff
        $replace_space = str_replace(array("\n", "\r", "  ", "\t", '(', ')'), " ", $value);
        $space_corrected_len = strlen($replace_space);
        $removed_comments_1 = preg_replace("/\/\*.*?\*\//sm", '', $replace_space, 256, $count);
        $removed_comments_2 = preg_replace("/(#|--\s)[^\n]+/", '', $removed_comments_1, 256, $count);
        $lower_len = strlen($removed_comments_2);
        
        // look for the short injection types
        $block = search_short_sql($name, $removed_comments_2);
        if(!$block->empty()) { return $block; }

        $sql_removed = str_replace(SQL_WORDS, "", $removed_comments_2);
        $sql_removed_len = strlen($sql_removed);

        // if we have enough sql like syntax
        if ($sql_removed_len + MIN_SQL_CHARS <= $space_corrected_len + $total_control) {
            // ugly but fast, remove temp variables ...
            $removed_space = preg_replace("/\s+/sm", ' ', $sql_removed);
            $removed_leading_text = preg_replace("/^[^']+'/sm", '', $removed_space);
            $removed_trailing_text = preg_replace("/'[^']+$/sm", '', $removed_leading_text);
            $removed_inner_strings = preg_replace("/'[^']*'/sm", "", $removed_trailing_text);
            $removed_table_alias = preg_replace("/as\s+\w+/sm", "", $removed_inner_strings);
            $new_len = strlen($removed_table_alias);
            // we removed at least half of the input, look like sql to me..
            if ($new_len < ($space_corrected_len / 2) || $new_len < ($space_corrected_len - 20)) {
                return BitFire::new_block(FAIL_SQL_FOUND, $name, $value, 'sql identified', 0);
            } else if ($new_len < 15) {
                return search_short_sql($name, $removed_table_alias);
            }
        }
    }
    else {
        $block = search_short_sql($name, $value);
    }
    if(!$block->empty()) { return $block; }
    // union select?

    if (preg_match("/(union|;)[\sal(]*select/sm", $value)) {
        return BitFire::new_block(FAIL_SQL_UNION, $name, $value, 'sql identified', 0);
    }

    return \TF\Maybe::of(false);
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
    return \TF\Maybe::of(false);
}

/**
 * reduce key / value with fn
 */
function generic_reducer(array $keys, array $values, string $key, string $value, $ignore) : \TF\Maybe {
    if (strlen($value) > 0) {
        return \BitFire\generic($key, $value, $values, $keys);
    }
    return \TF\Maybe::of(false);
}

function generic(string $name, string $value, array $values, array $keys) : \TF\Maybe {
    foreach ($values as $a => $b) {
        if (empty($b)) { continue; }
        if (strpos($value, $b) !== false || strpos($name, $b) !== false) {
            $maybe_block = BitFire::get_instance()->new_block($a, $name, $value, 'static match');
            if (!$maybe_block->empty()) {
                return $maybe_block;
            }
        }
    }

    foreach ($keys as $a => $b) {
        if (preg_match($b, $value) === 1) {
            $maybe_block = BitFire::get_instance()->new_block($a, $name, $value, 'dynamic match');
            if (!$maybe_block->empty()) {
                return $maybe_block;
            }
        }
    }
    
    return \TF\Maybe::of(false);
}

function sum_sql_control_chars(array $counts) : int {
    return array_sum(array_intersect_key($counts, SQL_CONTROL_CHARS));
}

