#!/opt/homebrew/bin/php
<?php declare(strict_types=1);
namespace TinyTest {

use Throwable;

const VER = "10";
const ERR_OUT = "/tmp/tinytest";
const COVERAGE = 'c'; const TEST_FN = 't'; const SHOW_COVERAGE = 'r'; const ASSERT_CNT = 'assert_count';
define('YEARAGO', time() - 86400 * 365);
opcache_reset();


/** BEGIN USER EDITABLE FUNCTIONS, override in user_defined.php and prefix with "user_" */
// test if a file is a test file, this should match your test filename format
// $options command line options
// $filename is the file to test
function is_test_file(string $filename, array $options = null) : bool {
    return (starts_with($filename, "test_") && ends_with($filename, "php"));
}

// test if a function is a valid test function also limits testing to a single function
// $funcname - function name to test
// $options - command line options
function is_test_function(string $funcname, array $options) : bool {
    if (isset($options[TEST_FN])) {
        return $funcname == $options[TEST_FN];
    }
    return (substr($funcname, 0, 5) === "test_" ||
            substr($funcname, 0, 3) === "it_" ||
            substr($funcname, 0, 7) === "should_");
}

// format test success
function format_test_success(array $test_data, array $options, float $time) : string {
    $out = ($test_data['status'] == "OK") ? GREEN : YELLOW;
    if (little_quiet($options)) {
        $out .= sprintf("%-3s%s in %s", $test_data['status'], NORML, number_format($time, 5));
    } else if (very_quiet($options)) {
        $out .= "." . NORML;
    }
    return $out . display_test_output($test_data['result'], $options);
}

// display the test returned string output
function display_test_output(string $result = null, array $options) {
    return ($result != null && not_quiet($options)) ?
        GREY . substr(str_replace("\n", "\n  -> ", "\n".rtrim($result)), 1) . "\n" . NORML:
        "";
}

// format the test running. only return data if 0 or 1 -q options
function format_test_run(string $test_name, array $test_data, array $options) : string {
    $tmp = explode(DIRECTORY_SEPARATOR, $test_data['file']);
    $file = end($tmp);
    $file = substr($file, -32);
    return (little_quiet($options)) ? sprintf("\n%s%-32s :%s%-16s/%s%-42s%s ", CYAN, $file, GREY, $test_data['type'], BLUE_BR, $test_name, NORML) : '';
}

// format test failures , simplify?
function format_assertion_error(array $test_data, array $options, float $time) {
    $out = "";
    $ex = $test_data['error'];
    if (little_quiet($options) && $ex !== null) {
        $out .= sprintf("%s%-3s%s in %s\n", RED, "err", NORML, number_format($time, 5));
        $out .= YELLOW . "  " . $ex->getFile() . NORML . ":" . $ex->getLine() . "";
    }
    if (not_quiet($options)) {
        $out .= LRED . "  " . $ex->getMessage() . NORML . "" ;
    }
    if (very_quiet($options)) { 
        $out = "E";
    }
    if (full_quiet($options)) {
        $out = "";
    } 
    if (isset($options['v'])) {
        $out .= GREY . $ex->getTraceAsString(). NORML . "";
    }
    return $out . display_test_output($test_data['result'], $options);
}
/** END USER EDITABLE FUNCTIONS */
// assertion functions located in assertion.php



/** internal helper functions */
// TODO bind options array to global option helpers...
function dbg($x) { print_r($x); die(); }
function partial(callable $fn, ...$args) : callable { return function(...$x) use ($fn, $args) { return $fn(...array_merge($args, $x)); }; }
function not_quiet(array $options) : bool { return $options['q'] == 0; }
function little_quiet(array $options) : bool { return $options['q'] <= 1; }
function very_quiet(array $options) : bool { return $options['q'] == 2; }
function full_quiet(array $options) : bool { return $options['q'] >= 3; }
function verbose(array $options) : bool { return isset($options['v']); }
function count_assertion() { $GLOBALS[ASSERT_CNT]++; }
function count_assertion_pass() { count_assertion(); $GLOBALS['assert_pass_count']++; }
function count_assertion_fail() { count_assertion(); $GLOBALS['assert_fail_count']++; }
function panic_if(bool $result, string $msg) {if ($result) { die($msg); }}
function warn_ifnot(bool $result, string $msg) {if (!$result) { printf("%s%s%s\n", YELLOW, $msg, NORML); }}
function between(int $data, int $min, int $max) { return $data >= $min && $data <= $max; }
function do_for_all(array $data, callable $fn) { foreach ($data as $item) { $fn($item); } }
function do_for_allkey(array $data, callable $fn) { foreach ($data as $key => $item) { $fn($key); } }
function do_for_all_key_value(array $data, callable $fn) { foreach ($data as $key => $item) { $fn($key, $item); } }
function do_for_all_key_value_recursive(array $data, callable $fn) { foreach ($data as $key => $items) { foreach ($items as $item) { $fn($key, $item); } } }
function array_map_assoc(callable $f, array $a) { return array_column(array_map($f, array_keys($a), $a), 1, 0); }
function if_then_do($testfn, $action, $optionals = null) : callable { return function($argument) use ($testfn, $action, $optionals) { if ($argument && $testfn($argument, $optionals)) { $action($argument); }}; }
function is_equal_reduced($value) : callable { return function($initial, $argument) use ($value) { return ($initial || $argument === $value); }; }
function is_contain($value) : callable { return function($argument) use ($value) { return (strstr($argument, $value) !== false); }; }
function starts_with(string $haystack, string $needle) { return (substr($haystack, 0, strlen($needle)) === $needle); } 
function ends_with(string $haystack, string $needle) { return (substr($haystack, -strlen($needle)) === $needle); } 
function say($color = '\033[39m', $prefix = "") : callable { return function($line) use ($color, $prefix) : string { return (strlen($line) > 0) ? "{$color}{$prefix}{$line}".NORML."\n" : ""; }; } 
function last_element(array $items, $default = "") { return (count($items) > 0) ? array_slice($items, -1, 1)[0] : $default; }
function nth_element(array $items, int $index, $default = "") { return (count($items) > 0) ? array_slice($items, $index, 1)[0] : $default; }
function line_at_a_time(string $filename) : iterable { $r = fopen($filename, 'r'); $i=0; while (($line = fgets($r)) !== false) { $i++; yield "line $i" => trim($line); } }
function get_mtime(string $filename) : string { $st = stat($filename); $m = $st['mtime']; return strftime(($m < YEARAGO) ? "%h %y" : "%h %d", $m); }
function all_match(array $data, callable $fn, bool $match = true) : bool { foreach($data as $elm) { if ($fn($elm) !== $match) { return !$match; } } return $match; }
function any_match(array $data, callable $fn) : bool { return all_match($data, $fn, false); }
function fatals() { echo "\n"; if (file_exists(ERR_OUT)) { fwrite(STDERR, file_get_contents(ERR_OUT)); } }


// initialize the system
function init(array $options) : array {
    // global state (yuck)
    $GLOBALS['m0'] = microtime(true);
    $GLOBALS[ASSERT_CNT] = $GLOBALS['assert_pass_count'] = $GLOBALS['assert_fail_count'] = 0;

    // define console colors
    define("ESC", "\033");
    $d = array("RED"=>0, "LRED"=>0, "CYAN"=>0, "GREEN"=>0, "BLUE"=>0, "GREY"=>0, "YELLOW"=>0, "UNDERLINE"=>0, "NORML" => 0); 
    if (!isset($options['m'])) { $d = array("RED"=>31, "LRED"=>91, "CYAN"=>36, "GREEN"=>32, "BLUE"=>34, "GREY"=>90, "YELLOW"=>33, "UNDERLINE"=>"4:3", "NORML" => 0); }
    do_for_allkey($d, function($name) use ($d) { define($name, ESC . "[".$d[$name]."m"); define("{$name}_BR", ESC . "[".$d[$name].";1m"); });

    // program inffails o
    echo __FILE__ . CYAN . " Ver " . VER . NORML . "\n";

    // include test assertions
    require __DIR__ . "/assertions.php";
    if (file_exists("user_defined.php")) { include_once "user_defined.php"; }

    // usage help
    if ((!isset($options['d']) && !isset($options['f'])) || isset($options['h']) || isset($options['?'])) { die(show_usage()); }
    // set assertion state
    ini_set("assert.exception", "1");

    // squelch error reporting if requested
    error_reporting($options['s'] ? 0 : E_ALL);
    @unlink(ERR_OUT);
    ini_set("error_log", ERR_OUT);
    gc_enable();

    // trying to read error log fails in shutdown fails if we are monitoring code coverage...
    if (!$options[COVERAGE]) { register_shutdown_function("TinyTest\\fatals"); }
    else { ini_set('memory_limit','1024M'); }
    
    return $options;
}

// load a single unit test
function load_file(string $file, array $options) : void {
    assert(is_file($file), "test file [$file] does not exist");
    if (verbose($options)) {
        printf("loading test file: [%s%-45s%s]", CYAN, $file, NORML);
    }
    require_once "$file";
    if (verbose($options)) {
        echo GREEN_BR . "  OK\n" . NORML;
    }
}

// load all unit tests in a directory
function load_dir(string $dir, array $options) {
    assert(is_dir($dir), "[$dir] is not a directory");
    $action = function($item) use ($dir, $options) { load_file($dir . DIRECTORY_SEPARATOR . $item, $options); };
    $is_test_file_fn = (function_exists("user_is_test_file")) ? "user_is_test_file" : "TinyTest\is_test_file";
    do_for_all(scandir($dir), if_then_do($is_test_file_fn, $action, $options));
}

// check if this test should be excluded, returns false if test should run
function is_excluded_test(array $test_data, array $options) {
    //print_r($options);
    if (isset($options['i']) && count($options['i']) > 0) { return !in_array($test_data['type'], $options['i']); }
    if (isset($options['e']) && count($options['e']) > 0) { return in_array($test_data['type'], $options['e']); }
    return false; 
}

// read the test annotations, returns an array with all annotations
function read_test_annotations(string $testname) : array {
    $refFunc = new \ReflectionFunction($testname);
    $result = array('exception' => array(), 'test' => $testname, 'type' => 'standard', 'file' => $refFunc->getFileName(), 'line' => $refFunc->getStartLine(), 'error' => '', 'phperror' => array());
    $result['mtime'] = get_mtime($result['file']);
    $doc = $refFunc->getDocComment();
    if ($doc === false) { return $result; }

    $docs = explode("\n", $doc);
    array_walk($docs, function ($line) use (&$result) {
        $last = last_element(explode(" ", $line));
        if (preg_match("/\@(\w+)(.*)/", $line, $matches)) {
            if ($matches[1] === "exception") {
                array_push($result['exception'], $last);
            } else if ($matches[1] === "phperror") {
                array_push($result['phperror'], $matches[2]);
            } else {
                $result[$matches[1]] = $last;
            }
        }
    });

    return $result;
}

// show the test runner usage
function show_usage() {
    warn_ifnot(ini_get("zend.assertions") == 1, "zend.assertions are disabled. set zend.assertions in " . php_ini_loaded_file());
    echo " -d <directory> " . GREY . "load all tests in directory\n" . NORML;
    echo " -f <file>      " . GREY . "load all tests in file\n". NORML;
    echo " -t <test_name> " . GREY . "run just the test named test_name\n" . NORML;
    echo " -i <test_type> " . GREY . "only include tests of type <test_type> support multiple -i\n" . NORML;
    echo " -e <test_type> " . GREY . "exclude tests of type <test_type> support multiple -e\n" . NORML;
    echo " -b <bootstrap> " . GREY . "include a bootstrap file before running tests\n" . NORML;
    echo " -a " . GREY . "            auto load a bootstrap file in test directory\n" . NORML;
    echo " -c " . GREY . "            include code coverage information (generate lcov.info)\n" . NORML;
    echo " -q " . GREY . "            hide test console output (up to 3x -q -q -q)\n" . NORML;
    echo " -m " . GREY . "            set monochrome console output\n" . NORML;
    echo " -v " . GREY . "            set verboise output (stack traces)\n" . NORML;
    echo " -s " . GREY . "            squelch php error reporting\n" . NORML;
    echo " -r " . GREY . "            display code coverage totals (assumes -c)\n" . NORML;
    echo " -p " . GREY . "            save xhprof profiling tideways or xhprof profilers\n" . NORML;
    echo " -k " . GREY . "            save callgrind profiling data for cachegrind profilers\n" . NORML;
    echo " -n " . GREY . "            skip profile data for functions with low overhead\n" . NORML;
    echo " -w " . GREY . "            use wall time for callgrind output (default cpu)\n" . NORML;
    echo " -l " . GREY . "            just list tests, don't run\n" . NORML;
}


/** BEGIN CODE COVERAGE FUNCTIONS */
// merge the oplog after every test adding all new counts to the overall count
function combine_oplog(array $cov, array $newdata, array $options) : array {
    
    // remove unit test files from oplog data
    $remove_element = function($item) use (&$newdata) { unset($newdata[$item]); };
    do_for_allkey($newdata, if_then_do(is_contain($options['d'] ?? $options['f']), $remove_element));

    // a bit ugly...
    foreach($newdata as $file => $lines) {
        if (isset($cov[$file])) {
            foreach($lines as $line => $cnt1) {
                $cov[$file][$line] = $cnt1 + ($cov[$file][$line] ?? 0);
            }
        }
        else {
            $cov[$file] = $lines;
        }
    }

    return $cov;
}

// return true only if token is valid with lineno, and is not whitespace or other crap
function is_important_token($token) : bool {
    return (!is_array($token) || in_array($token[0], array(379, 382, 378, 323, 377, 268))) ? false : true;
}

// return a new function definition
function new_line_definition(int $lineno, string $name, string $type, int $end) : array {
    return array("start" => $lineno, "type" => $type, "end" => $end, "name" => $name, "hit" => HIT_MISS);
} 

// find the function, branch or statement at lineno for source_listing
function find_index_lineno_between(array $source_listing, int $lineno, string $type) : int {
    //print_r($source_listing);
    for($i=0,$m=max(array_keys($source_listing)); $i<$m; $i++) {
        if (!isset($source_listing[$i])) { continue; } // skip empty items

        //echo "BETWEEN [$lineno] $type\n";
        //if ($type == "da") { print "is between: ". $source_listing[$i]['start'] . "\n"; }
        if (between($lineno, $source_listing[$i]['start'], $source_listing[$i]['end'])) {
           //echo "HEY FOUND [$i] $type\n";
           //print_r($source_listing[$i]);
           return $i;
        }
        if ($type == "da") {
            //echo "check $lineno {$source_listing[$i]['start']} @ {$source_listing[$i]['name']} $i\n";
        }
    }
    return -1;
}

// main lcov file format output
// TODO: get which branch was taken in oplog output and update branch path here
// TODO: replace first mt_rand with an actual internal branch number.  maybe a counter for function definition number?
function format_output(string $type, array $def, int $hit) {
    switch ($type) {
        case "fn":
            return "FNDA:{$hit},{$def['name']}\n";
        case "da":
            return "DA:{$def['start']},$hit\n";
        case "brda":
            return "BRDA:{$def['start']},".mt_rand(100000,900000).",".mt_rand(100000,900000).",$hit\n";
    }
}

// combine the source file mappings, with the covered lines and produce an lcov output
function output_lcov(string $file, array $covered_lines, array $src_mapping, bool $showcoverage = false) {
    // loop over all covered lines and update hit counts
    do_for_all_key_value($covered_lines, function($lineno, $cnt) use (&$src_mapping, $file) {
        // loop over all covered line types
        do_for_allkey($src_mapping, function($src_type) use (&$index, &$src_mapping, $lineno, &$type, $cnt) {
            // see if this line is one of our line types
            //echo "check $lineno [$src_type]\n";
            $index = find_index_lineno_between($src_mapping[$src_type], $lineno, $src_type);
            //echo "find [$src_type] [$lineno] - $index\n";
            // update the hit count for this line
            if ($index >= 0) { 
                $src_mapping[$src_type][$index]["hit"] = min($src_mapping[$src_type][$index]["hit"], $cnt);
            }
        });
    });

    $hits = array("fn" => 0, "brda" => 0, "da" => 0);
    $outputs = array("fnprefix" => "", "fn" => "", "brda" => "", "da" => "");
    // loop over all source lines with updated hit counts and product the output format
    do_for_all_key_value_recursive($src_mapping, function($type, $def) use (&$hits, &$outputs) {
        $hit = ($def['hit'] === HIT_MISS) ? 0 : $def['hit'];
        if ($hit > 0) { $hits[$type]++; }
        $outputs[$type] .= format_output($type, $def, $hit);
        // special case since functions have 2 outputs...
        if ($type == "fn") {
            $outputs["fnprefix"] .= "FN:{$def['start']},{$def['name']}\n";
        }
    });

    // update the lcov coverage totals
    $outputs['fn'] .= "FNF:".count($src_mapping['fn'])."\nFNH:{$hits['fn']}\n";
    $outputs['brda'] .= "BRF:".count($src_mapping['brda'])."\nBRH:{$hits['brda']}\n";
    $outputs['da'] .= "LF:".count($src_mapping['da'])."\nLH:{$hits['da']}\n";

    // output to the console the coverage totals
    if ($showcoverage) {
        echo "$file " . GREEN . round((intval($hits['da']) / count($src_mapping['da'])) * 100) . " % " . NORML . "\n";
        echo "function coverage: {$hits['fn']}/".count($src_mapping['fn'])."\n";
        echo "conditional coverage: {$hits['brda']}/".count($src_mapping['brda'])."\n";
        echo "statement coverage: {$hits['da']}/".count($src_mapping['da'])."\n";
    }
    // return the combined outputs
    return array_reduce($outputs, function($result, $item) { return $result . $item; }, "SF:$file\n") . "end_of_record\n";
}

// a bit ugly, consider some state machine abstraction, may require 2 passes...???
// take a mapping of file => array(tokens) and create a source mapping for function, branch, statement 
function make_source_map_from_tokens(array $tokens) {
    $funcs = get_defined_functions(false);
    $lcov = array();
    foreach ($tokens as $file => $tokens) {
        $lcov[$file] = array("fn" => array(), "da" => array(), "brda" => array());
        $fndef = new_line_definition(0, '', 'fn', 999999);
        $lastname = "";
        foreach ($tokens as $token) {
            // skip whitespace and other tokens we don't care about, as well as non tokenizable stuff
            if (!is_important_token($token)) { 
                // not whitespace, and function name is empty, then we havre anon function... ugly hack
                if ($token[0] != 382 && $fndef['name'] == "" && strlen($lastname) > 0) {
                    $fndef['name'] = $lastname;
                }
                continue;
            }

            $nm = token_name($token[0]);
            $src = $token[1];
            $lineno = $token[2];

            if ($nm == "T_STRING" && $fndef['name'] == "" && $src != "strict_types") {
                $fndef = new_line_definition($lineno, $src, "fn", 999999);
                array_push($lcov[$file]["fn"], $fndef);
            }
            else if ($nm == "T_FUNCTION") {
                // a new function.  end the previous function
                if ($fndef['name'] != '') { 
                    // update the end of the last function to this line -1, ugly hack
                    $lcov[$file]["fn"][count($lcov[$file]["fn"])-1]['end'] = $lineno-1;
                    $lastname = $fndef['name'];
                    $fndef['name'] = "";
                }
            }
            // handle user and system function calls
            else if ($nm == "T_STRING") {
                if (in_array($token[1], $funcs['internal']) || in_array($token[1], $funcs['user'])) {
                    array_push($lcov[$file]["da"], new_line_definition($lineno, "S", "da", $lineno));
                }
            }
            else if ($nm == "T_IF") {
                array_push($lcov[$file]["brda"], new_line_definition($lineno, $src, "brda", $lineno));
            }
            else { 
                array_push($lcov[$file]["da"], new_line_definition($lineno, "E", "da", $lineno));
            }
        }
        // add the last function definition
        //$fndef['end'] = 999999;
        //array_push($lcov[$file]["fn"], $fndef);

        // remove statement lines we have multiple tokens for
        $keep_map = array();
        $lcov[$file]['da'] = array_filter($lcov[$file]['da'], function ($element) use (&$keep_map) {
            if (!isset($keep_map[$element['start']])) {
                $keep_map[$element['start']] = true;
                return true;
            }
            return false;
        });
    }

    return $lcov;
}
 
function keep_fn($options) : callable {
    $is_test_function_fn = function_exists("user_is_test_function") ? "user_is_test_function" : "TinyTest\\is_test_function";
    return function($fn_name) use($options, $is_test_function_fn) : bool {
        return $is_test_function_fn($fn_name, $options);
    };
}

// take coverage data from oplog and convert to lcov file format
function coverage_to_lcov(array $coverage, array $options) {

    // read in all source files and parse the php tokens
    $tokens = array();
    do_for_allkey($coverage, function($file) use (&$tokens) {
        $tokens[$file] = token_get_all(file_get_contents($file));
    });

    // convert the tokens to a source map
    $src_map = make_source_map_from_tokens($tokens);
    $res = "";
    // combine the coverage output with the source map and produce an lcov output
    foreach($src_map as $file => $mapping) {
        $res .= output_lcov($file, $coverage[$file], $mapping, $options[SHOW_COVERAGE]);
    } 

    return $res;
}
/** END CODE COVERAGE FUNCTIONS */

define("HIT_MISS", 999999999);
// internal assert errors.  handle getting correct file and line number.  formatting for assertion error
// todo: add user override callback for assertion error formatting
class TestError extends \Error {
    public $test_data;
    //public function __construct(string $message, $actual, $expected, \Exception $ex = null) {
    public function __construct(string $message, $actual, $expected, \Throwable $ex = null) {
        $formatted_msg = sprintf("%sexpected [%s%s%s] got [%s%s%s] \"%s%s%s\"\n", NORML, GREEN, $expected, NORML, YELLOW, $actual, NORML, RED, $message, NORML);

        parent::__construct($formatted_msg, 0, $ex);
        if ($ex != null) {
            $this->line = $ex->getLine();
            $this->file = $ex->getFile();
        } else {
            $bt = nth_element(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3), 2);
            $this->line = $bt['line'];
            $this->file = $bt['file'];
            //$this->file = "BTF:".$bt['file'] . " L:".$bt['line'];
        }
    }
}


// coerce get_opt to something we like better...
function parse_options(array $options) : array {
    // count quiet setting
    $q = $options['q'] ?? array();
    $options['q'] = is_array($q) ? count($q) : 1;

    // print_r($options);
    // force inclusion to array type
    if (isset($options['i'])) { $options['i'] = is_array($options['i']) ? $options['i'] : array($options['i']); }
    if (isset($options['e'])) { $options['e'] = is_array($options['e']) ? $options['e'] : array($options['e']); }

    //print_r($options);
/*
    $options['i'] = is_array($options['i']) ? $options['i'] : isset($options['i']) ? array($options['i']) : array();
    $options['e'] = is_array($options['e']) ? $options['e'] : isset($options['e']) ? array($options['e']) : array();
    if (count($options['i']) <= 0) { unset($options['i']); }
    if (count($options['e']) <= 0) { unset($options['e']); }
*/

    // load / autodetect test bootstrap file
    if (isset($options['a'])) { 
		$d = isset($options['f']) ? dirname($options['f']) : $options['d'];
        $options['b'] = file_exists("$d/bootstrap.php") ? "$d/bootstrap.php" : $options['b'] ?? '';
    }
    //print_r($options);
    //die();
    if (isset($options['b']) && is_string($options['b']) && strlen($options['b']) > 1) { require $options['b']; }

    // php error squelching
    $options['s'] = isset($options['s']) ? true : false;
    $options['l'] = isset($options['l']) ? true : false;
    $options['p'] = isset($options['p']) ? true : false;
    $options['k'] = isset($options['k']) ? true : false;
	$options['n'] = isset($options['n']) ? true : false;
    $options['cost'] = isset($options['w']) ? 'wt' : 'cpu';
    // code coverage reporting
    $options[COVERAGE] = isset($options[COVERAGE]) ? true : false;
    $options[SHOW_COVERAGE] = isset($options[SHOW_COVERAGE]) ? true : false;
    if ($options[SHOW_COVERAGE]) { $options[COVERAGE] = true; }
    return $options;
}

/** MAIN ... */
// process command line options
$options = parse_options(getopt("b:d:f:t:i:e:pmnqchrvsalkw?"));
$options = init($options);
$options['cmd'] = join(' ', $argv);

// get a list of all tinytest fucntion names
$funcs1 = get_defined_functions(true);
unset($funcs1['internal']);

// load the unit test files
if (isset($options['d'])) {
    load_dir($options['d'], $options);
} else if ($options['f']) {
    load_file($options['f'], $options);
}

// filter out test framework functions by diffing functions before and after loading test files
$just_test_functions = array_filter(get_defined_functions(true)['user'], function($fn_name) use ($funcs1) { return !in_array($fn_name, $funcs1['user']); });

// display functions with userspace override
$is_test_fn = (function_exists("user_is_test_function")) ? "user_is_test_function" : "TinyTest\is_test_function";

class TestResult {
    public $error = null;
    public $pass = false;
    public $result = "";
    public $console = "";
    public function set_error(\Throwable $error) { $this->error = $error; }
    public function set_result(?string $output) { $this->result = $output; }
    public function set_console(?string $output) { $this->console = $output; }
    public function pass() { $this->pass = true; }
}

function do_test(callable $test_function, array $exceptions, ?string $dataset_name, $value) : TestResult {
    $result = new TestResult();
    try {
        ob_start();
        if ($value !== null) {
            $result->set_result(strval($test_function($value)));
        } else {
            $result->set_result(strval($test_function()));
        }
        $result->pass();
    } catch (TestError $err) {
        $err->test_data = $dataset_name;
        $result->set_error($err);
    } catch (Throwable $ex) {
        if (array_reduce($exceptions, is_equal_reduced(get_class($ex)), false) === false) {
            count_assertion_fail();
            $err = new TestError("unexpected: (".$ex->getMessage().") [$dataset_name] [$value]", get_class($ex), join(', ', $exceptions), $ex);
            $result->set_error($err);
        } else {
            $result->pass();
        }
    } finally {
        $result->set_console(ob_get_contents());
        ob_end_clean();
    }
    return $result;
}

// run the test (remove pass by ref)
function run_test(callable $test_function, array $test_data) : array {
    $results = array();
    if (isset($test_data['dataprovider'])) {
		//print_r($test_data);
		//die("hit\n");
        foreach (call_user_func($test_data['dataprovider']) as $dataset_name => $value) {
            $result = do_test($test_function, $test_data['exception'], strval($dataset_name), $value);
            $results[] = $result;
        }
    } else {
        $results[] = do_test($test_function, $test_data['exception'], null, null);
    }

    return $results;
}


// TODO: simplify, maybe add an error handler and skip the error file...
function get_error_log(array $errorconfig, array $options) : ?\Error {
    $verbose_out = "";
    if (file_exists((ERR_OUT))) {
        $lines = file(ERR_OUT);
        @unlink(ERR_OUT);

        foreach ($lines as $line) {
            if (count($errorconfig) > 0) {
                foreach ($errorconfig as $config) {
                    $type_name = explode(":", $config);
                    if (stripos($line, $type_name[0]) !== false && stripos($line, $type_name[1]) !== false) { $verbose_out .= $line; continue; }
                    return new \Error($line);
                }
            } else {
                return new \Error($line);
            }
        }
    }

    if (verbose($options)) { echo $verbose_out; }
    return null;
}

// ugly but compatible with all versions of php
function call_to_source(string $fn, array $x, array $options) : array {
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

    //$call['cost'] = $x[$options['cost']];
    //$call['count'] = $x['ct'];
    //echo "file $fn = [$file:$line]\n";
    return array('line' => $line, 'fn' => $fn, 'file' => $file, 'calls' => array(), 'count' => $x['ct'], 'cost' => $x[$options['cost']]);
}

/*

version: 1
  2 creator: xh2cg for xhprof
  3 cmd: Unknown PHP script
  4 part: 1
  5 positions: line
  6 events: Time
  7 summary: 748168
  */

function output_profile(array $data, string $func_name, array $options) {
	if ($options['n']) {
	    $data = array_filter($data, function($elm) { return ($elm['ct'] > 2 || $elm['wt'] > 9 || $elm['cpu'] > 9); });
    }
    if ($options['p']) {
        return file_put_contents("$func_name.xhprof.json", json_encode($data, JSON_PRETTY_PRINT));
    }

    $pre  = "version: 1\ncreator: https://github.com/bitslip6/tinytest\ncmd: {$options['cmd']}\npart: 1\npositions: line\nevents: Time\nsummary: "; 

    // remove internal functions
    $call_graph = array_filter($data, function($k) {
        return (stripos($k, 'tinytest') !== false
            || stripos($k, 'assert_') !== false
            ) ? false : true;
    }, ARRAY_FILTER_USE_KEY);


    $fn_list = array();
    array_walk($call_graph, function($x, $fn_name) use (&$fn_list, $func_name, $options) { 
        $parts = explode('==>', $fn_name);
        if (!isset($fn_list[$parts[0]])) {
            $call = call_to_source($parts[0], $x, $options);
            $fn_list[$parts[0]] = $call;
        }
        if (count($parts) > 1) {
            $call = call_to_source($parts[1], $x, $options);
            $fn_list[$parts[0]]['calls'][] = $call;
        }
    });

    $out = "";
    $sum = 0;
    array_walk($fn_list, function($x, $fn_name) use (&$out, &$sum) {
        $out .= sprintf("fl=%s\nfn=%s\n%d %d\n", $x['file'], $x['fn'], $x['line'], $x['cost']);
        //$sum += $x['cost'];
        foreach ($x['calls'] as $call) {
            $out .= sprintf("cfl=%s\ncfn=%s\ncalls=%d %d\n%d %d\n", $call['file'], $call['fn'], $call['count'], $call['line'], $x['line'], $call['cost']);
            $sum += $call['cost'];
        }
        $out .= "\n";
    });
    
    file_put_contents("callgrind.$func_name", $pre . $sum . "\n\n". $out);
    return;
}

// a bit ugly
// loop over all user included functions
$coverage = array();
do_for_all($just_test_functions, function($function_name) use (&$coverage, $options, $is_test_fn) {

    $data_set_name = "";
    // exclude functions that don't match test name signature
    if (!$is_test_fn($function_name, $options)) { return; }
    // read the test annotations, exclude test based on types
    $test_data = read_test_annotations($function_name);
    if (is_excluded_test($test_data, $options)) { return; }

    // display the test we are running
    $format_test_fn = (function_exists("user_format_test_run")) ? "user_format_test_run" : "\\TinyTest\\format_test_run";
    echo $format_test_fn($function_name, $test_data, $options);

    // only list tests
    if ($options['l']) { return; }
    $error = $result = $t0 = $t1 = null;
    $pre_test_assert_count = $GLOBALS[ASSERT_CNT];

    // turn on output buffer and start the operation log for code coverage reporting
	if ($options[COVERAGE]) {
    	panic_if(!function_exists('phpdbg_start_oplog'), RED . "\ncode coverage only available in phpdbg -rre tinytest.php\n" . NORML);
		\phpdbg_start_oplog();
    }

    // run the test
    if ($options['p'] || $options['k']) { \tideways_enable(TIDEWAYS_FLAGS_MEMORY | TIDEWAYS_FLAGS_CPU); }
    $t0 = microtime(true);
    $results = run_test($function_name, $test_data, $options);
    $t1 = microtime(true);
    if ($options['p'] || $options['k']) { output_profile(\tideways_disable(), $function_name, $options); }

    // combine the oplogs...
    if ($options[COVERAGE]) {
        $coverage = combine_oplog($coverage, \phpdbg_end_oplog(), $options);
    }


    // did the test pass?
    $passed = all_match($results, function(TestResult $result) { return $result->pass; });

    $test_data['result'] = array_reduce($results, function(string $out, TestResult $result) { return $out . $result->result; }, "");
    $console = array_reduce($results, function(string $out, TestResult $result) { return $out . $result->console; }, "");
    if (verbose($options) && $console !== "") { $test_data["result"] .= "\nconsole output:\n$console"; }


    $test_data['error'] = (!$passed) ? 
        array_reduce($results, function($last_error, TestResult $result) { return (!$result->pass) ? $result->error : $last_error; }, null) :
        get_error_log($test_data['phperror'], $options);

    if ($passed) {
        $test_data['status'] = "OK";
        if ($GLOBALS[ASSERT_CNT] === $pre_test_assert_count) {
            count_assertion_fail();
            $test_data['status'] = "IN";
        }
        $success_display_fn = (function_exists("user_format_test_success")) ? "user_format_test_success" : "\\TinyTest\\format_test_success";
        echo $success_display_fn($test_data, $options, $t1-$t0);
    } else {
        if ($data_set_name !== "") { $result .= "\nfailed on dataset member [$data_set_name]\n"; }
        $error_display_fn = (function_exists("user_format_assertion_error")) ? "user_format_assertion_error" : "\\TinyTest\\format_assertion_error";
        echo $error_display_fn($test_data, $options, $t1-$t0);
    }

    
	gc_collect_cycles();
});

if (count($coverage) > 0) {
    //print_r($coverage);
    echo "\ngenerating lcov.info...\n";
    file_put_contents("lcov.info", coverage_to_lcov($coverage, $options));
}

@unlink(ERR_OUT);
// display the test results
$m1=microtime(true);
echo "\n".NORML.$GLOBALS[ASSERT_CNT] . " tests, " . $GLOBALS['assert_pass_count'] . " passed, " . $GLOBALS['assert_fail_count'] . " failures/exceptions, using " . number_format(memory_get_peak_usage(true)/1024) . "KB in ".number_format($m1-$m0, 5)." seconds";
}
