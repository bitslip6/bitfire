<?php declare(strict_types=1);

if (!defined("WAF_DIR")) {
    define('WAF_DIR', realpath(dirname(__DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR)) . DIRECTORY_SEPARATOR);
}
require_once WAF_DIR . "src/internal/hash.php";

use function \TF\partial as BIND;
use function \TF\partial_right as BIND_R;

function var_find_list() : array { 
    return array(
        "basic" => array('$foo = 1;', '$foo'),
        "basic2" => array('$foo = 1; $bar = 2;', '$foo $bar'),
        "array1" => array('$foo[\'x\'] = 1;', '$foo[\'x\']'),
        "array2" => array('$foo["x1234"] = 1;', '$foo["x1234"]'),
        "array3" => array('$foo[\'x\'] = 1;', '$foo[\'x\']'),
        "array4" => array('$foo["x1234"] = 1;', '$foo["x1234"]'),
        "array5" => array('$fêo[\'x1234\'] = 1;', '$fêo[\'x1234\']'),
        "ascii1" => array('$Zê = 1;', '$Zê')
    );
}

/**
 * @dataprovider var_find_list
 */
function test_find_variable(array $test_data) : void {

    preg_match_all("/".PHP_VAR."/", $test_data[0], $matches);
    $parts = explode(" ", $test_data[1]);
    for ($i=0; $i<count($parts); $i++) {
        $var = trim($matches[0][$i]??'');
        assert_eq($var, $parts[$i], "unable to find variable");
    }
}

function fix_test_find_sinks() : void {
    $lines = array("<?php echo 'some data ' . \$foobar . ' more data . \" \$thing['xyz']\n\";");
    $r = find_sinks($lines);
    assert_gt(1, count($r), "unable to find 2 sinks");
}

function fix_test_trace_and_taint() : void {
    $example = file(__DIR__ . "/test_taint.txt");
    print_r($example);
    $tainted = trace_and_taint($example);
    print_r($tainted);
}



/**
 * @type manual
 */
function fix_test_sink_taint() : void {
    //ini_set('memory_limit', '1024M');
    //$tainted = trace_and_taint($lines, "test_taint.txt");
    $path = "/tmp/out/plugins.svn.wordpress.org/zettle-pos-integration/tags/1.4.2";
    $GLOBALS['tfuncs'] = array("echo" => 'echo', "print" => 'echo', "mysql_query" => 'sql', "mysqli_query" => 'sql');
    \TF\file_recurse($path, 'sink_finder');
    //\TF\file_recurse("/tmp/out/plugins.svn.wordpress.org/zettle-pos-integration/tags/1.4.2", 'sink_finder');//, '/^(?!.*(vendor)).*$/');
    $sinks = \TF\file_recurse($path, 'sink_finder');
    //$sinks = \TF\file_recurse("/tmp/out/plugins.svn.wordpress.org/zettle-pos-integration/tags/1.4.2", 'sink_finder');//, '/^(?!.*(vendor)).*$/');

    $tainted = \TF\file_recurse($path, 'taint_finder');
    //$tainted = \TF\file_recurse("/tmp/out/plugins.svn.wordpress.org/zettle-pos-integration/tags/1.4.2", 'taint_finder');//, '/^(?!.*(vendor)).*$/');
    
    $full_list = array();
    foreach ($tainted as $x) {
        foreach ($x as $y => $list) {
            if (count($list) > 0) {
                if (!isset($full_list[$y])) { $full_list[$y] = $list; }
                else { $full_list[$y] = array_merge($full_list[$y], $list); }
            }
        }
    }

    $x = resolve_tained_sinks($sinks, $full_list);
    print_r($x);
}
