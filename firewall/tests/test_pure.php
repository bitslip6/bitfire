<?php declare(strict_types=1);

use TF\FileData;

use function BitFire\flatten;
use function TF\tar_extract;

if (!defined("\BitFire\WAF_ROOT")) {
    define('\BitFire\WAF_ROOT', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)));
}
include_once \BitFire\WAF_SRC."php";
include_once \BitFire\WAF_SRC."php";
include_once \BitFire\WAF_SRC."php";



function test_ip_block() : void {
    $block = new \BitFire\Block(0, "foobar", "value", "thing", 0);
    $request = new \BitFire\Request();
    $request->agent = "Unit Test";
    $request->ip = "127.0.0.1";
    $block_time = 600;
    $response_code = 200;

    $effect = \BitFire\Pure\ip_block($block, $request, $block_time);
    assert_eq(count($effect->read_files()), 1, "ip block did not set any ip block files");
    assert_eq($effect->read_files()[0]->filename, "/tmp/blocks/127.0.0.1", "ip block did not set correct path");
    assert_eq($effect->read_files()[0]->modtime, time() + 600, "ip block did not set correct expiration time");
    assert_gt(strlen($effect->read_files()[0]->content), 128, "ip block did not set block reason");
}

/*
function flatten_tests() : array {
    return array( 
        "test string" => "test string",
        array("array", "of", "strings") => "array^of^strings",
        "array", 1234, "numbers", 13412, "and", "strings"] => "array^1234^numbers^13412^and^strings"
    );
}
*/

    /*
    $r = "";
        foreach($data as $key => $value) {
            if (is_array($value)) {
                $r .= flatten($value);
            } else {
                $r .= "^$key:$value";
            }
        }
    }
    else {
        $r .= (string)$data;
    }

    return $r;
    */

/**
 * @return void 
 */
function test_flatten_array() : void {
    $data = array("key1" => "value 1", "key2" => 12345, "key3" => ["string d", 1234, ["second", "level", "array"], "more string d"]);
    $r = flatten($data);
    assert_contains($r, "level", "unable to flatten multi-dimensional");
}


function test_param_to_str() : void {
    
    $params = array("user" => "myself", "pwd" => "secret"); 
    $filter = array("pwd" => true); 

    $result = \BitFire\Pure\param_to_str($params, $filter);
    assert_contains($result, "**REDACTED**", "unable to redact password");
}


function test_load_exceptions_unit() : void {
    // mock the FS
    $d = '[
{"parameter":"example", "uuid": "example_global_parameter_code_class", "code": 14000},
{"parameter":"example", "uuid": "example_global_parameter_single_code", "code": 14003},
{"parameter":"example", "uuid": "example_global_parameter_all_codes", "code": 0},
{"parameter":"example", "path": "/some/path", "uuid": "example_parameter_one_url_all_codes", "code": 0}
]';
    $file = \BitFire\WAF_ROOT."exceptions.json";
    FileData::mask_file($file, $d);

    $exceptions = FileData::new($file)->read()->unjson();
    assert_gt(count($exceptions()), 1, "unable to load exceptions from $file");
}

/**
 * @type integration
 */
function test_load_exceptions_int() : void {
    $file = \BitFire\WAF_ROOT."exceptions.json";
    $exceptions = FileData::new($file)->read()->unjson();
    assert_gt(count($exceptions()), 1, "unable to load exceptions from $file");
}


/*
function test_wrapper() : void {
    stream_wrapper_unregister("file");
    stream_wrapper_register("file", "FileProtection");
    $h1 = file_get_contents("src/botfilter.php");
    assert_gt(strlen($h1), 20000, "unable to read botfilter.php");

    $wrote = file_put_contents("/tmp/test.txt", "php file!\n");
    assert_eq($wrote, 10, "unable to write to /tmp/test.txt");


    $renamed = rename("/tmp/test.txt", "/tmp/test2.txt");
    assert_true($renamed, "unable to rename to txt file");

    $unlinked = unlink("/tmp/test2.txt");
    assert_true($unlinked, "unable to rename to txt file");

    $wrote = file_put_contents("/tmp/foo.php", "<?php echo 'foo'; ?>");
    assert_false($wrote, "was able to write php content");

    $wrote = file_put_contents("/tmp/foo.txt", "<?php echo 'foo'; ?>", FILE_APPEND);
    assert_false($wrote, "was able to write php content");

    $wrote = file_put_contents("/tmp/test.txt", "average contents", FILE_APPEND);
    $renamed = rename("/tmp/test.txt", "/tmp/test.php");
    assert_false($renamed, "unable to rename txt to /tmp/test.php");
}
*/