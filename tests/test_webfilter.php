<?php declare(strict_types=1);

use BitFire\Config;
use BitFire\WebFilter;

use const BitFire\CONFIG_SPAM_FILTER;
use const BitFire\CONFIG_SQL_FILTER;
use const BitFire\CONFIG_WEB_FILTER_ENABLED;
use const BitFire\CONFIG_CACHE_TYPE;

function sql_test_list1() : iterable {
    return TinyTest\line_at_a_time(dirname(__FILE__) . "/sql_payload2.txt");
}
function xss_test_list1() : iterable {
    return TinyTest\line_at_a_time(dirname(__FILE__) . "/xss_payload.txt");
    //return TinyTest\line_at_a_time(dirname(__FILE__) . "/xss_small.txt");
}
function xss_test_list2() : iterable {
    return TinyTest\line_at_a_time(dirname(__FILE__) . "/xss_payload2.txt");
}
function xss_test_list3() : iterable {
    return TinyTest\line_at_a_time(dirname(__FILE__) . "/xss_payload3.txt");
}

function run_xss_filter1(string $data) : void {
    Config::set_value(CONFIG_WEB_FILTER_ENABLED, true);
    static $filter = NULL;
    if ($filter === NULL) { $filter = new WebFilter(); }

    $request = setup($data);
    $block = $filter->inspect($request);
    assert_false($block->empty(), "did not block [$data]");

    $v2 = preg_replace_callback("|\\\\x([a-fA-F0-9]{2})|", function ($matches) {
        return chr(hexdec($matches[1]));
    }, $data);
    if ($v2 !== $data) {
        $request = setup($v2);
        $block = $filter->inspect($request);
        assert_false($block->empty(), "did not block [$data]");
    }

    $v3 = urldecode($data);
    if ($v3 !== $data) {
        $request = setup($v3);
        $block = $filter->inspect($request);
        assert_false($block->empty(), "did not block [$data]");
    }
}


/**
 * @dataprovider xss_test_list1
 * @type biglist
 */
function test_xss_list1(string $data) : void {
    $v1 = $data;
    $v2 = preg_replace_callback("|\\\\x([a-fA-F0-9]{2})|", function ($matches) {
        return chr(hexdec($matches[1]));
    }, $data);
    run_xss_filter1($data);
    if ($v2 !== $data) {
        run_xss_filter1($v2);
    }
}
/**
 * @dataprovider xss_test_list2
 * @type biglist
 */
function test_xss_list2(string $data) : void {
    run_xss_filter1($data);
}

/**
 * @dataprovider xss_test_list3
 * @type biglist
 */
function test_xss_list3(string $data) : void {
    run_xss_filter1($data);
}

/**
 * @type coverage
 */
function test_xss_list4() : void {
    run_xss_pass("a simple parameter with no attacks");
}

/**
 * @type coverage
 */
function test_xss_list5() : void {
    run_xss_block("<script>alert(1)</script>\n");
}


/**
 * @dataprovider sql_test_list1
 * @type biglist
 */
function test_sql_list1(string $data) : void {
    if (strlen(trim($data)) < 2) { return; }

    $req = setup($data);
    $filter = new WebFilter();
    Config::set_value(CONFIG_WEB_FILTER_ENABLED, false);
    Config::set_value(CONFIG_SPAM_FILTER, false);
    Config::set_value(CONFIG_SQL_FILTER, true);
    $maybe_error = $filter->inspect($req);
    assert_false($maybe_error->empty(), "failed to find sql [$data]");
}


function setup(string $data) : \BitFire\Request {
    \TF\Maybe::$FALSE = \TF\MaybeBlock::of(NULL);
    $server['REQUEST_URI'] = "https://www.mysite.com/some/page?param1=foo&" . $data;
    $request = BitFire\process_request2(
        //array('a'=>'1', 'inj_param' => $data, 'normal_param' => 'whatever'),
        //array('a'=>'1', 'inj_param' => $data, 'normal_param' => 'whatever'),
        array('inj_param' => $data),
        array(),
         $server, array());
    return $request;
}

function run_xss_pass(string $data) : void {
    $static = "a parameter with just placeholder data";
    $req = setup($static);
    $filter = new WebFilter();
    Config::set_value(CONFIG_WEB_FILTER_ENABLED, true);
    Config::set_value(CONFIG_SPAM_FILTER, false);
    Config::set_value(CONFIG_SQL_FILTER, false);
    $maybe_error = $filter->inspect($req);
    assert_true($maybe_error->empty(), "false positive xss [$static]");
}

function run_xss_block(string $data) : void {
    $static = "<script>alert(1)</script>";
    $req = setup($static);
    //$filter = $GLOBALS['f'];
    $filter = new WebFilter();
    Config::set_value(CONFIG_WEB_FILTER_ENABLED, true);
    Config::set_value(CONFIG_SPAM_FILTER, false);
    Config::set_value(CONFIG_SQL_FILTER, false);
    $maybe_error = $filter->inspect($req);
    assert_false($maybe_error->empty(), "false negative xss [$static]");
}
