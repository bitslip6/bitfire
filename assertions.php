<?php declare(strict_types=1);
namespace {

    function assert_base_condition(callable $test_fn, $actual, $expected, string $message, string $output = "") {
        if ($test_fn($actual, $expected) === false) {
        	TinyTest\count_assertion_fail();
			if ($output !== "") { echo $output; }
            throw new TinyTest\TestError($message, $actual, $expected);
        }
        TinyTest\count_assertion_pass();
    }

    function assert_true($condition, string $message, string $output = "") {
        assert_base_condition(function($condition, $expected) { return $condition; }, $condition, true, $message, $output);
    }

    function assert_false($condition, string $message, string $output = "") {
        assert_base_condition(function($condition, $expected) { return !$condition; }, $condition, false, $message, $output);
    }

    function assert_eq($actual, $expected, string $message, string $output = "") {
        assert_base_condition(function($actual, $expected) { return $actual === $expected; }, $actual, $expected, $message, $output);
    }

    function assert_eqic($actual, $expected, string $message) {
        assert_base_condition(function($actual, $expected) { return ($actual === $expected || ($actual != null && strcasecmp($actual, $expected) === 0)); }, $actual, $expected, $message);
    }

    function assert_neq($actual, $expected, string $message) {
        assert_base_condition(function($actual, $expected) { return $actual !== $expected; }, $actual, $expected, $message);
    }

    function assert_gt($actual, $expected, string $message) {
        assert_base_condition(function($actual, $expected) { return $actual > $expected; }, $actual, $expected, $message);
    }

    function assert_lt($actual, $expected, string $message) {
        assert_base_condition(function($actual, $expected) { return $actual < $expected; }, $actual, $expected, $message);
    }

    function assert_icontains(?string $haystack, ?string $needle, string $message) {
        assert_base_condition(function(?string $needle, ?string $haystack) { 
            return ($haystack != null && stripos($haystack, $needle) !== false); }, $needle, $haystack, $message);
    }

    function assert_contains(?string $haystack, ?string $needle, string $message) {
        assert_base_condition(function(?string $needle, ?string $haystack) { 
            return ($haystack != null && strpos($haystack, $needle) !== false); }, $needle, $haystack, $message);
    }

    function assert_not_contains(?string $haystack, ?string $needle, string $message) {
        assert_base_condition(function(?string $needle, ?string $haystack) { 

            return ($haystack == null || $needle == null || strpos($haystack, $needle) === false); }, $needle, $haystack, $message);
    }

	function assert_instanceof($actual, $expected, $message) {
        assert_base_condition(function($actual, $expected) { 
            return ($actual != null && $actual instanceof $expected); }, $actual, $expected, $message);
	}
	
}
