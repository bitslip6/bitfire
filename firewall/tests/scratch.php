<?php

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

$user_agent = "cloud mapping experiment. contact research@pdrlabs.net";
// remove anything that is not alpha
$agent_min1 = preg_replace("/[^a-z\s]+/", " ", strtolower(trim($user_agent)));
// remove short words
$agent_min2 = preg_replace("/\s+/", " ", preg_replace("/\s[a-z]{1,3}\s([a-z]{1-3}\s)?/", " ", $agent_min1));
$trim = substr($agent_min2, 0, 250);
$crc32 = crc32($agent_min2);
die("$trim = $crc32");


$c = ["a", "this", "string"];
$a = "this 1.2.3.1 (iss a rv:1223 test) string ";
$z = ["is", "test"];
$fn = function($carry, $item) { return str_replace($item, "", $carry); };

$agent_min1 = preg_replace("/[^a-z\s]/", " ", $a);
$agent_min2 = preg_replace("/\s[a-z]{0,3}\s/", "  ", $agent_min1);
$agent_min3 = preg_replace("/\s[a-z]{0,3}\s/", " ", $agent_min2);
echo "($a) => [$agent_min2] ($agent_min3)\n";


$r = array_reduce($c, $fn, $agent_min3);
$w = array_filter(explode(" ", $r));
$d = array_diff($w, $z);
print_r($c);
print_r($a);
echo "\n---\n";
print_r($w);
echo "\n---\n";
print_r($d);
echo "\n";
die();
