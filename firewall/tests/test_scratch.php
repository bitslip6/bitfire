<?php declare(strict_types=1);

//use FineDiff;
use function ThreadFin\dbg;
use function ThreadFin\http2;

if (!defined("\BitFire\WAF_ROOT")) {
    define('\BitFire\WAF_ROOT', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)) . DIRECTORY_SEPARATOR);
    define('\BitFire\WAF_ROOT', realpath(\BitFire\WAF_ROOT . ".."));
}

include_once \BitFire\WAF_SRC."bitfire.php";
include_once \BitFire\WAF_SRC."util.php";
include_once \BitFire\WAF_SRC."diff.php";



/*
function test_thing() : void {
    echo "TW\n";
    $d = 'a->2->{i->0;s->5->"0002.";i->1;s->1517->"0002.Nsj1u_mj4JqKsXOP_ocLBLxGgs0cVBWKEuH9IqcOSACvNxWPIPuauQiaHftLtJd58hh26Vv3K1dbHJE353NTmIkaA5zL6dPO4WdkIVDr4BH4XN1osaWdgkuNKERVt04xLjZDSALuZBXp0dp_QnECqZFe3WUhsEkngLl1xqPGUmfrcEmsCmnnl4Q9oM4I9U_89KaquOlmW2GYTKOk0Tqr0LoXDKCJioJxPKMqLOs2b2M_JdA3KzYWvdCe0pW0iPCz3uCZvwsH3t0iWw3_Dk8il1jPLAr_BOA0Ri7YKFcC0hI7hahH1gH_yPNvTt9nCeRwVFSujQRyP5EjvQBUojJF5rlmEEYaPObm3BFIrhWOSzEB8QvQqC0GFfumvbOkgIrd_n_tG0W_HBqNVXmVzJmejaV44XcAQ6vJ4I2Tz6yBVWF7HZ9a2U4BNAHTsN8AtySu4jTbo8uIJYpZ6BGXNKnL7LPyc2af1iQcE_L6P00Uetz6JKqUQmYn7MITJhLm0O2cgihRyV_OiHhsR2SDSzrClQAO6JU4k6eEoHerhY8gm5Qv0DNWgv5cM0jYQfKf_P8U9j6pOkRODPXbhw24_NTuJqn6MzBIfBb1ge0aA4FjUEiA_3YVfJRpfDLh4iV__qBvMf_lyYT0_TcT9rZBWM_xbAAgRN8SOgRkT0rHGmHExuuS_CE5MEWe2pq8j5_sNFQ_gHwTNcX8BfjVbO6KuNK5ysSe5H616FHELKAQwU2F9wHrEyuGWBnaeuERodLEoatAAkubH5In6j_ZE7hBAFg2vh1UG_Is_Aox3fauqqTkwtI8_OYjeVydx5o1dLbXdkuJyugQ7t1LoZ0ELlKuyBOUxgA_WFuUzYXOwJko_4GFDwpw8fTrW8krEhjfbJtRwenaLbas52q1syenitwut0LjHpaGYcrByd8_twsjqpb1BrXq9Y0geD5K_woYKSbR5tVYr98zZDSz15r0TCPA_WhjTBSBpcMfCS_z5xq_o91JFbD_LFt8GlrCJ3_zQBJurTufoZNaAmjV0um8noLmX39r4_vh0j96_ezAsR0jnwHO0M9lKA9vBrvoZDDhSPvjytaA6jWUJN6vK4ZIIHqjE7I3qPKXm759ouR2yNlvc__g_QB_b59KhLBaKNzvRNCUyBoG2CvJLr4NI_lBwSNNMuncMansqNkM7OT5hOxxA2QMHWsyXN3sax5dgs2XUClEqCmXJkE4TLXgYRweo7sfb1wDqllMConRavR9rDzklEUcUDWoZALK_Z0yjHQ3VsLLOsgKwAF4WIkW4c8HlbLpI4esAvODdp9eBzxsocKH1_WxUXeaprE53eld1WFPZQFcNvjcU5fQfvx9GIHq3pFw5BuXJf1FHEGPcwwta6PqxjVbb6N_CMw6qFSPQLi0ITzF0I2Lekg4P2pZQ8N7YQeGhKMifiPoCu_miPYGN94_B1eVpXImpeFnOM39ZrudOxqqEqoOO34I7FZ30BE6NJ0ghRR6vyPEy5oxzKfz8tEWFxx9";}';
    $x = unserialize($d);
    print_r($x);
    //stream_wrapper_register("file", "mywrap");
}
*/

function test_diff() : void {
    $local = "/var/www/wordpress/wp-content/plugins/bitfire/startup.php";
    $url = "https://plugins.svn.wordpress.org/bitfire/tags/3.6.1/startup.php";
    $result = http2("GET", $url);
    if (empty($result["content"])) {
        $url = "https://plugins.svn.wordpress.org/bitfire/trunk/startup.php";
        $result = http2("GET", $url);
    }

    $op_codes = FineDiff::getDiffOpcodes($result['content'], $local, FineDiff::$paragraphGranularity);
    $to_text = FineDiff::renderToTextFromOpcodes($result["content"], $op_codes);
    //dbg($to_text, "diff");
}

function test_dir() : void {
    $ctx = stream_context_create([], []);
    $dh = opendir("/tmp", $ctx);
    print_r($ctx);
    print_r($dh);
    echo "----\n";
    $file = readdir($dh);
    print_r($file);
    $file = readdir($dh);
    print_r($file);
    $file = readdir($dh);
    print_r($file);
    echo "----\n";


    $cs = serialize($ctx);
    $ds = serialize($dh);

    print_r($cs);
    print_r($ds);

}

//test_thing();

