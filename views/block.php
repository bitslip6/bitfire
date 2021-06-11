<html>
<body>
<h2>this IP address has been blocked for unusual or suspicious activity</h2>
<h3>reference id: <?php echo \BitFire\BitFire::get_instance()->uid . "\n"; ?>
<!--
<?php
http_response_code(\BitFire\Config::int('response_code', 500));
if (\BitFire\Config::enabled('debug')) {
    $end_time = \microtime(true);
    echo "BitFire block time: " . \number_format((($end_time - $GLOBALS['start_time'])*1000), 3) . " ms\n";
    print_r($block);
}
?>
-->
</body>
</html>
