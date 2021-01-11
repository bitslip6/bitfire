<html>
<body>
<h2>this IP address has been blocked for unusual or suspicious activity</h2>
<h3>reference id: <?php echo \BitFire\BitFire::get_instance()->uid . "\n"; ?>
<!--
<?php
echo "BitFire block time: " . \number_format(((\microtime(true) - $m0)*1000), 3) . " ms\n";
print_r($block->value());
?>
-->
</body>
</html>
<?php 
file_put_contents("/tmp/block.json", json_encode(\tideways_disable(), JSON_PRETTY_PRINT));
exit();