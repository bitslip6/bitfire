<html>
<head>
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
</head>
<body>
<h2>this IP address has been blocked for unusual or suspicious activity</h2>
<h3>reference id: <?php echo htmlspecialchars(\BitFire\BitFire::get_instance()->uid)."\n"; //uid can only be alpha-num, extra safe encoding here?>
<!--
<?php
http_response_code(\BitFire\Config::int('response_code', 500));
// $block is the firewall block reason
if (\BitFire\Config::enabled('debug')) {
    echo(json_encode($block, JSON_PRETTY_PRINT));
}
?>
-->
</body>
</html>
