<?php
    $code = intval(\BitFire\Config::int("response_code", 200));
    $error_css = isset($error_css) ? htmlentities($error_css) : "";
    $uuid = $block_type = "undefined";
    if (isset($block)) {
        $uuid = $block->uuid;
        $block_type = htmlentities($block->__toString());
    }
    $ms = round(((microtime(true)-$GLOBALS['start_time'])*1000), 2);
    $now = \ThreadFin\utc_date("m/d @H.i.s"); 
    http_response_code($code);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Request blocked by BitFire</title>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, follow">
    <link type="text/css" rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.1/css/fontawesome.min.css">
    <link type="text/css" rel="stylesheet" href="<?php echo $error_css; ?>">
    <style>
    </style>
</head>
<body>
<div id="block"> <div class="block-bg"></div> <div class="block"> <div class="block-err"> <h1>Halt!</h1> </div>
<h2>Something went wrong</h2>
<p class="nor">This site is protected by BitFire WAF.  <br>
Your action: <strong><?php echo $block_type; ?></strong> was blocked.  </p>
<p class="nor">If this is an error, please click the request review button below. Reference ID <i><?php echo $uuid; ?></i></p>
<a href="#" id="review"> <button type="button" id="review">Request Review</button> </a>
<a href="/"> <button type="button" id="home">Back To Homepage</button> </a>
</div> </div>
<div id="attribute"><p>
    <span> Powered by: <a href="https://bitfire.co" rel="nofollow sponsored" target="_blank" style="color: #fff;">BitFire</a></span>
    <span> Photo by: <a href="https://www.pexels.com/@pok-rie-33563/" rel="nofollow ugc" target="_blank" style="color: #fff;">@pok-rie</a> </span>
</p></div>
<script>
document.getElementById("review").addEventListener("click", function () {
let e=window.event; let data={"uuid":'<?php echo $uuid;?>',"x":e.clientX,"y":e.clientY}; console.log(data);
const response = fetch("/?BITFIRE_API=review", {
method:'POST',mode:'no-cors',cache:'no-cache',credentials:'omit',headers:{'Content-Type': 'application/json'},redirect:'follow',referrerPolicy:'unsafe-url',body:JSON.stringify(data)
});
});
</script>
</body>
</html>
<!--
detailed block reason: 
<?php if (\BitFire\Config::enabled('debug')) { echo(json_encode($block, JSON_PRETTY_PRINT)); } ?>
-->
