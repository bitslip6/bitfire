<?php
namespace BitFireHeader;

const CONFIG_ENFORCE_SSL = "enforce_ssl_1year";

const FEATURE_POLICY = array('accelerometer' => 'self', 'ambient-light-sensor' => 'self', 'autoplay' => 'self', 'camera' => 'self', 'geolocation' => '*', 'midi' => 'self', 'notifications' => 'self', 'push' => 'self', 'sync-xhr' => 'self', 'microphone' => 'self', 'gyroscope' => 'self', 'speaker' => 'self', 'vibrate' => 'self', 'fullscreen' => 'self', 'payment' => '*');

const FEATURE_NAMES = array('geolocation', 'midi', 'notifications', 'push', 'sync-xhr', 'microphone', 'gyroscope', 'speaker', 'vibrate', 'fullscreen', 'payment');

const CSP = array('child-src', 'connect-src', 'default-src', 'font-src',
            'frame-src', 'img-src', 'manifest-src', 'media-src', 'object-src', 'prefetch-src',
            'script-src', 'style-src', 'style-src-elem', 'script-src-attr', 'style-src', 
            'style-src-elem', 'style-src-attr', 'worker-src');

/**
 * log CSP report failures
 */
function header_report(\BitFire\Request $request) : void {
    file_put_contents("/tmp/bitfire.report.json", \TF\en_json($request), FILE_APPEND);
}

/**
 * add the security headers from config
 */
function send_security_headers(\BitFire\Request $request) : void {
    if (!$request) { return; }

    $path = $request->host . $request->path . "?" . \BitFire\BITFIRE_INTERNAL_PARAM . "=report";
    core_headers($path);

    // set strict transport security (HSTS)
    if (\Bitfire\Config::str("enforce_ssl_1year") == "block" || \Bitfire\Config::str("enforce_ssl_1year") === true) {
        force_ssl_with_sts();
    }

    if (\BitFire\Config::enabled("nel")) {
        header('{"report_to":"bitfire","max_age":2592000,"include_subdomains":true}');
    }

    // PRO HEADERS
    if (function_exists('\BitFirePRO\send_pro_headers')) {
        \BitFirePRO\send_pro_headers($request);
    }
 
}

function core_headers(string $path) : void {
	if (headers_sent()) { return; }
    header_remove('X-Powered-By');
    header_remove('Server');

    @header("X-Frame-Options: deny");
    @header("X-Content-Type-Options: nosniff");
    @header("X-XSS-Protection: 1; mode=block");
    @header("Referrer-Policy: strict-origin-when-cross-origin");
}

function force_ssl_with_sts() : void {
	if (headers_sent()) { return; }
    header("Strict-Transport-Security: max-age=31536000; preload");
    if (($_SERVER['REQUEST_SCHEME']??'https') === 'http') {
         header("Location: https://". $_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']);
         die();
    }
}
