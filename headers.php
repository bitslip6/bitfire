<?php declare(strict_types=1);
namespace BitFireHeader;

use const BitFire\REQUEST_HOST;
use const BitFire\REQUEST_PATH;

const CONFIG_ENFORCE_SSL = "encorfe_ssl_1year";

const FEATURE_POLICY = array('geolocation' => '*', 'midi' => 'self', 'notifications' => 'self', 'push' => 'self', 'sync-xhr' => 'self', 'microphone' => 'self', 'gyroscope' => 'self', 'speaker' => 'self', 'vibrate' => 'self', 'fullscreen' => 'self', 'payment' => '*');
const FEATURE_NAMES = array('geolocation', 'midi', 'notifications', 'push', 'sync-xhr', 'microphone', 'gyroscope', 'speaker', 'vibrate', 'fullscreen', 'payment');

const CSP = array('child-src', 'connect-src', 'default-src', 'font-src',
            'frame-src', 'img-src', 'manifest-src', 'media-src', 'object-src', 'prefetch-src',
            'script-src', 'style-src', 'webrtc-src', 'worker-src', 'base-uri',
            'form-action', 'frame-ancestors', 'upgrade-insecure-requests');

/**
 * add the security headers from config
 */
function send_security_headers(?array $request) : void {
    if (!$request) { return; }

    header_remove('X-Powered-By');
    header_remove('Server');
    $path = $request[REQUEST_HOST].$request[REQUEST_PATH]."?_bitfire=report";

    header("X-Frame-Options: deny");
    header("X-Content-Type-Options: nosniff");
    header("X-XSS-Protection: 1; report=$path");
    header("Referer-Policy: strict-origin-when-cross-origin");
    header('Report-To: {"group":"bitfire","max_age":2592000,"endpoints":[{"url"'.$path.'"}],"include_subdomains":true}');

    // set strict transport security (HSTS)
    if (\Bitfire\Config::enabled("enforce_ssl_1year")) {
        header("Strict-Transport-Security: max-age=31536000; preload");
    }

    // set a default feature policy
    if (\BitFire\Config::enabled("default_feature_policy")) {
        // TODO: replace with reduce_map
        header(\TF\map_reduce(FEATURE_POLICY, function($key, $value, $carry) {
                return  $carry . $key . " '$value'; ";
            }, "Feature-Policy: ") );
    }
    
    if (\BitFire\Config::enabled("nel")) {
        header('{"report_to":"bitfire","max_age":2592000,"include_subdomains":true}');
    }
}
