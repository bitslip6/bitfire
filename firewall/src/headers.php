<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * all functions are called via api_call() from bitfire.php and all authentication 
 * is done there before calling any of these methods.
 */

namespace BitFireHeader;

use BitFire\Config;
use BitFire\UserAgent;
use ThreadFin\Effect;
use ThreadFin\MaybeStr;

use function ThreadFin\contains;
use function ThreadFin\trace;
use function ThreadFin\debug;

const CONFIG_ENFORCE_SSL = "enforce_ssl_1year";
const FEATURE_POLICY = array('accelerometer' => 'self', 'ambient-light-sensor' => 'self', 'autoplay' => 'self', 'camera' => 'self', 'geolocation' => '*', 'midi' => 'self', 'notifications' => 'self', 'push' => 'self', 'sync-xhr' => 'self', 'microphone' => 'self', 'gyroscope' => 'self', 'speaker' => 'self', 'vibrate' => 'self', 'fullscreen' => 'self', 'payment' => '*');
const FEATURE_NAMES = array('geolocation', 'midi', 'notifications', 'push', 'sync-xhr', 'microphone', 'gyroscope', 'speaker', 'vibrate', 'fullscreen', 'payment');

const CSP = array('child-src', 'connect-src', 'default-src', 'font-src',
            'frame-src', 'img-src', 'manifest-src', 'media-src', 'object-src', 'prefetch-src',
            'script-src', 'style-src', 'style-src-elem', 'script-src-attr', 'style-src', 
            'style-src-elem', 'style-src-attr', 'worker-src');


/**
 * add the security headers from config
 */
function send_security_headers(\BitFire\Request $request, MaybeStr $cookies, ?UserAgent $agent) : Effect {
    // GUARD, should never be hit
	if (headers_sent() || php_sapi_name() == "cli") { trace("HDR_SENT"); return Effect::new(); }
    trace("HDR");

    $effect = core_headers($agent);

    // set strict transport security (HSTS)
    if (\Bitfire\Config::str("enforce_ssl_1year") == "block" || \Bitfire\Config::str("enforce_ssl_1year") === true) {
        $effect->chain(force_ssl_with_sts());
    }

    // PRO HEADERS
    if (function_exists('\BitFirePRO\send_pro_headers')) {
        $effect->chain(\BitFirePRO\send_pro_headers($request, $cookies, $agent));
    }
 
    return $effect;
}

/**
 * create an effect to set http security headers
 * @param UserAgent $agent 
 * @return Effect 
 */
function core_headers(?UserAgent $agent) : Effect {
    // seems excessive to add effect support for removing headers
    header_remove('X-Powered-By');
    header_remove('Server');

    $effect = Effect::new();

    $effect->header("Referrer-Policy", "no-referrer-when-downgrade");
    // deny i-frames if not running in wordpress admin area
    $effect->header("X-Frame-Options", "sameorigin");
    $effect->header("X-Content-Type-Options", "nosniff");
    $effect->header("Referrer-Policy", "strict-origin-when-cross-origin");

    // only turn on the XSS auditor for older browsers
    if ($agent) {
        if (($agent->browser == "chrome" && version_compare($agent->ver, "78.0") < 0)
            || ($agent->browser == "edge" && version_compare($agent->ver, "17.0") < 0)
            || ($agent->browser == "explorer") || ($agent->browser == "safari")) {

            $effect->header("X-XSS-Protection", ": 1; mode=block");
            trace("oldbr");
        }
    }
    
    return $effect;
}

/**
 * force redirect to https and enable STS
 * @return Effect 
 */
function force_ssl_with_sts() : Effect {
    $effect = Effect::new();
    $effect->header("Strict-Transport-Security", "max-age=31536000; preload");
    // find the request scheme (ssl/tls?)
    $scheme = ($server["HTTP_X_FORWARDED_PROTO"]??$server["REQUEST_SCHEME"]??"http");
    // force encryption
    if ($scheme === "http") {
        $host = $_SERVER["HTTP_HOST"];
        $uri = $_SERVER["REQUEST_URI"];
        $effect->header("Location", "https://{$host}{$uri}");
        $effect->exit(true);
    }

    return $effect;
}
