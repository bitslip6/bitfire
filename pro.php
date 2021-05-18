<?php
namespace BitFirePRO;

use function TF\file_replace;

class CSPBlock {
    public $uri;
    public $directive;
    public function __construct(string $uri, string $directive) {
        $this->uri = $uri;
        $this->directive = $directive;
    }
}

function strip_to_domain(string $uri) {
    if (preg_match('@^(?:http://)?([^/]+)@i', $uri, $matches)) {
        $host = $matches[1];

        if (preg_match('/[^.]+\.[^.]+$/', $host, $matches)) {
            return $matches[0];
        }
    }
    
    return "'self'";
}

function parse_pro_csp(string $csp_report) : CSPBlock {
    $report = \TF\un_json($csp_report);
    return new CSPBlock(strip_to_domain($report['blocked-uri']??''), $report['violated-directive']??'default-src');
}

function update_csp_config(CSPBlock $cspblock, array $csp_config) : array {
    // split up each domain element from the config
    $elements = explode(" ", $csp_config[$cspblock->directive]);
    // remove csp block element if it exists in the list;
    $new_list = array_filter($elements, function($element) use ($cspblock) {
        return \TF\ends_with($element, $cspblock->uri);
    });
    // if the element exists in the list (new_list is shorter because matching item was removed) return original list
    if (count($new_list) < count($elements)) { return $csp_config; }
    // return the list with *. appended to it
    $new_list[] = "*." . $cspblock->uri;
    return $new_list;
}

function update_csp_config_file(string $config_json) : void {
    $block = parse_pro_csp($config_json);
    
    $config = update_csp_config($block, \BitFire\Config::$_options['csp_policy']??array());
    
    \TF\file_replace(WAF_DIR . "cache/config.ini", \BitFire\config::$_options['csp_policy'][$block->directive], $config[$block->directive]);
}


function send_pro_headers(\BitFire\Request $request) : void {
    // set a default feature policy
    if (\BitFire\Config::enabled("feature_policy_enabled")) {

        $policy = array('geolocation' => '', 'midi' => '', 'notifications' => '', 'push' => '', 'sync-xhr' => '', 'microphone' => '', 'gyroscope' => '', 'speaker' => '', 'vibrate' => '', 'fullscreen' => '', 'payment' => '');
        foreach(\BitFire\Config::arr("allowed_features") as $feature => $value) {
            $policy[$feature] = $value;
        }
        header(\TF\map_reduce($policy, function($key, $value, $carry) {
                return  $carry . $key . "=('$value'), ";
            }, "Permissions-Policy: ") );
    }

    // set a default feature policy
    if (\BitFire\Config::enabled("csp_policy_enabled")) {

        $policy = array();
        foreach(\BitFire\Config::arr("csp_policy") as $policy_name => $value) {
            /*
            if ($policy_name == "script-src") {
                $policy[$policy_name] =  " 'nonce-" . \BitFire\Config::nonce(). "' 'unsafe-inline' $value";
            } else {
                $policy[$policy_name] = $value;
            }
            */
            $policy[$policy_name] = $value;
        }
        header(\TF\map_reduce($policy, function($key, $value, $carry) {
                return  "$carry $key $value; ";
            }, "Content-Security-Policy: upgrade-insecure-requests; default-src 'self' " . \BitFire\Config::str('csp_default', 'self') . "; ") . ' report-uri https://www.bitslip6.com/csp/_doc; report-to bitfire');
    }
}

function send_pro_mfa(\BitFire\Request $request) {
    if (\BitFire\Config::enabled(\BitFire\CONFIG_MFA_PATH) && \BitFire\Config::int(\BitFire\CONFIG_MFA_NUMBER, 0) != 0) {
        die("pro mfa");
        if ($_GET['_bf_code'] ?? false !== false) {
            $check = \TF\decrypt_ssl(\BitFire\Config::str(\BitFire\CONFIG_SECRET, 'default_secret'), $_COOKIE['_bf_code']);
            if ($_GET['_bf_code'] === $check()) { return; }
            $message = "invalid code: {$_GET['_bf_code']} expected: $check";
        }
        if (in_array($request->path, \BitFire\Config::arr(\BitFire\CONFIG_MFA_PATH))) {
            \mt_srand(time());
            $code = (string)\mt_rand(100000, 999999);
            \TF\cookie("_bf_code", \TF\encrypt_ssl(\BitFire\Config::str(\BitFire\CONFIG_SECRET, 'default_secret'), $code), 120);
            \TF\bit_http_request("GET", "https://www.bitslip6.com/mfa?auth=".\BitFire\Config::str("pro_key")."&code={$code}&number=".\BitFire\Config::str("mfa_phone_number"), '');
            include "views/sms.html";
            exit;
        }
    }
}
