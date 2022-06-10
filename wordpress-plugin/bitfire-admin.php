<?php
namespace BitFirePlugin;

use function BitFire\serve_advanced;
use function BitFire\serve_dashboard;
use function BitFire\serve_malware;
use function BitFire\serve_settings;

use BitFire\BitFire;
use BitFire\Config as CFG;
use ThreadFin\Effect as Effect;

use function BitFireSvr\update_ini_value;
use function ThreadFin\en_json;
use function ThreadFin\trace;
use function ThreadFin\debug;

// we should have attempted load 2x before here
// 1: for for auto laod, 2: plugin load, if it didn't load, something is wrong
if (!defined("BitFire\\WAF_ROOT")) {
    die("BitFire did not load correctly.  Please re-install.");
}

// since this is an admin page, make sure we have the admin functions loaded
require_once \BitFire\WAF_SRC."dashboard.php";
require_once \BitFire\WAF_SRC."server.php";
require_once \BitFire\WAF_SRC."api.php";



/**
 * Create an effect to update the firewall admin status.  Admin functions require
 * an access token (like nonce), Basic Auth AND CMS admin status (if applicable)
 * 
 * This function should sync the bitfire cookie "wp" value with the current
 * admin status.
 * 
 * @return Effect 
 */
function bf_auth_effect() : Effect {
    if (!defined("BitFire\\WAF_ROOT")) { return Effect::$NULL; } // GUARD
    $c = BitFire::get_instance()->cookie;
    if (empty($c)) { return Effect::$NULL; } // GUARD

    // admin is 2, anything else is nothing
    $value = (\BitFirePlugin\is_admin()) ? 2 : 0;

    $effect = Effect::new();
    // the current admin status needs to be updated
    if ($c->extract("wp")() != $value) {
        // get the full current cookie value
        $d = $c->value("array");
        // update the wp admin status
        $d["wp"] = $value;
        // set the new cookie value
        $effect->cookie(en_json($d));
    }

    return $effect;
}



/**
 * handle the very rare case where administrator moves the wp-content url or directory
 * impure
 */
function sync_paths() : void {
    // sync all paths (make sure we stay up to date if WP_CONTENT_DIR is ever changed)
    if (\get_home_path() != CFG::str("wp_root")) {
        $e = update_ini_value("wp_root", \get_home_path())->run();
        debug("sync wp_root [%s] / [%s] - [%d] (%s)", \get_home_path(), CFG::str("wp_root"), $e->read_status(), $e->read_errors());
    }
    if (defined("WP_CONTENT_DIR") && \WP_CONTENT_DIR != CFG::str("wp_contentdir")) {
        update_ini_value("wp_contentdir", \WP_CONTENT_DIR)->run();
    }
    if (\content_url() != CFG::str("wp_contenturl")) {
        update_ini_value("wp_contenturl", \content_url())->run();
    }
}


/**
 * called on admin page load
 * 
 * 
 * THIS IS THE ADMIN MAIN
 * 
 */
function admin_init() {
    trace("admin init");

    // notify if wp-content dir changes...
    sync_paths();

    // the admin function to run
    $page = filter_input(INPUT_GET, "BITFIRE_WP_PAGE", FILTER_SANITIZE_SPECIAL_CHARS);

    
    // serve the requested page
    // TODO: change this to a function map for settings to functions similar to API
    if (strtolower($page) == "settings") {
        serve_settings();
    }
    else if (strtolower($page) == "advanced") {
        serve_advanced();
    }
    else if (strtolower($page) == "malwarescan") {
        serve_malware();
    }
    // default to the basic dashboard
    else {
        serve_dashboard();
    }
}


// TODO: this desn't seem to load with admin_enqueue_scripts...
function bitfire_styles() {
    \wp_enqueue_script("underscore", "/wp-includes/js/underscore.min.js");
}


function user_edit($user_id) {
    //print_r($_POST);
    $number = filter_input(INPUT_POST, "bitfire_mfa_tel", FILTER_SANITIZE_SPECIAL_CHARS);
    //dbg($number);
    if ($number) {
        $code = mt_rand(1, 9) . mt_rand(0, 9) . mt_rand(0, 9) . " " . mt_rand(1, 9) . mt_rand(0, 9) . mt_rand(0, 9);
        update_user_meta($user_id, "bitfire_mfa_code", $code);
        update_user_meta($user_id, "bitfire_mfa_tel", $number);
    }
}

