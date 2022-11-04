<?php
namespace BitFirePlugin;

use function BitFire\serve_advanced;
use function BitFire\serve_dashboard;
use function BitFire\serve_malware;
use function BitFire\serve_settings;
use function BitFire\serve_exceptions;
use function BitFireSvr\doc_root;

use BitFire\BitFire;
use BitFire\Config as CFG;
use RuntimeException;
use ThreadFin\Effect as Effect;
use ThreadFin\FileMod;

use const BitFire\FILE_RW;

use function BitFireSvr\update_ini_value;
use function ThreadFin\contains;
use function ThreadFin\en_json;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\error;

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
    $effect = Effect::new();
    $c = BitFire::get_instance()->cookie;
    $request = BitFire::get_instance()->_request;

    $x = (current_user_can("unfiltered_html")) ? 2 : 0;
    $u = (current_user_can("upload_files")) ? 2 : 0;
    $a = (\BitFirePlugin\is_admin()) ? 2 : 0;
    if (empty($c)) { 
        return $effect->cookie(en_json([
            "ip" => crc32($request->ip), "ua" => crc32($request->agent), 
            "et" => time() + 86400, "wp" => $a, "u" => $u, "x" => $x]));
    }

    // always allow administrator IPs
    if ($a) { 
        $ip = filter_input(INPUT_SERVER, CFG::str_up("ip_header", "REMOTE_ADDR"), FILTER_VALIDATE_IP);
        $block_file = \BitFire\BLOCK_DIR . DIRECTORY_SEPARATOR . $ip;
        $effect->file(new FileMod($block_file, "allow",  FILE_RW, 0, true)); 
    }

    $d = $c->value("array");
    // the current admin status needs to be updated
    if ($c->extract("wp")->value('int') != $a) {
        $d["wp"] = $a;
    }
    if ($c->extract("u")->value('int') != $u) {
        $d["u"] = $u;
    }
    if ($c->extract("x")->value('int') != $x) {
        $d["x"] = $x;
    }

    // set the new cookie value
    return $effect->cookie(en_json($d));
}



/**
 * handle the very rare case where administrator moves the wp-content url or directory
 * impure
 */
function sync_paths() : void {
    // sync all paths (make sure we stay up to date if WP_CONTENT_DIR is ever changed)
    $home = \get_home_path();
    if ($home != CFG::str("wp_root") && contains($home, doc_root())) {
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
    else if (strtolower($page) == "exceptions") {
        serve_exceptions();
    }
    // default to the basic dashboard
    else {
        serve_dashboard();
    }
}


// helper wrapper for wp_enqueue_script
function add_script_src(string $handle, string $src, string $optional) : string {
    if (contains($src, "https")) {
        \wp_enqueue_scripts($handle, $src, [], "1.0", true);
    }
    return "";
}
// helper wrapper for wp_add_inline_script
function add_script_inline(string $handle, string $code) : string {
    \wp_add_inline_script($handle, $code);
    return "";
}

// TODO: this desn't seem to load with admin_enqueue_scripts...
function bitfire_styles() {
    // ONLY ENQUEU ON BITFIRE PAGES
    $page = filter_input(INPUT_GET, "BITFIRE_WP_PAGE", FILTER_SANITIZE_SPECIAL_CHARS);
    if (empty($page)) {
        $page = filter_input(INPUT_GET, "page", FILTER_SANITIZE_SPECIAL_CHARS);
        if (empty($page) || $page != "bitfire_admin") {
            return;
        }
    }
    \wp_register_script("dashkit", plugin_dir_url(__FILE__) . "public/dashkit.min.js", ["jquery"], "1.0", false);
    //\wp_register_script("dashkit-boot", plugin_dir_url(__FILE__) . "public/bootstrap.bundle.min.js", ["jquery"], "1.0", false);
    \wp_register_script("dashkit-chart", plugin_dir_url(__FILE__) . "public/chart.min.js", ["jquery"], "1.0", false);
    \wp_register_script("dashkit-diff", plugin_dir_url(__FILE__) . "public/difflib.js", ["jquery"], "1.0", false);
    \wp_register_script("dashkit-prism", plugin_dir_url(__FILE__) . "public/prism.js", ["jquery"], "1.0", false);
    \wp_register_script("dashkit-vendor", plugin_dir_url(__FILE__) . "public/vendor.bundle.js", ["jquery"], "1.0", false);
    \wp_register_script("dashkit-theme", plugin_dir_url(__FILE__) . "public/theme.bundle.js", ["jquery"], "1.0", false);
    \wp_register_script("dashkit-pako", plugin_dir_url(__FILE__) . "public/pako.js", [], "1.0", false);
    \wp_register_script("dashkit-underscore", plugin_dir_url(__FILE__) . "public/underscore.min.js", [], "1.0", false);
    \wp_register_script("dashkit-boot", plugin_dir_url(__FILE__) . "public/bootstrap.bundle.min.js", [], "1.0", false);
    \wp_register_style("dashkit-vs2015", plugin_dir_url(__FILE__) . "public/vs2015.min.css", [], "1.0");
    \wp_register_style("dashkit-prism", plugin_dir_url(__FILE__) . "public/prism.css", [], "1.0");
    \wp_register_style("dashkit-theme", plugin_dir_url(__FILE__) . "public/theme.min.css", [], "1.0");
    \wp_register_style("dashkit-bundle", plugin_dir_url(__FILE__) . "public/theme.bundle.css", [], "1.0");
    \wp_register_style("dashkit-feather", plugin_dir_url(__FILE__) . "public/feather.css", [], "1.0");

    //\wp_register_script("underscore2", "/wp-includes/js/underscore.min.js", [], false, false);
    \wp_enqueue_script("dashkit-underscore");
    \wp_enqueue_script("dashkit-vendor", plugin_dir_url(__FILE__) . "public/vendor.bundle.js", ["jquery"], "1.0", false);
    \wp_enqueue_script("dashkit-chart", plugin_dir_url(__FILE__) . "public/chart.min.js", ["jquery"], "1.0", false);
    \wp_enqueue_script("dashkit-diff", plugin_dir_url(__FILE__) . "public/difflib.js", ["jquery"], "1.0", false);
    \wp_enqueue_script("dashkit-prism", plugin_dir_url(__FILE__) . "public/prism.js", ["jquery"], "1.0", false);
    \wp_enqueue_script("dashkit-pako", plugin_dir_url(__FILE__) . "public/pako.js", [], "1.0", false);
    \wp_enqueue_script("dashkit-theme", plugin_dir_url(__FILE__) . "public/theme.bundle.js", ["jquery"], "1.0", false);
    \wp_enqueue_script("dashkit", plugin_dir_url(__FILE__) . "public/dashkit.min.js", ["jquery"], "1.0", false);
    \wp_enqueue_script("dashkit-boot", plugin_dir_url(__FILE__) . "public/bootstrap.bundle.min.js", array("jquery"), "1.0", false);

    \wp_enqueue_style("dashkit-vs2015", plugin_dir_url(__FILE__) . "public/vs2015.min.css", [], "1.0");
    \wp_enqueue_style("dashkit-prism", plugin_dir_url(__FILE__) . "public/prism.css", [], "1.0");
    \wp_enqueue_style("dashkit-theme", plugin_dir_url(__FILE__) . "public/theme.min.css", [], "1.0");
    \wp_enqueue_style("dashkit-bundle", plugin_dir_url(__FILE__) . "public/theme.bundle.css", [], "1.0");
    \wp_enqueue_style("dashkit-feather", plugin_dir_url(__FILE__) . "public/feather.css", [], "1.0");
}

function user_has_role($user_id, $role_name) {
    $user_meta = get_userdata($user_id);
    $user_roles = $user_meta->roles;
    return in_array($role_name, $user_roles);
}


/**
 * when a new admin user id added, set the mfa number to the current user until is is updated
 * @param mixed $user_id 
 * @return void 
 */
function user_add($user_id) {
    if (user_has_role($user_id, "Super Admin") || user_has_role($user_id, "Administrator")) {
        $my_id = get_current_user_id();
        $tel = get_user_meta($my_id, "bitfire_mfa_tel");
        user_edit($user_id, $tel);
    }
}

/**
 * called on user edit to update the mfa number
 * @param mixed $user_id - user id to update
 * @param int $number - will pull from post data if default or 0
 */
function user_edit($user_id, $number = 0) {
    if ($number == 0) {
        $number = filter_input(INPUT_POST, "bitfire_mfa_tel", FILTER_SANITIZE_SPECIAL_CHARS);
    }
    if ($number) {
        $code = mt_rand(1, 9) . mt_rand(0, 9) . mt_rand(0, 9) . " " . mt_rand(1, 9) . mt_rand(0, 9) . mt_rand(0, 9);
        update_user_meta($user_id, "bitfire_mfa_code", $code);
        update_user_meta($user_id, "bitfire_mfa_tel", $number);
    } else {
        error("unable to edit user, no number given");
    }
}

/**
 * add admin notices for unenabled configurations
 * @return void 
 */
function alerts() {
    // show the wizard alert if we are not setup and not on the wizard page...
    if (CFG::disabled("wizard") && strpos($_SERVER['REQUEST_URI'], "SETTINGS") < 1) {
        $url = admin_url("admin.php?page=bitfire_admin&BITFIRE_WP_PAGE=SETTINGS");
        show_alert("error", "BitFire setup is not complete.  Please <a href='$url'>run the setup wizard</a>.");
    }

    // permanently disable nag messages  
    if (isset($_GET['bitfire_nag_ignore'])) { \BitFireSvr\update_ini_value("nag_ignore", "true")->run(); return; }

    // honor disable nag notices
    if (defined("DISABLE_NAG_NOTICES") && DISABLE_NAG_NOTICES) { return; }
    // notice has been dismissed
    if (CFG::enabled("nag_ignore")) { return; }

    $current_url = filter_input(INPUT_SERVER, "REQUEST_URI", FILTER_SANITIZE_SPECIAL_CHARS);
    $current_url .= (strpos($current_url, "?") > 1) ? "&" : "?";

    // show some nag notices for important settings
    if (CFG::disabled("whitelist_enable") || CFG::disabled("require_full_browser")) {
        $url = admin_url("admin.php?page=bitfire_admin&BITFIRE_WP_PAGE=SETTINGS#bot_handling");
        show_alert("warning", "<div style='display:flex;flex-direction:row;justify-content:space-between;'><span><a href='$url'>BitFire Settings</a> : Bot blocking is not fully enabled.  Please enable <strong>whitelist</strong> and <strong>full browser required</strong> to block hacking bots.</span> <a href='{$current_url}bitfire_nag_ignore=1'>&#10006; Dismiss</a></div>");
    }
    if (CFG::disabled("auto_start")) {
        $url = admin_url("admin.php?page=bitfire_admin&BITFIRE_WP_PAGE=SETTINGS");
        show_alert("warning", "<div style='display:flex;flex-direction:row;justify-content:space-between;'><span><a href='$url'>BitFire Settings</a> : <strong>Always-On protection</strong> needs to be enabled to prevent direct plugin attacks. </span> <a href='{$current_url}bitfire_nag_ignore=1'>&#10006; Dismiss</a></div>");
    }
    if (strlen(CFG::str("pro_key")) > 20) {
        if (CFG::disabled("site_lock")) {
            $url = admin_url("admin.php?page=bitfire_admin&BITFIRE_WP_PAGE=ADVANCED");
            //show_alert("warning", "BitFire File Lock is purchased but disabled.  Please enable in BitFire Advanced Settings");
            show_alert("warning", "<div style='display:flex;flex-direction:row;justify-content:space-between;'><span><a href='$url'>BitFire Advanced</a> : BitFire File Lock is purchased but disabled.  Please enable in BitFire Advanced Settings. </span> <a href='{$current_url}bitfire_nag_ignore=1'>&#10006; Dismiss</a></div>");
        }
    }
}

/**
 * echo an alert
 * @param string $type  (warning|error|success|info)
 * @param string $notice 
 */
function show_alert(string $type, string $notice) {
    echo "<div class='notice notice-{$type}'>{$notice}</div>\n";
}

add_action("admin_enqueue_scripts", "\BitFirePlugin\bitfire_styles");

add_action("admin_notices", "\BitFirePlugin\alerts");
//\wp_enqueue_script("bootstrap", \get_template_directory_uri() . "/js/bootstrap.min.js", array("jquery"), "20220601", true);
