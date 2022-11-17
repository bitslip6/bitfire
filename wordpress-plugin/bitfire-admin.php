<?php
namespace BitFirePlugin;

use function BitFire\serve_advanced;
use function BitFire\serve_dashboard;
use function BitFire\serve_malware;
use function BitFire\serve_settings;
use function BitFire\serve_exceptions;
use function BitFireSvr\doc_root;
use function BitFireSvr\get_wordpress_version;

use BitFire\BitFire;
use BitFire\Config as CFG;
use Exception;
use RuntimeException;
use ThreadFin\Effect as Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;

use const BitFire\CONFIG_BLOCK_FILE;
use const BitFire\FILE_RW;
use const BitFire\FILE_W;
use const BitFire\WAF_INI;
use const BitFire\WAF_ROOT;
use const ThreadFin\DAY;

use function BitFireSvr\update_ini_value;
use function ThreadFin\array_filter_modify;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\en_json;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\ends_with;
use function ThreadFin\error;
use function ThreadFin\partial as BINDL;
use function ThreadFin\partial_right as BINDR;

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
    if (!$c || $c->empty()) {
        $cookie = en_json(["ip" => crc32($request->ip), "ua" => crc32($request->agent), 
            "et" => time() + DAY, "wp" => $a, "u" => $u, "x" => $x]);
        return $effect->cookie($cookie);
    }

    // always allow administrator IPs
    $ip = filter_input(INPUT_SERVER, CFG::str_up("ip_header", "REMOTE_ADDR"), FILTER_VALIDATE_IP);
    $block_file = \BitFire\BLOCK_DIR . DIRECTORY_SEPARATOR . $ip;
    if ($a && !file_exists($block_file)) {
        $effect->file(new FileMod($block_file, "allow",  FILE_RW, 0, true)); 
    }

    $d = $c->value("array");
    $updated = false;
    // the current admin status needs to be updated
    if ($c->extract("wp")->value('int') != $a) {
        $updated = true;
        $d["wp"] = $a;
    }
    if ($c->extract("u")->value('int') != $u) {
        $updated = true;
        $d["u"] = $u;
    }
    if ($c->extract("x")->value('int') != $x) {
        $updated = true;
        $d["x"] = $x;
    }
    if ($updated) {
       $effect->cookie(en_json($d));
    }

    // set the new cookie value
    return $effect;
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
        $dir = (!contains(\WP_CONTENT_DIR, doc_root())) ? doc_root() . \WP_CONTENT_DIR : \WP_CONTENT_DIR;
        $e = update_ini_value("wp_contentdir", $dir)->run();
        debug("sync wp_contentdir [%s] / [%s] - [%d] (%s)", \WP_CONTENT_DIR, CFG::str("wp_contentdir"), $e->read_status(), $e->read_errors());
    }
    if (\content_url() != CFG::str("wp_contenturl")) {
        update_ini_value("wp_contenturl", \content_url())->run();
    }
    $wp_version = get_wordpress_version(CFG::str("wp_root"));
    // update wordpress version
    if (CFG::str("wp_version") != $wp_version) {
        update_ini_value("wp_version", $wp_version)->run();
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

    $rm_path = CFG::str("rm_bitfire");
    if ($rm_path) {
        debug("PURGE $rm_path");
        // remove old bitfire directory, if it exists
        if (ends_with($rm_path, "bitfire") && !contains(ini_get("auto_prepend_file"), $rm_path)) { 
            debug("EXEC PURGE $rm_path");
            file_recurse($rm_path, BINDR("chmod", FILE_RW));
            //file_recurse($rm_path, "unlink");
            //unlink($rm_path);
        }
    }

    
    // serve the requested page
    // TODO: change this to a function map for settings to functions similar to API
    if (strtolower($page) === "settings") {
        serve_settings();
    }
    else if (strtolower($page) === "advanced") {
        serve_advanced();
    }
    else if (strtolower($page) === "malwarescan") {
        serve_malware();
    }
    else if (strtolower($page) === "exceptions") {
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

// TODO: this doesn't seem to load with admin_enqueue_scripts...
function bitfire_styles() {
    // ONLY ENQUEUE ON BITFIRE PAGES
    $page = filter_input(INPUT_GET, "BITFIRE_WP_PAGE", FILTER_SANITIZE_SPECIAL_CHARS);
    if (empty($page)) {
        $page = filter_input(INPUT_GET, "page", FILTER_SANITIZE_SPECIAL_CHARS);
        if (empty($page) || $page != "bitfire_admin") {
            return;
        }
    }

    \wp_register_script("dashkit", plugin_dir_url(__FILE__) . "public/dashkit.min.js", ["jquery"], "1.0", true);
    //\wp_register_script("dashkit-boot", plugin_dir_url(__FILE__) . "public/bootstrap.bundle.min.js", ["jquery"], "1.0", false);
    \wp_register_script("dashkit-chart", plugin_dir_url(__FILE__) . "public/chart.min.js", ["jquery"], "1.0", true);
    \wp_register_script("dashkit-diff", plugin_dir_url(__FILE__) . "public/difflib.js", ["jquery"], "1.0", true);
    \wp_register_script("dashkit-prism", plugin_dir_url(__FILE__) . "public/prism.js", ["jquery"], "1.0", true);
    \wp_register_script("dashkit-vendor", plugin_dir_url(__FILE__) . "public/vendor.bundle.js", ["jquery"], "1.0", true);
    \wp_register_script("dashkit-theme", plugin_dir_url(__FILE__) . "public/theme.bundle.js", ["jquery"], "1.0", true);
    \wp_register_script("dashkit-pako", plugin_dir_url(__FILE__) . "public/pako.js", [], "1.0", true);
    \wp_register_script("dashkit-underscore", plugin_dir_url(__FILE__) . "public/underscore.min.js", [], "1.0", false);
    \wp_register_script("dashkit-boot", plugin_dir_url(__FILE__) . "public/bootstrap.bundle.min.js", [], "1.0", true);
    \wp_register_style("dashkit-vs2015", plugin_dir_url(__FILE__) . "public/vs2015.min.css", [], "1.0");
    \wp_register_style("dashkit-prism", plugin_dir_url(__FILE__) . "public/prism.css", [], "1.0");
    \wp_register_style("dashkit-theme", plugin_dir_url(__FILE__) . "public/theme.min.css", [], "1.0");
    \wp_register_style("dashkit-bundle", plugin_dir_url(__FILE__) . "public/theme.bundle.css", [], "1.0");
    \wp_register_style("dashkit-feather", plugin_dir_url(__FILE__) . "public/feather.css", [], "1.0");

    //\wp_register_script("underscore2", "/wp-includes/js/underscore.min.js", [], false, false);
    \wp_enqueue_script("dashkit-underscore", plugin_dir_url(__FILE__) . "public/underscore.min.js", "1.0", false);
    \wp_enqueue_script("dashkit-chart", plugin_dir_url(__FILE__) . "public/chart.min.js", ["jquery"], "1.0", false);
    \wp_enqueue_script("dashkit-vendor", plugin_dir_url(__FILE__) . "public/vendor.bundle.js", ["jquery"], "1.0", true);
    \wp_enqueue_script("dashkit-diff", plugin_dir_url(__FILE__) . "public/difflib.js", ["jquery"], "1.0", true);
    \wp_enqueue_script("dashkit-prism", plugin_dir_url(__FILE__) . "public/prism.js", ["jquery"], "1.0", true);
    \wp_enqueue_script("dashkit-pako", plugin_dir_url(__FILE__) . "public/pako.js", [], "1.0", true);
    \wp_enqueue_script("dashkit-theme", plugin_dir_url(__FILE__) . "public/theme.bundle.js", ["jquery"], "1.0", true);
    \wp_enqueue_script("dashkit", plugin_dir_url(__FILE__) . "public/dashkit.min.js", ["jquery"], "1.0", true);
    \wp_enqueue_script("dashkit-boot", plugin_dir_url(__FILE__) . "public/bootstrap.bundle.min.js", array("jquery"), "1.0", true);

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
 * this function will also update the ignore cve data
 * @param bool $skip_ignored 
 * @return array 
 * @throws RuntimeException 
 * @throws Exception 
 */
function create_plugin_alerts($skip_ignored = true) : array {

    $result = [];

    $content_dir = CFG::str("wp_contentdir");
    if ($content_dir == "" && defined(WP_CONTENT_DIR)) {
        $content_dir = WP_CONTENT_DIR;
    }
    // fetch the list of plugins with security issues
    $cve_plugins_file = $content_dir."/plugins/bitfire/cache/plugins.json";
    if ($cve_plugins_file == "/plugins/bitfire/cache/plugins.json") {
        return $result;
    }
    $file_data = FileData::new($cve_plugins_file);

    if (!$file_data->exists) {
        bitfire_plugin_check();
    }
    if($file_data->exists) {
        $plugins = json_decode($file_data->read()->raw(), true);
        // update ignore data if user is an admin
        if (isset($_GET['cve_ignore']) && is_admin()) {
            $match_fn = function($key, $value) { return $value['cve'] == $_GET['cve_ignore']; };
            $plugins = array_filter_modify($plugins,
                $match_fn,
                function($key, $value) { $value['ignore'] = time() + \ThreadFin\DAY; return $value; }
            );
            $file_mod = new FileMod($cve_plugins_file, en_json($plugins), FILE_W);
            Effect::new()->file($file_mod)->run();
        }

        //global $wp;
        //$self = add_query_arg($wp->query_vars, home_url($wp->request));
        $self = preg_replace("/[?&]cve_ignore=[^&]*/", "", $_SERVER['REQUEST_URI']);
        $self .= (strpos($self, "?") === false ? "?" : "&");

        foreach ($plugins as $plugin) {
            $name = esc_html(strtolower($plugin["name"]));
            // skip if we have already ignored this plugin
            if ($skip_ignored && $plugin['ignore']??0 > time()) { continue; }

            if (strlen($plugin["vendor"])) {
                $vendor = esc_html(strtolower($plugin["vendor"]));
                $name = "<a href='/wp-admin/plugins.php#{$name}-update'>$name</a> by " . $vendor;
            }
            if (!strlen($name) > 3) { $name = esc_html(strtolower($plugin["plugin_name"]));}
            $cve = esc_html($plugin["cve"]??"unknown");


            $links = array_reduce(explode("\n", $plugin["links"]), function($carry, $item) {
                $item = esc_html($item);
                return $carry . " <a style='float:left' href='$item' target='_blank'>$item</a><br>";
            }, "");
            $difficulty = esc_html($plugin["difficulty"]??"unknown");
            $type = esc_html($plugin["cvss_type"]??"unknown");
            $info = esc_html($plugin["info"]??"unknown");
            $result[] = "<strong>$name has a known security issue <a target='_blank' href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=$cve'>$cve</a></strong> <span style='padding-left:3rem'>Exploit difficulty: <em>".
            "{$difficulty}</em></span><br><hr>{$type}<br><hr><!--span class='dashicons dashicons-arrow-up' onclick='document.getElementById(\"bfslide{$cve}\").classList.toggle(\"open\")'></span--><div class='' id='bfslide{$cve}'>{$info}<br><br>$links</div><a style='text-align:right;width:100%;display:block;margin-bottom:1rem;' href='{$self}cve_ignore=$cve' title='hide this alert for 1 day'>Dismiss Notice</a>";//, $plugin["plugin_name"]); 
        }
    }

    return $result;
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
    if (strpos($_SERVER['REQUEST_URI'], "plugins.php") > 1) {
       \ThreadFin\do_for_each(create_plugin_alerts(), BINDL("BitFirePlugin\show_alert", "error"));
    }

    
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
function show_alert(string $type, string $notice, string $id="") {
    if ($id != "") {
        echo "<div data-dismissible='$id-1' class='notice notice-{$type} is-dismissible'><p>{$notice}</p></div>\n";
    } else {
        echo "<div data-dismissible='disable-done-notice-forever' class='notice notice-{$type}'>{$notice}</div>\n";
    }
}

if (isset($_POST['action']) && isset($_POST['slug']) && $_POST['action'] == "update-plugin" && $_POST['slug'] == "bitfire") {
    \ThreadFin\file_recurse(WAF_ROOT, function($file) {
        $st = stat($file);
        $hex = dechex($st['mode']);
        $read = is_readable($file);
        $write = is_writable($file);
        if (!$read || !$write) {
            chmod($file, 0664);
        }
    });
    copy(WAF_INI, CFG::str("wp_contentdir") . "/bitfire.ini");
}

function upgrade($upgrade=null, $extra=null) {
    copy(CFG::str("wp_contentdir") . "/bitfire.ini", WAF_INI);
}

function user_columns($columns = []) {
    if (is_admin()) {
        $columns['bitfire_mfa'] = "BitFire MFA";
        $columns['bitfire_last_login'] = "BitFire Last Login";
    }
    return $columns;
}

//function custom_columns() {
function custom_columns($value = '', $column_name = '', $user_id = 0) {
    switch($column_name) {
        case "bitfire_last_login":
            $last_login = get_user_meta($user_id, "bitfire_last_login", true);
            $parts = explode(":", $last_login);
            if ($last_login) {
                //dbg($last_login);
                $days_ago = floor((time() - intval($parts[0])) / DAY);
                if ($days_ago > 365) { $days_ago = ">365"; }
                return "{$days_ago} days ago {$parts[5]}<br>" . join("/", array_slice($parts, 1, 4));
            } else {
                return "Never";
            }
            break;
        case "bitfire_mfa":
            $mfa = get_user_meta($user_id, "bitfire_mfa_tel", true);
            $correct = intval(get_user_meta($user_id, "bitfire_mfa_correct", true)||0);
            $sent = intval(get_user_meta($user_id, "bitfire_mfa_sent", true)||0);
            $edit_url = _wp_specialchars(get_admin_url() . "user-edit.php?user_id={$user_id}#bitfire_mfa", ENT_QUOTES);

            $html = ($mfa) ? 
            "<a href='$edit_url'><span class='dashicons dashicons-yes' data-code='f12a'></span><span style='color:#181;text-decoration:underline'>Yes</span></a>&nbsp;&nbsp;&nbsp;<span style='color:#999'> ok: </span><strong>$correct</strong> / <strong>$sent</strong>"
            : "<a href='$edit_url'><span class='dashicons dashicons-no' data-code='f158'></span><span style='color:#181;text-decoration:underline'>No</span></a>";
            return $html;
    }
}

add_action("upgrader_process_complete", "\BitFirePlugin\upgrade");

add_action("admin_enqueue_scripts", "\BitFirePlugin\bitfire_styles");
/*
add_action("wp_footer", function() { 
    //\wp_register_script("dashkit-underscore", plugin_dir_url(__FILE__) . "public/underscore.min.js", [], "1.0", true);
    echo "<script src='".plugin_dir_url(__FILE__) . "public/chart.min.js"."' type='text/javascript'></script>";
    echo "<script src='". plugin_dir_url(__FILE__) . "public/chart.min.js"."' type='text/javascript'></script>";
    echo "<script src='". plugin_dir_url(__FILE__) . "public/vendor.bundle.js"."' type='text/javascript'></script>";
    echo "<script src='". plugin_dir_url(__FILE__) . "public/difflib.js"."' type='text/javascript'></script>";
    echo "<script src='". plugin_dir_url(__FILE__) . "public/prism.js"."' type='text/javascript'></script>";
    echo "<script src='". plugin_dir_url(__FILE__) . "public/pako.js"."' type='text/javascript'></script>";
    echo "<script src='". plugin_dir_url(__FILE__) . "public/theme.bundle.js"."' type='text/javascript'></script>";
    echo "<script src='". plugin_dir_url(__FILE__) . "public/dashkit.min.js"."' type='text/javascript'></script>";
    echo "<script src='".plugin_dir_url(__FILE__) . "public/bootstrap.bundle.min.js"."' type='text/javascript'></script>";

    echo "<!-- BitFire wp_footer -->\n";
});
*/

add_action("admin_notices", "\BitFirePlugin\alerts");

add_action("activated_plugin", "BitFirePlugin\bitfire_plugin_check");
add_action("deactivated_plugin", "BitFirePlugin\bitfire_plugin_check");


add_filter("manage_users_columns", "BitFirePlugin\user_columns");
add_filter('manage_users_custom_column', "BitFirePlugin\custom_columns", 10, 3);

add_action('wp_dashboard_setup', 'BitFirePlugin\dashboard_init');
  
function dashboard_init() {
    wp_add_dashboard_widget('custom_help_widget', 'BitFire Security Notices', 'BitFirePlugin\dashboard_content');
}
 
function dashboard_content() {

    echo "<style> .bfslideup { height: 0px; transition: height 0.5s linear;} .bfslideup.open { height: auto; transition: height 0.5s linear;}</style>";

    $url = admin_url("admin.php?page=bitfire_admin&BITFIRE_WP_PAGE=MALWARESCAN");
    $malware_file = WAF_ROOT . "/cache/malware_files.json";
    $malware = FileData::new($malware_file);
    if ($malware->exists) {
        $malware_data = $malware->read()->un_json()->lines;
        $seconds = time() - $malware_data['time'];
        $days = floor($seconds / DAY);
        $malware_good = "#36d638";
        $malware_icon = "yes";
        if ($days > 14) {
            $malware_good = "#d63638";
            $malware_icon = "warning";
        }

        if ($malware_data['malware'] == 0) {
            echo "<div style='border-left: 5px solid $malware_good; padding-left: 1rem;'><span class='dashicons dashicons-yes'></span> Malware Scan: <a href='$url' style='float:right'>No malware detected</a></div>";
        } else {
            echo "<div style='border-left: 5px solid #d63638; padding-left: 1rem;'><span class='dashicons dashicons-warning'></span> Malware Scan: <a href='$url' style='float:right'>{$malware_data['malware']} possible malware files detected </a></div>";
        }
        echo "<div style='border-left: 5px solid $malware_good; padding-left:1rem'><span class='dashicons dashicons-$malware_icon'></span>Last scan time: <span style='float:right;'>$days days ago</span></div>";
    } else {
        echo "<div style='border-left: 5px solid #d63638; padding-left: 1rem;'>Malware Scan: <a href='$url' title='Run Malware Check'><strong>Never</strong></a></div>";
        echo "<div style='border-left: 5px solid #d63638; padding-left:1rem'><span class='dashicons dashicons-warning'></span>Last scan time: <span style='float:right;'>Never</span></div>";
    }
    echo "<br><hr><br>\n";


    // load all alert data
    $url = admin_url("admin.php?page=bitfire_admin&BITFIRE_WP_PAGE=DASHBOARD");
    $block_file = \ThreadFin\FileData::new(CFG::file(CONFIG_BLOCK_FILE))
        ->read()
        ->map('\ThreadFin\un_json');
    $blocking_full = $block_file->lines;

    $check_day = time() - DAY;
    $block_24 = array_filter($blocking_full, function ($x) use ($check_day) {
        return isset($x['tv']) && $x['tv'] > $check_day;
    });
    $block_24_num = count($block_24);
    echo "<div style='border-left: 5px solid #36d638; padding-left: 1rem;'><span class='dashicons dashicons-shield'></span> Last 24 Hour Blocked Attacks: <a href='$url' style='float:right'>$block_24_num</a></div>";
    echo "<br><hr><br>\n";


    $alerts = create_plugin_alerts(false);
    $num_alerts = count($alerts);
    if ($num_alerts > 0) {
        foreach ($alerts as $alert) {
            echo "<div style='border-left: 5px solid #d63638; padding-left: 1rem;'>
            <span class='dashicons dashicons-warning' data-code='f485'></span> {$alert}</div>\n";
        }
    } else {
        echo "<p>
        <span class='dashicons dashicons-plugins-checked' data-code='f485'></span>
        No Plugin Vulnerabilities Detected</p>";
    }
}