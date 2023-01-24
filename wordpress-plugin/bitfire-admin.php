<?php
namespace BitFirePlugin;

use function BitFire\serve_advanced;
use function BitFire\serve_dashboard;
use function BitFire\serve_database;
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

use const BitFire\FILE_RW;
use const BitFire\FILE_W;
use const BitFire\WAF_INI;
use const BitFire\WAF_ROOT;
use const BitFire\WAF_SRC;
use const ThreadFin\DAY;

use function BitFireSvr\update_ini_value;
use function ThreadFin\array_filter_modify;
use function ThreadFin\contains;
use function ThreadFin\file_recurse;
use function ThreadFin\dbg;
use function ThreadFin\en_json;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\ends_with;
use function ThreadFin\error;
use function ThreadFin\get_hidden_file;
use function ThreadFin\partial as BINDL;
use function ThreadFin\partial;
use function ThreadFin\partial_right as BINDR;

// we should have attempted load 2x before here
// 1: for for auto load, 2: plugin load, if it didn't load, something is wrong
if (!defined("BitFire\\WAF_ROOT")) {
    die("BitFire did not load correctly.  Please re-install.");
}

// since this is an admin page, make sure we have the admin functions loaded
require_once \BitFire\WAF_SRC."dashboard.php";
require_once \BitFire\WAF_SRC."server.php";
require_once \BitFire\WAF_SRC."api.php";


/**
 * get the current locale setting
 * @return string 
 */
function find_locale() : string {
   return get_locale(); 
}


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
    return;
    require_once ABSPATH . "/wp-admin/includes/file.php";
    // sync all paths (make sure we stay up to date if WP_CONTENT_DIR is ever changed)
    $home = \get_home_path();
    if ($home != CFG::str("cms_root") && contains($home, doc_root())) {
        $e = update_ini_value("cms_root", \get_home_path())->run();
        debug("sync cms_root [%s] / [%s] - [%d] (%s)", \get_home_path(), CFG::str("cms_root"), $e->read_status(), $e->read_errors());
    }
    if (defined("WP_CONTENT_DIR") && \WP_CONTENT_DIR != CFG::str("cms_content_dir")) {
        $dir = (!contains(\WP_CONTENT_DIR, doc_root())) ? doc_root() . \WP_CONTENT_DIR : \WP_CONTENT_DIR;
        $e = update_ini_value("cms_content_dir", $dir)->run();
        debug("sync cms_content_dir [%s] / [%s] - [%d] (%s)", \WP_CONTENT_DIR, CFG::str("cms_content_dir"), $e->read_status(), $e->read_errors());
    }
    if (\content_url() != CFG::str("cms_content_url")) {
        update_ini_value("cms_content_url", \content_url())->run();
    }
    $wp_version = get_wordpress_version(CFG::str("cms_root"));
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
    // sync_paths();

    // the admin function to run
    // $page = filter_input(INPUT_GET, "BITFIRE_WP_PAGE", FILTER_SANITIZE_SPECIAL_CHARS);

    $rm_path = CFG::str("rm_bitfire");
    if ($rm_path) {
        // need
        debug("PURGE $rm_path");
        // remove old bitfire directory, if it exists
        // TODO: improve this....
        if (ends_with($rm_path, "bitfire") && !contains(ini_get("auto_prepend_file"), $rm_path)) { 
            if (file_exists($rm_path) && file_exists("{$rm_path}/startup.php")) {
                debug("EXEC PURGE $rm_path");
                file_recurse($rm_path, function($x) {
                    if (is_dir($x)) {
                        $r = chmod($x, 0775);
                    } else {
                        chmod($x, 0664);
                        unlink($x);
                    }
                });
                file_recurse($rm_path, function($x) {
                    if (is_dir($x)) { rmdir($x); }
                    else { unlink($x); } 
                });
                file_recurse($rm_path, function($x) {
                    if (is_dir($x)) { rmdir($x); }
                    else { unlink($x); } 
                });
                chmod($rm_path, 0775);
                unlink($rm_path);
                if (!file_exists($rm_path)) {
                    update_ini_value("rm_bitfire", "")->run();
                }
            }
        }
    }

    
    // serve the requested page
    // TODO: change this to a function map for settings to functions similar to API
    /*
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
    else if (strtolower($page) === "database") {
        serve_database();
    }
    // default to the basic dashboard
    else {
        serve_dashboard();
    }
    */
}


/**
 * Register a custom admin menu page.
 */
function bitfire_add_menu() {
    $alerts = create_plugin_alerts();
    $base_num = count($alerts);
    $title = ($base_num > 0) ? "Vulnerable Plugins, " : "";
    $base_num += (CFG::disabled("whitelist_enable") || CFG::disabled("require_full_browser")) ? 1 : 0;
    $title = ($base_num > 0) ? "Bot Blocking Disabled, " : "";
    //$base_num += (CFG::disabled("auto_start")) ? 1 : 0;
    //$title = ($base_num > 0) ? "Always On Disabled" : "";

    \add_menu_page(
        "BitFire Dashboard",
        "BitFire <span class='update-plugins count-$base_num' title='$title'><span class='plugin-count'>$base_num</span></span>",
        "manage_options",
        "bitfire",
        "\BitFire\serve_dashboard",
        "dashicons-shield",
        66
    );

    \add_submenu_page(
        "bitfire",
        "BitFire Bot Control",
        "Bot Control",
        "manage_options",
        "bitfire_botlist",
        "\BitFire\serve_bot_list",
        1
    );

    \add_submenu_page(
        "bitfire",
        "BitFire Settings",
        "Settings",
        "manage_options",
        "bitfire_settings",
        "\BitFire\serve_settings",
        2
    );
    
    \add_submenu_page(
        "bitfire",
        "BitFire Malware Scanner",
        "Malware Scan",
        "manage_options",
        "bitfire_malware",
        "\BitFire\serve_malware",
        3
    );  

    if (strlen(CFG::str("pro_key")) > 20) {
        \add_submenu_page(
            "bitfire",
            "BitFire PRO Settings",
            "Advanced Settings",
            "manage_options",
            "bitfire_advanced",
            "\BitFire\serve_advanced",
            4
        );  
    }

    \add_submenu_page(
        "bitfire",
        "BitFire Database", 
        "Database Recovery",
        "manage_options",
        "bitfire_database",
        "\BitFire\serve_database",
        10
    ); 

    \add_submenu_page(
        "bitfire",
        "BitFire Exceptions",
        "Rule Exceptions",
        "manage_options",
        "bitfire_exceptions",
        "\BitFire\serve_exceptions",
        6
    ); 

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

function bitfire_styles() {
    // ONLY ENQUEUE ON BITFIRE PAGES
    $page = filter_input(INPUT_GET, "BITFIRE_WP_PAGE", FILTER_SANITIZE_SPECIAL_CHARS);
    if (empty($page)) {
        $page = filter_input(INPUT_GET, "page", FILTER_SANITIZE_SPECIAL_CHARS);
        if (empty($page) || !contains($page, "bitfire")) {
            return;
        }
    }

    \wp_register_script("dashkit", plugin_dir_url(__FILE__) . "public/dashkit.min.js", ["jquery"], "1.0", true);
    \wp_register_script("dashkit-chart", plugin_dir_url(__FILE__) . "public/chart.min.js", ["jquery"], "1.0", true);
    \wp_register_script("dashkit-diff", plugin_dir_url(__FILE__) . "public/difflib.js", ["jquery"], "1.0", true);
    \wp_register_script("dashkit-prism", plugin_dir_url(__FILE__) . "public/prism.js", ["jquery"], "1.0", true);
    \wp_register_script("dashkit-internal", plugin_dir_url(__FILE__) . "public/internal.js", [], "1.0", false);
    \wp_register_script("dashkit-vendor", plugin_dir_url(__FILE__) . "public/vendor.bundle.js", ["jquery"], "1.0", true);
    \wp_register_script("dashkit-theme", plugin_dir_url(__FILE__) . "public/theme.bundle.js", ["jquery"], "1.0", true);
    \wp_register_script("dashkit-pako", plugin_dir_url(__FILE__) . "public/pako.js", [], "1.0", true);
    \wp_register_script("dashkit-underscore", plugin_dir_url(__FILE__) . "public/underscore.min.js", [], "1.0", false);
    \wp_register_style("dashkit-vs2015", plugin_dir_url(__FILE__) . "public/vs2015.min.css", [], "1.0");
    \wp_register_style("dashkit-prism", plugin_dir_url(__FILE__) . "public/prism.css", [], "1.0");
    //\wp_register_style("dashkit-theme", plugin_dir_url(__FILE__) . "public/theme.min.css", [], "1.0");
    \wp_register_style("dashkit-bundle", plugin_dir_url(__FILE__) . "public/theme.bundle.css", [], "1.0");
    \wp_register_style("dashkit-feather", plugin_dir_url(__FILE__) . "public/feather.css", [], "1.0");

    //\wp_register_script("underscore2", "/wp-includes/js/underscore.min.js", [], false, false);
    \wp_enqueue_script("dashkit-underscore", plugin_dir_url(__FILE__) . "public/underscore.min.js", "1.0", false);
    \wp_enqueue_script("dashkit-chart", plugin_dir_url(__FILE__) . "public/chart.min.js", ["jquery"], "1.0", false);
    \wp_enqueue_script("dashkit-vendor", plugin_dir_url(__FILE__) . "public/vendor.bundle.js", ["jquery"], "1.0", true);
    \wp_enqueue_script("dashkit-diff", plugin_dir_url(__FILE__) . "public/difflib.js", ["jquery"], "1.0", true);
    \wp_enqueue_script("dashkit-prism", plugin_dir_url(__FILE__) . "public/prism.js", ["jquery"], "1.0", true);
    \wp_enqueue_script("dashkit-internal", plugin_dir_url(__FILE__) . "public/internal.js", [], "1.0", false);
    \wp_enqueue_script("dashkit-pako", plugin_dir_url(__FILE__) . "public/pako.js", [], "1.0", true);
    \wp_enqueue_script("dashkit-theme", plugin_dir_url(__FILE__) . "public/theme.bundle.js", ["jquery"], "1.0", true);
    \wp_enqueue_script("dashkit", plugin_dir_url(__FILE__) . "public/dashkit.min.js", ["jquery"], "1.0", true);

    \wp_enqueue_style("dashkit-vs2015", plugin_dir_url(__FILE__) . "public/vs2015.min.css", [], "1.0");
    \wp_enqueue_style("dashkit-prism", plugin_dir_url(__FILE__) . "public/prism.css", [], "1.0");
    \wp_enqueue_style("dashkit-bundle", plugin_dir_url(__FILE__) . "public/theme.bundle.css", [], "1.0");
    \wp_enqueue_style("dashkit-feather", plugin_dir_url(__FILE__) . "public/feather.css", [], "1.0");
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
        debug("unable to edit user, no number given");
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

    $content_dir = CFG::str("cms_content_dir");
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
        // no plugins found?  odd...
        if (empty($plugins)) { return $result; }

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
            $result[] = "<style>.bf{height:0;line-height:0;padding:0;overflow:hidden;opacity:0;transition:all .5s ease-in-out;} .bf.open{padding:.5em;line-height:1.5;opacity:1;height:auto !important}</style>
            <strong>$name has a known security issue <a target='_blank' href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=$cve'>$cve</a></strong> <span style='padding-left:3rem'>Exploit difficulty: <em>".
            "{$difficulty}</em></span><br><hr>{$type}<span style='float:right;display:none;' class='dashicons dashicons-arrow-up' onclick='document.getElementById(\"bfslide{$cve}\").classList.toggle(\"open\")'></span><br><hr><div class='bf open' id='bfslide{$cve}'>{$info}<br><br>$links<a style='text-align:right;width:100%;display:block;margin-bottom:1rem;' href='{$self}cve_ignore=$cve' title='hide this alert for 1 day'>Dismiss Notice</a></div>";//, $plugin["plugin_name"]); 
        }
    }

    return $result;
}


/**
 * add admin notices for disabled configurations
 * @return void 
 */
function alerts() {
    // show the wizard alert if we are not setup and not on the wizard page...
    if (CFG::disabled("wizard") && strpos($_SERVER['REQUEST_URI'], "SETTINGS") < 1) {
        $url = admin_url("admin.php?page=bitfire_settings");
        show_alert("error", "BitFire setup is not complete.  Please <a href='$url'>run the setup wizard</a>.");
        return;
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
        $url = admin_url("admin.php?page=bitfire_settings#bot_handling");
        show_alert("warning", "<div style='display:flex;flex-direction:row;justify-content:space-between;'><span><a href='$url'>BitFire Settings</a> : Bot blocking is not fully enabled.  Please enable <strong>whitelist</strong> and <strong>full browser required</strong> to block hacking bots.</span> <a href='{$current_url}bitfire_nag_ignore=1'>&#10006; Dismiss</a></div>");
    }
    /*
    if (CFG::disabled("auto_start")) {
        $url = admin_url("admin.php?page=bitfire_settings");
        show_alert("warning", "<div style='display:flex;flex-direction:row;justify-content:space-between;'><span><a href='$url'>BitFire Settings</a> : <strong>Always-On protection</strong> needs to be enabled to prevent direct plugin attacks. </span> <a href='{$current_url}bitfire_nag_ignore=1'>&#10006; Dismiss</a></div>");
    }
    */
    if (strlen(CFG::str("pro_key")) > 20) {
        if (CFG::disabled("rasp_filesystem")) {
            $url = admin_url("admin.php?page=bitfire_advanced");
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



function upgrade($upgrade=null, $extra=null) {
    // restore the old configurations
    $old_config = CFG::str("cms_content_dir") . "/bitfire/config.ini";
    if (file_exists($old_config)) {
        @chmod(WAF_INI, FILE_RW);
        rename($old_config, WAF_INI);
    }
    $restore_list = glob(CFG::str("cms_content_dir") . "/bitfire/*");
    array_walk($restore_list, function($x) {
        $n = basename($x);
        chmod(WAF_ROOT."cache/$n", FILE_RW);
        rename($x, WAF_ROOT."cache/$x");
    });
    $dir_name = CFG::str("cms_content_dir") . "/bitfire";
    if (file_exists($dir_name)) {
        @chmod($dir_name, FILE_RW);
        @rmdir($dir_name);
    }
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
            "<a href='$edit_url'><span class='dashicons dashicons-yes' data-code='f12a'></span><span style='color:#181;text-decoration:underline' title='Click to edit the MFA telephone number'>Yes</span></a>&nbsp;&nbsp;&nbsp;<span style='color:#999'> ok: </span><strong>$correct</strong> / <strong>$sent</strong>"
            : "<a href='$edit_url'><span class='dashicons dashicons-no' data-code='f158'></span><span style='color:#181;text-decoration:underline' title='Click to edit the MFA telephone number'>No</span></a>";
            return $html;
    }
}

function dashboard_init() {
    wp_add_dashboard_widget('custom_help_widget', 'BitFire Security Notices', 'BitFirePlugin\dashboard_content');
}
 
/**
 * todo: rewrite with renderer
 * @return void 
 * @throws RuntimeException 
 * @throws Exception 
 */
function dashboard_content() {

    echo "<style> .bfslideup { height: 0px; transition: height 0.5s linear;} .bfslideup.open { height: auto; transition: height 0.5s linear;}</style>";

    $url = admin_url("admin.php?page=bitfire_malware");
    $malware_file = WAF_ROOT . "/cache/malware_files.json";
    $malware = FileData::new($malware_file);
    if ($malware->exists) {
        $malware_data = $malware->read()->un_json()->lines;
        $seconds = time() - $malware_data['time'];
        $days = floor($seconds / DAY);
        //malware_data also has "total" attribute
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
    $url = admin_url("admin.php?page=bitfire");
    $block_file = \ThreadFin\FileData::new(get_hidden_file("blocks.json"))
        ->read()
        ->map('\ThreadFin\un_json');
    $blocking_full = $block_file->lines;

    $check_day = time() - DAY;
    $block_24 = array_filter($blocking_full, function ($x) use ($check_day) {
        return isset($x['tv']) && $x['tv'] > $check_day;
    });
    $block_24_num = count($block_24);
    echo "<div style='border-left: 5px solid #36d638; padding-left: 1rem;'><span class='dashicons dashicons-shield'></span> Last 24 Hours # Blocked Attacks: <a href='$url' style='float:right'>$block_24_num</a></div>";
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


/** don't show the bitfire menus if the user is not an admin.. */
if (!is_admin()) {
    return;
}

//add_action("upgrader_process_complete", "\BitFirePlugin\upgrade");

add_action("admin_enqueue_scripts", "\BitFirePlugin\bitfire_styles");

// add the menu, 
\add_action("admin_menu", "BitFirePlugin\bitfire_add_menu");
add_action("admin_notices", "\BitFirePlugin\alerts");

add_action("activated_plugin", "BitFirePlugin\bitfire_plugin_check");
add_action("deactivated_plugin", "BitFirePlugin\bitfire_plugin_check");


// TODO: only show this if the user is on the edit user page
add_filter("manage_users_columns", "BitFirePlugin\user_columns");
add_filter('manage_users_custom_column', "BitFirePlugin\custom_columns", 10, 3);

// TODO: only show this if the user is on the dashboard page
add_action('wp_dashboard_setup', 'BitFirePlugin\dashboard_init');
  

// run the bitfire admin page code if we are showing the bitfire admin page
if (isset($_GET["page"])) {
    $parts = explode("_", $_GET["page"]);
    if ($parts[0] === "bitfire") {
        admin_init();
    }
}
