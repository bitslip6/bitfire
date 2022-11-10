<?php
/**
 * The BitFire Wordpress bootstrap file
 *
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin if it has not started via auto_prepend_file.
 * 
 * This WordPress plugin uses the BitFire firewall library to perform all
 * security functions.  This plugin integrates the WordPress admin and plugin
 * pages with the library API.  Source available at github, see link below
 *
 * @link              http://bitfire.co
 * @source            https://github.com/bitslip6/bitfire
 * @since             1.8.0
 * @package           BitFire
 *
 * @wordpress-plugin
 * Plugin Name:       BitFire
 * Plugin URI:        https://bitfire.co/
 * Description:       Free/Premium WordPress Security - 100% refund guarantee. Lock files from attack, recover from malware, IP/Country ban, 100% bot protection - SEO compatible.
 * Version:           __VERSION__
 * Author:            BitFire.co
 * License:           AGPL-3.0+
 * License URI:       https://www.gnu.org/licenses/agpl-3.0.en.html
 * Text Domain:       BitFire-Security
 * Domain Path:       /bitfire
 */

namespace BitFirePlugin;

use BitFire\BitFire;
use BitFire\Config as CFG;
use BitFire\MatchType;
use BitFire\Request;
use Exception;
use RuntimeException;
use ThreadFin\Effect;

use const BitFire\CONFIG_REQUIRE_BROWSER;
use const BitFire\CONFIG_USER_TRACK_COOKIE;
use const BitFire\FILE_W;
use const BitFire\STATUS_EACCES;
use const ThreadFin\ENCODE_RAW;

use function BitFire\verify_browser_effect;
use function BitFireBot\send_browser_verification;
use function BitFirePRO\wp_requirement_check;
use function BitFireSvr\bf_deactivation_effect;
use function BitFireSvr\doc_root;
use function BitFireSvr\update_ini_value;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\partial as BINDL;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\do_for_each;
use function ThreadFin\file_recurse;

// If this file is called directly, abort.
if ( ! defined( "WPINC" ) ) { die(); }
if (defined("BitFire\TYPE") && \BitFire\TYPE == "STANDALONE") { 
    require_once \BitFire\WAF_SRC."server.php";
    $effect = \BitFireSvr\uninstall()->hide_output();
    $effect->run();

}

/**
 * @OVERRIDE dashboard url
 * @since 1.9.0 
 */
function dashboard_url() : string {
    trace("wpself");
    return \admin_url("admin.php?page=bitfire_admin");
}

/**
 * @OVERRIDE the default authentication function
 * @since 1.9.0
 */ 
function is_admin() : bool {
    return \current_user_can("manage_options");
}

function is_author() : bool {
    return \current_user_can("edit_posts");
}

/**
 * create effect with error action if user is not admin
 * @since 1.9.0
 */
function verify_admin_effect(Request $request) : Effect {
    trace("va");
    return ($request->get["BITFIRE_API"]??"" == "send_mfa") || (is_admin())  
        ? Effect::$NULL
        : Effect::new()->exit(true, STATUS_EACCES, "requires admin access");
}

/**
 * @OVERRIDE for cms_root() function
 * @since 1.9.1
 */
function find_cms_root() : ?string {
    // prefer code
    if (function_exists('get_home_path')) { trace("HOMEPATH"); $root = \get_home_path(); }
    // then constant
    if (defined("ABSPATH")) { trace("ABSPATH"); $root = ABSPATH; }
    // fall back to config file if we are running in front of WordPress 
    // could be dead code here...
    $cfg_path = CFG::str("wp_root");
    if (contains($cfg_path, $_SERVER["DOCUMENT_ROOT"]) && file_exists("$cfg_path/wp-config.php")) { trace("CFGPATH"); return $cfg_path; }
    $files = file_recurse($_SERVER["DOCUMENT_ROOT"], function($path) {
        if (file_exists($path)) {
            trace("FINDPATH");
            return dirname($path);
        }
    }, "/wp-config.php/", [], 1);
    debug("files [%s]", print_r($files, true));

    if (isset($files[0]) && file_exists($files[0])) {
        trace("UPDATEPATH");
        update_ini_value("wp_root", $files[0])->run();
        return $files[0];
    }

    return doc_root();
}


/**
 * Begins BitFire firewall, respects bitfire_enabled flag in config.ini
 * We might have already run the firewall if we are auto_prepend, so
 * check if we have loaded and do not double load.  This check
 * is also done in startup.php as a failsafe
 * @since    1.8.0
 */
if (!defined("BitFire\WAF_ROOT")) {
    $f =  __DIR__ . "/startup.php";
    if (file_exists($f)) {
        include_once $f;
    }
    trace("wp");
}

function query_filter(string $query) : string {
    /*
    $q = strtolower($query);
    $p = explode("where", $q);
    if (!$p || count($p) < 0) {
        $p = explode("values", $q);
    }

    $key = crc32($p[0])??0;
    $value = crc32($p[1])??00;
    $len = strlen($p[1])??00;
    debug("SQL [%s] (%d/%d/%d)" , $query, $key, $value, $len);
    */
    return $query;
}

/**
 * called when left nav menu is clicked
 * @return void 
 * @throws RuntimeException 
 */
function bitfire_menu_hit() {
    trace("wp_menu");
    include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";
    \BitFirePlugin\admin_init();
}

/**
 * The code that runs during plugin activation.
 * enable the firewall enable option, and install always on protection
 * on second activation (this is by design and based on "configured" flag)
 */
function activate_bitfire() {
    trace("wp_act");
    ob_start(function($x) { if(!empty($x)) { debug("PHP Warnings: [%s]\n", $x); } return $x; });

    // install data can be verbose, so redirect to install log
    \BitFire\Config::set_value("debug_file", \BitFire\WAF_ROOT . "install.log");
    \BitFire\Config::set_value("debug_header", false);
    include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";
    $effect = \BitfireSvr\bf_activation_effect()->hide_output()->run();
    debug(trace());
    @chmod(\BitFire\WAF_INI, FILE_W);
}

/**
 * The code that runs during plugin deactivation.
 * toggle the firewall enable option, uninstall
 */
function deactivate_bitfire() {
    trace("wp_deact");
    // install data can be verbose, so redirect to install log
    \BitFire\Config::set_value("debug_file", \BitFire\WAF_ROOT . "install.log");
    \BitFire\Config::set_value("debug_header", false);
    include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";
    \BitFireSvr\bf_deactivation_effect()->hide_output()->run();
    debug(trace());
    @chmod(\BitFire\WAF_INI, FILE_W);
}

/**
 * The code that runs during plugin deactivation.
    @chmod(\BitFire\WAF_INI, FILE_W);
}


/**
 * Register a custom admin menu page.
 */
function bitfire_add_menu() {
    \add_menu_page(
        "BitFire Firewall",
        "BitFire Firewall",
        "manage_options",
        "bitfire_admin",
        "\BitFirePlugin\bitfire_menu_hit",
        "dashicons-shield",
        66
    );
}

/**
 * render the MFA page and exit script execution
 * @param string $msg 
 * @return void 
 */
function render_mfa_page($msg = "Please enter the access code just sent to the address on record.") {
    $content = '
    <form name="loginform" id="loginform" action="%s" method="post">
        <p>
            <label for="user_login">Enter the Access Code just sent to the address on record</label>
            <input type="text" name="log" id="user_login" class="input" value="%s" size="20" autocapitalize="off" autocomplete="off" disabled="disabled" />
            <input type="hidden" name="log" id="user_login" class="input" value="%s" size="20" autocapitalize="off" autocomplete="off" />
        </p>

        <div class="user-pass-wrap">
            <label for="user_pass">Password</label>
            <div class="wp-pwd">
                <input type="password" name="pwd" id="user_pass" class="input password-input" value="%s" size="20" autocomplete="off" disabled="disabled" />
                <input type="hidden" name="pwd" id="user_pass" class="input password-input" value="%s" size="20" autocomplete="off" />
            </div>
        </div>
        <hr>
<div class="user-mfa-wrap">
<label for="user_mfa">Access Code</label>
<div class="wp-mfa">
    <input type="number" name="bitfire_mfa" id="bitfire_mfa" class="input" value="" size="6" autocomplete="off" />
</div>
</div>
		<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever" %s /> <label for="rememberme">Remember Me</label></p>
        <p class="submit">
            <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
                                <input type="hidden" name="redirect_to" value="%s" />
                                <input type="hidden" name="testcookie" value="1" />
        </p>
    </form>
    <script type="text/javascript">document.getElementById("bitfire_mfa").focus();</script>
';


    \wp_add_inline_script("bitfire-mfa-focus", "document.getElementById(\"bitfire_mfa\").focus();");
    echo \login_header("MFA Code Required", "<p class='message'>".esc_html($msg)."</p>");
    printf($content, 
        \wp_login_url(
            esc_url($_GET["redirect_to"])),
            esc_attr($_POST["log"]),
            esc_attr($_POST["log"]),
            esc_attr($_POST["pwd"]),
            esc_attr($_POST["pwd"]),
            ($_REQUEST["rememberme"]??false) ? "checked" : "",
            esc_attr($_POST["redirect_to"]));
    echo \login_footer("bitfire_mfa");
}

/**
 * make a JavaScript browser challenge.  just the inline script content.
 * Effect contains, cache updates and script contents.
 * This function will set the encrypted JWT with the answer
 * @return Effect 
 * @throws Exception 
 */
function make_js_challenge_effect() : Effect {
    $ip_data  = BitFire::get_instance()->bot_filter->ip_data;
    $request  = BitFire::get_instance()->_request;
    $block_effect = send_browser_verification($ip_data, $request, false);

    // we must send the cookie here before the headers are sent...
    $cookie_effect = Effect::new()->cookie($block_effect->read_cookie(), "wp_make_challenge");
    $cookie_effect->run();

    // don't change the response code, cookie, exit or send cache headers
    $alert_effect = $block_effect->response_code(0)->exit(false)->cookie("", "wp_clear_challenge")->clear_headers();
    $alert_effect->out(wp_get_inline_script_tag($block_effect->read_out()), ENCODE_RAW, true);

    return $alert_effect;
}

// we must do this here because by the time bitfire-admin.php loads, content has already been
// rendered.  Don't want to introduce dependency on WordPress with admin-ajax.php calls
function bitfire_init() {
    trace("init");
    if (is_user_logged_in()) {
        trace("admin");
        include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";

        // make sure we have authentication correct
        bf_auth_effect()->run();
    }

    if (CFG::enabled("pro_mfa") && function_exists("\BitFirePRO\sms")) {
        trace("mfa");
        function mfa_field($user) { echo \BitFirePRO\wp_render_user_form($user); }
        // mfa field display
        add_action('show_user_profile', '\BitFirePlugin\mfa_field');
        // mfa field update
        add_action("edit_user_profile_update", "\BitFirePlugin\user_edit");
        add_action("personal_options_update", "\BitFirePlugin\user_edit");
        add_action("user_register", "\BitFirePlugin\user_add");
    }



    // we want to run API function calls here AFTER loading.
    // this ensures that all overrides are loaded before we run the API
    if (isset($_REQUEST[\BitFire\BITFIRE_COMMAND])) {
        trace("wp_api");
        require_once \BitFire\WAF_SRC."server.php";
        require_once \BitFire\WAF_SRC."api.php";
        $request = \BitFire\BitFire::get_instance()->_request;
        \BitFire\api_call($request)->exit(true)->run();
    }


    // show the MFA form if we are on the login page and we are configured to use MFA
    if (CFG::enabled("pro_mfa") && function_exists("\BitFirePRO\wp_render_mfa_page")) {
        $path = BitFire::get_instance()->_request->path;
        if (contains($path, "wp-login.php")) {
            trace("wp_login");
            add_action("wp_authenticate", "\BitFirePRO\wp_user_login");
        }
    }
}

/**
 * Add CSP Policy nonce if enabled
 * @param string $nonce 
 * @param null|string $script_tag 
 * @return string 
 */
function add_nonce(string $nonce, ?string $script_tag) : string {
    assert(!empty($script_tag), "cant add nonce to empty script tag");
    // only add the nonce if we don't have one
    if (!contains($script_tag, "nonce=")) {
        return preg_replace("/(id\s*=\s*[\"'].*?[\"'])/", "$1 nonce='$nonce'", $script_tag);
    }
    return $script_tag;
}
/**
 * wp_script_attribute filter for adding nonces.
 * TODO: add integrity check.  Needs an API callback to automatically store the hash integrity
 * @param string $nonce - the per page generated nonce
 * @param array $attributes the script attributes
 * @return array 
 */
function add_nonce_attr(string $nonce, array $attributes) : array {
    $attributes["nonce"] = $nonce;
    return $attributes;
}



/**
 * BEGIN MAIN PLUGIN CODE
 */


// add the menu, 
\add_action("admin_menu", "BitFirePlugin\bitfire_add_menu");
// plugin run once wordpress is loaded
\add_action("wp_loaded", "BitFirePlugin\bitfire_init");
// update logout function to remove our cookie as well
\add_action("wp_logout", function() { \ThreadFin\cookie(CFG::str(CONFIG_USER_TRACK_COOKIE), null, -1); });
// \add_filter("query", "BitFirePlugin\query_filter");
 

\register_activation_hook(__FILE__, 'BitFirePlugin\activate_bitfire');
\register_deactivation_hook(__FILE__, 'BitFirePlugin\deactivate_bitfire');

$i = BitFire::get_instance();
$r = $i->_request;
$br = $i->bot_filter->browser;

/**
 * if browser verification is in reporting mode, we need to append the JavaScript
 * and NOT block the request.
 */
if (!$br->bot && CFG::is_report(CONFIG_REQUIRE_BROWSER) && (CFG::enabled('cookies_enabled') || CFG::str("cache_type") != 'nop')) {

    if (isset($r->post['_bfxa'])) {
        $effect = verify_browser_effect($r, $i->bot_filter->ip_data, $i->cookie)->exit(true);
        $effect->run();
    }
    // don't challenge if the browser is already valid
    else if (!$br->valid) {

        debug("browser verification level [%d]", $br->valid);
        // effect contains the inline javascript and cache entry updates
        // run(print) the challenge effect at the bottom of the <body> tag
        add_action("wp_footer", function() { 
            // make the challenge and send the cookie here (before headers are sent)
            // this function will split up the normal blocking effect into two parts
            // the first cookie effect will be run here, the second will be run in the action
            make_js_challenge_effect()->run();
        });
    } else {
        add_action("wp_footer", function() {
            echo "<!-- browser verification passed -->\n";
        });
    }
}


if (CFG::enabled("csp_policy_enabled")) {
    $nonce = CFG::str("csp_nonce", random_str(16));
    // script nonces. Prefer new attribute style for >= 5.7
    if (version_compare($GLOBALS["wp_version"]??"4.0", "5.7") >= 0) {
        add_filter("wp_script_attributes", BINDL("\BitFirePlugin\add_nonce_attr", $nonce));
        add_filter("wp_inline_script_attributes", BINDL("\BitFirePlugin\add_nonce_attr", $nonce));
    }
}

// make sure important WordPress calls are legitimate 
// TODO: improve this by integrating to the main inspection engine
if (function_exists('BitFirePRO\wp_requirement_check') && !wp_requirement_check()) {
    $i = BitFire::get_instance();
    $request = $i->_request;

    BitFire::new_block(31001, "referer", $request->headers->referer, "new-user.php", 0);
    die("Invalid request");
}