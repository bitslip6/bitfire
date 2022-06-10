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
 * Version:           1.9.4
 * Author:            BitFire.co
 * License:           AGPL-3.0+
 * License URI:       https://www.gnu.org/licenses/agpl-3.0.en.html
 * Text Domain:       BitFire-Security
 * Domain Path:       /bitfire
 */

namespace BitFirePlugin;

use BitFire\BitFire;
use BitFire\Config as CFG;
use BitFire\Request;
use RuntimeException;
use ThreadFin\Effect;

use const BitFire\FILE_W;
use const BitFire\STATUS_EACCES;

use function ThreadFin\contains;
use function ThreadFin\partial as BINDL;
use function ThreadFin\trace;
use function ThreadFin\debug;

// If this file is called directly, abort.
if ( ! defined( "WPINC" ) ) { die(); }


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
    // prefeer code
    if (function_exists('get_home_path')) { return \get_home_path(); }
    // then constant
    if (defined("ABSPATH")) { return ABSPATH; }
    // fall back to config file if we are running in front of WordPress 
    // could be dead code here...
    $cfgpath = CFG::str("wp_root");
    if (file_exists($cfgpath)) { return $cfgpath; }

    return null;
}

/*
function script_tag(string $src) : string {
    return "<script src='$src'></script>";
}
*/


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
    // install data can be verbose, so redirect to install log
    \BitFire\Config::set_value("debug_file", \BitFire\WAF_ROOT . "install.log");
    \BitFire\Config::set_value("debug_header", false);
    include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";
    $effect = \BitfireSvr\bf_activation_effect()->hide_output()->run();
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

    echo \login_header("MFA Code Required", "<p class='message'>$msg</p>");
    printf($content, 
        \wp_login_url(filter_input(INPUT_GET, "redirect_to", FILTER_SANITIZE_URL)),
        esc_attr($_POST["log"]),
        esc_attr($_POST["log"]),
        esc_attr($_POST["pwd"]),
        esc_attr($_POST["pwd"]),
        ($_REQUEST["rememberme"]??false) ? "checked" : "",
        esc_attr($_POST["redirect_to"]));
    echo \login_footer("bitfire_mfa");
}


// we must do this here because by the time bitfire-admin.php loads, content has already been
// rendered.  Don't want to introduce dependency on WordPress with admin-ajax.php calls
function bitfire_init() {
    trace("init");
    if (current_user_can("manage_options")) {
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

// add the menu, check for an API call
\add_action("admin_menu", "BitFirePlugin\bitfire_add_menu");
// want to use init here, but that runs AFTER headers are sent.  *sigh*
\add_action("wp_loaded", "BitFirePlugin\bitfire_init");

\register_activation_hook(__FILE__, 'BitFirePlugin\activate_bitfire');
\register_deactivation_hook(__FILE__, 'BitFirePlugin\deactivate_bitfire');


/**
 * Add CSP Policy nonce if enabled
 * @param string $nonce 
 * @param null|string $script_tag 
 * @return string 
 */
function add_nonce(string $nonce, ?string $script_tag) : string {
    assert(!empty($script_tag), "cant add nonce to empty script tag");
    return preg_replace("/(id\s*=\s*[\"'].*?[\"'])/", "$1 nonce='$nonce'", $script_tag);
}
function scripter(string $nonce, &$scripter) {
    $clazz = get_class($scripter);
    $prop = new \ReflectionProperty($clazz, 'type_attr');
    $prop->setAccessible(true);
    $v = $prop->getValue($scripter);
    $prop->setValue($scripter, "$v nonce='$nonce'");
    //print_r($scripter);
    //dbg($prop);
    //$secret = $myClassReflection->getProperty('type_attr');
    //$v = $secret->type_attr;
    //echo "type: {$v} : \n";;
    //dbg($secret);
    //die();
}

if (CFG::enabled("csp_policy_enabled")) {
    $nonce = CFG::str("csp_nonce");
    add_action("script_loader_tag", BINDL("\BitFirePlugin\add_nonce", $nonce));
    add_action("wp_default_scripts", BINDL("\BitFirePlugin\scripter", $nonce));
}

