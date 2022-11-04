<?php
/**
 * The BitFire CMS bootstrap file.  This is used to load BitFire
 * from within the CMS system if not using the auto_prepend_file
 * method.  This is not the ideal setup, and does not provide
 * full protection, but is supported.
 *
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin if it has not started via auto_prepend_file.
 * 
 * Based on BitFire WordPress plugin uses the BitFire firewall library to 
 * perform all security functions.  This plugin integrates the WordPress admin
 * and plugin pages with the library API.  Source available at github, see 
 * link below
 *
 * @link              http://bitfire.co
 * @source            https://github.com/bitslip6/bitfire
 * @since             2.0
 * @package           BitFire
 */

namespace BitFirePlugin;

use BitFire\BitFire;
use BitFire\Config as CFG;
use BitFire\Request;
use Exception;
use RuntimeException;
use ThreadFin\Effect;

use const BitFire\APP;
use const BitFire\FILE_W;
use const BitFire\STATUS_EACCES;

use function ThreadFin\contains;
use function ThreadFin\partial as BINDL;
use function ThreadFin\trace;
use function ThreadFin\debug;
use function ThreadFin\en_json;
use function ThreadFin\httpp;

// If this file is called directly, abort.
if ( ! defined( "BitFire\WAF_ROOT" ) ) { die(); }


/**
 * @return string the full path to the dashboard page. Ideally this would
 * be loaded via the CMS plugin system.  but self loading via auto_prepend_file
 * is also supported bia the dashboard_path config.ini setting.
 * 
 * To use the BitFire loading method (runs before CMS start), return the 
 * config.ini dashboard_url here.
 * @since 1.9.0 
 */
function dashboard_url() : string {
    trace("dash_url");
    return "/some_admin_page.php?plugin=bitfire-plugin";
    return CFG::str("dashboard_path", "/bitfire_default_admin_page");
}

/**
 * UNCOMMENT IF YOU HAVE CMS AUTH INTEGRATION
 * 
 * This method will override the default authentication 
 * (basic auth, with sha3 hashed password in config.ini)
 * 
 * This method can perform any action required to authenticate the request
 * Performance is not a concern, since this method is only called on dashboard
 * page access.
 * @since 1.9.0
 */ 
/*
function is_admin() : bool {
    // This is the WordPress implementation:
    return \current_user_can("manage_options");
}
*/

/**
 * Called to verify dashboard authentication.  IF user is not authenticated,
 * return an effect to get them authenticated.
 * 
 * Leave commented out to use the default authentication.
 * 
 * @return \ThreadFin\Effect - an effect with the action to take if the user 
 * is not admin, or NULL effect if user is an admin.
 * @since 1.9.0
 */
function verify_admin_effect(Request $request) : Effect {
    trace("VAE");

    // unauthentiated users are allowd to use the send_mfa funtion
    if ($request->get["BITFIRE_API"]??"" == "send_mfa") {
        return Effect::$NULL;
    }

    // test the auth data with internal CMS function here
    if (function_exists('your_auth_function') && your_auth_function($_COOKIES['your_auth_token'])) {
        return Effect::$NULL;
    }


    // FAILED, do not pass go, do not serve the dashboard, redirect to login page
    return Effect::new()
        ->header("location", "https://mysite.com/login.php")
        ->exit(true);
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
        $effect->cookie(en_json($d, "custom-auth-effect"));
    }

    return $effect;
}




/**
 * This function returns the path to the cms root directory in case it is
 * different from DOCUMENT_ROOT
 * @since 1.9.1
 */
function find_cms_root() : string {
    // update to use your CMS root here 
    if (defined("MY_CMS_ROOT")) { return \MY_CMS_ROOT; }
    // fall back to config file if we are running in front of WordPress 
    $config_path = CFG::str("cms_root");
    if (file_exists($config_path)) { return $config_path; }

    return $_SERVER['DOCUMENT_ROOT']??"";
}

// helper wrapper for wp_enqueue_script
function add_script_src(string $handle, string $src, string $optional) : string {
    return "<script type='text/javascript' src='$src' $optional></script>";
}
// helper wrapper for wp_add_inline_script
function add_script_inline(string $handle, string $code) : string {
    return "<script type='text/javascript'>$code</script>";
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
    trace("cust");
}


/**
 * called when a CMS menu item for firewall administration is clicked
 * 
 * @return void 
 */
function bitfire_dashboard_hit() {
    trace("MENU");
    include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";
    \BitFirePlugin\admin_init();
}

/**
 * The code that runs during BitFire plugin activation.
 * enable the firewall enable option, and install always on protection
 * on second activation (this is by design and based on "configured" flag)
 * 
 * TODO: FORKED into server.php
 */
function activate_bitfire() {
    trace("ACTIVATE");
    include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";

    // install data can be verbose, so redirect to install log
    $debug_file = \BitFire\Config::str("debug_file");
    \BitFire\Config::set_value("debug_file", \BitFire\WAF_ROOT . "install.log");
    $effect = \BitfireSvr\bf_activation_effect();
    $effect->hide_output()->run();
    \BitFire\Config::set_value("debug_file", $debug_file);
    httpp(APP."zxf.php", base64_encode(\ThreadFin\en_json(["activate {$_SERVER['SERVER_NAME']}"])));

    @chmod(\BitFire\WAF_INI, FILE_W);
}

/**
 * The code that runs during plugin deactivation.
 * toggle the firewall enable option, uninstall
 */
function deactivate_bitfire() {
    trace("DEACTIVATE");
    include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";

    // install data can be verbose, so redirect to install log
    $debug_file = \BitFire\Config::str("debug_file");
    \BitFire\Config::set_value("debug_file", \BitFire\WAF_ROOT . "install.log");
    \BitFire\Config::set_value("debug_header", false);
    $effect = \BitFireSvr\bf_deactivation_effect();
    $effect->hide_output()->run();
    \BitFire\Config::set_value("debug_file", $debug_file);
    httpp(APP."zxf.php", \ThreadFin\en_json(["deactivate {$_SERVER['SERVER_NAME']}"]));

    @chmod(\BitFire\WAF_INI, FILE_W);
}


/**
 * Register a custom admin menu page.
 * Replace this with any code required to add a menu item to the CMS
 * 
 * WORDPRESS EXAMPLE FEATURED HERE:
 */
function bitfire_add_menu() {
    \add_menu_page(
        "BitFire Firewall",
        "BitFire Firewall",
        "manage_options",
        "bitfire_admin",
        "\BitFirePlugin\bitfire_admin_init",
        "dashicons-shield",
        66
    );
}


/**
 * render the MFA page and exit script execution
 * 
 * WORDPRESS EXAMPLE FEATURED HERE:
 * 
 * @param string $msg  - The note to display on the page
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
';

    wp_add_inline_script("bitfire_mfa_focus", "document.getElementById('bitfire_mfa').focus();");
    echo \login_header("MFA Code Required", "<p class='message'>$msg</p>");
    printf($content, 
        \wp_login_url(filter_input(INPUT_GET, "redirect_to", FILTER_SANITIZE_URL)),
        esc_attr($_POST["login"]),
        esc_attr($_POST["login"]),
        esc_attr($_POST["password"]),
        esc_attr($_POST["password"]),
        ($_REQUEST["rememberme"]??false) ? "checked" : "",
        esc_attr($_POST["redirect_to"]));
    echo \login_footer("bitfire_mfa");
}



/**
 * called on menu click
 * @return void 
 * @throws Exception 
 * @throws RuntimeException 
 */
function admin_init() {
    trace("admin init");

    // the admin function to run
    $page = filter_input(INPUT_GET, "BITFIRE_WP_PAGE", FILTER_SANITIZE_SPECIAL_CHARS);
    
    // serve the requested page
    // TODO: change this to a function map for settings to functions similar to API
    if (strtolower($page) == "settings") {
        \BitFire\serve_settings();
    }
    else if (strtolower($page) == "advanced") {
        \BitFire\serve_advanced();
    }
    else if (strtolower($page) == "malwarescan") {
        \BitFire\serve_malware();
    }
    else if (strtolower($page) == "exceptions") {
        \BitFire\serve_exceptions();
    }
    // default to the basic dashboard
    else {
        \BitFire\serve_dashboard();
    }
}



// we must do this here because by the time bitfire-admin.php loads, content has already been
// rendered.  Don't want to introduce dependency on WordPress with admin-ajax.php calls
function bitfire_init() {
    trace("init");
    
    // verify we have PRO MFA code available
    if (CFG::enabled("pro_mfa") && function_exists("\BitFirePRO\sms")) {
        trace("mfa");
        // add user edit field for mfa code here
        // WORDPRESS EXAMPLE FEATURED HERE:
        function mfa_field($user) { echo \BitFirePRO\wp_render_user_form($user); }
        add_action('show_user_profile', '\BitFirePlugin\mfa_field');

        // mfa field update on user save here
        add_action("edit_user_profile_update", "\BitFirePlugin\user_edit");
        add_action("personal_options_update", "\BitFirePlugin\user_edit");
        add_action("user_register", "\BitFirePlugin\user_edit");
    }

    // auth verification
    // LEAVE AS IS
    if (is_admin()) {
        trace("admin");
        include_once \plugin_dir_path(__FILE__) . "bitfire-admin.php";
        // make sure we have authentication correct
        bf_auth_effect()->run();
    }


    // we want to run API function calls here AFTER loading.
    // this ensures that all overrides are loaded before we run the API
    // LEAVE AS IS
    if (isset($_REQUEST[\BitFire\BITFIRE_COMMAND])) {
        trace("plugin_api");
        require_once \BitFire\WAF_SRC."server.php";
        require_once \BitFire\WAF_SRC."api.php";
        $request = \BitFire\BitFire::get_instance()->_request;
        \BitFire\api_call($request)->exit(true)->run();
    }


    // show the MFA form if we are on the login page and we are configured to use MFA
    // WORDPRESS EXAMPLE FEATURED HERE:
    if (CFG::enabled("pro_mfa") && function_exists("\BitFirePRO\wp_render_mfa_page")) {
        $path = BitFire::get_instance()->_request->path;
        if (contains($path, "wp-login.php")) {
            trace("wp_login");
            add_action("wp_authenticate", "\BitFirePRO\wp_user_login");
        }
    }
}


// add the menu, check for an API call
// WORDPRESS EXAMPLE HERE
\add_action("admin_menu", "BitFirePlugin\bitfire_add_menu");
\add_action("wp_loaded", "BitFirePlugin\bitfire_init");

\register_activation_hook(__FILE__, 'BitFirePlugin\activate_bitfire');
\register_deactivation_hook(__FILE__, 'BitFirePlugin\deactivate_bitfire');


// IMPLEMENT:
// FOREACH SCRIPT TAG ADD A NONCE="$nonce" ATTRIBUTE
// $nonce = CFG::str("csp_nonce");

