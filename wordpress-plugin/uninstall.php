<?php

/**
 * Fired when BitFire is uninstalled.
 *
 * @link       http://bitfire.co
 * @since      1.0.0
 *
 * @package    bitfire
 */

use const BitFire\FILE_EX;

// If uninstall not called from WordPress, then exit.
if (! defined('WP_UNINSTALL_PLUGIN')) {
	exit;
}


if ($_REQUEST['slug'] === "bitfire") {


	// make sure the user has at least admin credentials
	if (function_exists("current_user_can") && !current_user_can("manage_options")) {
		die("Uninstalling requires administrative privledges.");
	}

	// uninstall any .htaccess file changes or user.ini changes we might have made, 
	// remove wordfence-waf.php if in emulation mode
	if (defined("\BitFire\WAF_ROOT")) {
		if (\BitFire\Config::enabled("bitfire_enabled")) { die("must disable plugin before uninstalling."); }
		// make sure all files are deletable...
		\TF\file_recurse(plugin_dir_path(__FILE__), \TF\partial_right('chmod', FILE_EX));
		$lock = \BitFire\WAF_ROOT . "uninstall_lock";
		if (file_exists($lock)) {
			$exp = filemtime($lock);
			if ($exp > time()) {
				// if we have an unexpired lock AND auto_prepend is still active,
				// then do not allow the delete to occur YET
				if (!empty(ini_get("auto_prepend_file"))) {
					$seconds = $exp - time();
					die("must wait up to $seconds seconds for user.ini cache to expire, or restart php process.");
				}
			}
		}
		// looks good, go ahead and delete
        // \BitFireSvr\uninstall(new \BitFire\Request, \TF\MaybeA::of(false));
	}
}

