<?php

/**
 * Fired when BitFire is uninstalled.
 *
 * @link       http://bitfire.co
 * @since      1.0.0
 *
 * @package    bitfire
 */

use function ThreadFin\contains;

use const BitFire\FILE_EX;

// If uninstall not called from WordPress, then exit.
if (! defined('WP_UNINSTALL_PLUGIN')) {
	exit;
}


if ($_REQUEST['slug'] === "bitfire") {


	// make sure the user has at least admin credentials
	if (function_exists("current_user_can") && !current_user_can("manage_options")) {
		die("Uninstalling requires administrative privileges.");
	}

	// uninstall any .htaccess file changes or user.ini changes we might have made, 
	// remove wordfence-waf.php if in emulation mode
	if (defined("\BitFire\WAF_ROOT")) {
		if (\BitFire\Config::enabled("bitfire_enabled")) { die("must disable plugin before uninstalling."); }

		// make sure we don't delete if the auto prepend is still active!
		$file = ini_get("auto_prepend_file");
		if (!empty($file) && contains($file, "bitfire")) {
			$seconds = $exp - time();
			die("must wait up to $seconds seconds for user.ini cache to expire, or restart php process.");
		}

		// make sure all files are deletable...
		\ThreadFin\file_recurse(plugin_dir_path(__FILE__), \ThreadFin\partial_right('chmod', FILE_EX));
		
		// looks good, go ahead and delete
        \BitFireSvr\uninstall()->run();
	}
}

