<?php

namespace BitFirePlugin;

use BitFire\Config AS CFG;

use function ThreadFin\get_sub_dirs;
use function BitFireSvr\get_wordpress_version;
use function ThreadFin\contains;
use function ThreadFin\debug;
use function ThreadFin\ends_with;

define("\BitFire\\CMS_INCLUDED", true);

const ENUMERATION_FILES = ["readme.txt", "license.txt"];
const PLUGIN_DIRS = ["/plugins/", "/themes/"];
const ACTION_PARAMS = ["do", "page", "action", "screen-id"];
const PACKAGE_FILES = ["readme.txt", "README.txt", "style.css", "package.json"];


/**
 * return the hash file type
 * @param string $path 
 * @return string 
 */
function file_type(string $path) : string {
    if (contains($path, "/plugins/")) { return "wp_plugin"; }
    if (contains($path, "/themes/")) { return "wp_themes"; }
    return "wp_core";
}

/**
 * convert a path to a source url
 * @param string $name 
 * @param string $path 
 * @param string $ver 
 * @return string 
 */
function path_to_source(string $rel_path, string $type, string $ver, ?string $name=null) : string {

    static $core_ver = null;
    if ($core_ver == null) {
        $core_ver = get_wordpress_version(CFG::str("wp_root"));
    }

    switch($type) {
        case "wp_plugin":
            $source = "plugins.svn.wordpress.org/{$name}/tags/{$ver}/{$rel_path}";
            break;
        case "wp_themes":
            $source = "themes.svn.wordpress.org/{$name}/{$ver}/{$rel_path}";
            break;
        case "wp_core":
        default:
            $source = "core.svn.wordpress.org/tags/{$core_ver}/{$rel_path}?type={$type}";
            break;
    }
    $source = "https://" . str_replace("//", "/", $source);
    return $source;
}


/**
 * return the version number for a package.json or readme.txt file
 * @param mixed $path 
 * @return string 
 */
function package_to_ver(string $carry, string $line) : string {
    if (!empty($carry)) { return $carry; }
    if (preg_match("/stable\s+tag\s*[\'\":]+\s*([\d\.]+)/i", $line, $matches)) { return $matches[1]; }
    if (preg_match("/version\s*[\'\":]+\s*([\d\.]+)/i", $line, $matches)) { return $matches[1]; }
    return $carry;
}

function malware_scan_dirs(string $root) : array {
    debug("malware_scan (%s)", $root);
    if (!ends_with($root, "/")) { $root .= "/"; }
    $d1 = CFG::str("wp_contentdir")."/plugins";
    $d2 = CFG::str("wp_contentdir")."/themes";
    return array_merge(get_sub_dirs($d1), get_sub_dirs($d2));//, ["{$root}wp-includes", "{$root}wp-admin"]);
}


/**
 * wrapper function for cms mail implementation
 * @param string $subject 
 * @param string $message 
 * @return void 
 */
function mail(string $subject, string $message) {
    \wp_mail(CFG::str("email"), $subject, $message);
} 