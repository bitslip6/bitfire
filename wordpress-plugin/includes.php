<?php

namespace BitFirePlugin;

use BitFire\Config AS CFG;

use function BitFire\get_subdirs;
use function ThreadFin\contains;

define("\BitFire\\CMS_INCLUDED", true);

const ENUMERATION_FILES = ["readme.txt", "license.txt"];
const PLUGIN_DIRS = ["\/plugins\/", "\/themes\/"];
const ACTION_PARAMS = ["do", "page", "action", "screen-id"];
const PACKAGE_FILES = ["readme.txt", "README.txt", "package.json"];


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

    switch($type) {
        case "wp_plugin":
            $source = "https://plugins.svn.wordpress.org/{$name}/tags/{$ver}/{$rel_path}";
            break;
        case "wp_themes":
            $source = "https://themes.svn.wordpress.org/{$name}/{$ver}/{$rel_path}";
            break;
        case "wp_core":
        default:
            $source = "https://core.svn.wordpress.org/tags/{$ver}/{$rel_path}?type={$type}";
            break;
    }

    return $source;
}


/**
 * return the version number for a package.json or readme.txt file
 * @param mixed $path 
 * @return string 
 */
function package_to_ver(string $carry, string $line) : string {
    if (!empty($carry)) { return $carry; }
    if (preg_match("/stable\s+tag[\'\":\s]+([\d\.]+)/i", $line, $matches)) { return $matches[1]; }
    if (preg_match("/version[\'\":\s]+([\d\.]+)/i", $line, $matches)) { return $matches[1]; }
    return $carry;
}

function malware_scan_dirs(string $root) : array {
    $d1 = CFG::str("wp_contentdir")."/plugins";
    $d2 = CFG::str("wp_contentdir")."/themes";
    return array_merge(get_subdirs($d1), get_subdirs($d2), ["{$root}wp-includes", "{$root}wp-admin"]);
}