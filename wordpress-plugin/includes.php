<?php

namespace BitFirePlugin;

use BitFire\Config AS CFG;
use ThreadFin\FileData;

use const BitFire\WAF_ROOT;

use function BitFireSvr\get_wordpress_version;
use function BitFireSvr\trim_off;
use function ThreadFin\get_sub_dirs;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\debug;
use function ThreadFin\ends_with;
use function ThreadFin\find_const_arr;
use function ThreadFin\find_fn;

define("\BitFire\\CMS_INCLUDED", true);

const ENUMERATION_FILES = ["readme.txt", "license.txt"];
const PLUGIN_DIRS = ["/plugins/", "/themes/"];
const ACTION_PARAMS = ["do", "page", "action", "screen-id"];
const PACKAGE_FILES = ["readme.txt", "README.txt", "style.css", "package.json"];

/**
 * get the wordpress version from a word press root directory
 */
function get_cms_version(string $root_dir): string
{
    $full_path = "$root_dir/wp-includes/version.php";
    $wp_version = "1.0";
    if (file_exists($full_path)) {
        include $full_path;
    }
    return trim_off($wp_version, "-");
}


/**
 * return the hash file type
 * @param string $path 
 * @return string 
 */
function file_type(string $path) : string {
    if (strpos($path, "/plugins/") > 0) { return "wp_plugin"; }
    if (strpos($path, "/themes/") > 0) { return "wp_themes"; }
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
        $core_ver = get_wordpress_version(CFG::str("cms_root"));
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
    $r1 = realpath(CFG::str("cms_root"))."/";
    $r2 = realpath(CFG::str("cms_content_dir"))."/";

    if (!ends_with($root, "/")) { $root .= "/"; }
    $d1 = CFG::str("cms_content_dir")."/plugins";
    $d2 = CFG::str("cms_content_dir")."/themes";
    $d3 = CFG::str("cms_content_dir")."/uploads";
    $t4 = get_sub_dirs(CFG::str("cms_root"));
    $d4 = array_diff($t4, ["{$r1}wp-content", "{$r1}wp-includes", "{$r1}wp-admin"]);
    $t5 = get_sub_dirs(CFG::str("cms_content_dir"));
    $d5 = array_diff($t5, ["{$r2}plugins", "{$r2}themes"]);

    $result = array_merge(get_sub_dirs($d1), get_sub_dirs($d2), get_sub_dirs($d3), $d4, $d5);
    $q1 = array_unique($result);
    return $q1;
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

const PARAM_SEARCH = 1;
const LOG_ACTION = 2;
const DST_USER = 4;
const RISKY_DB_PARAM = ["wp_capabilities"];

/**
 * stub for function auditing
 * @param string $fn_name 
 * @param string $file 
 * @param string $line 
 * @param mixed $args 
 * @return void 
 */
function fn_audit(string $fn_name, string $file, string $line, ...$args) {
    static $fn_map = [
        "update_user_meta" => [1 => DST_USER, 2 => RISKY_DB_PARAM, 3=> PARAM_SEARCH],
        "wp_create_user" => [1 => LOG_ACTION],
        "wp_insert_user" => [1 => LOG_ACTION]
    ];
    $src = $file . ":" . $line;
    $x = FileData::new(WAF_ROOT."cache/{$fn_name}.json")->read()->un_json()->lines;
    if (!isset($x[$src])) { 
        $x[$src] = [];
    }
}

// find a plugin / theme version number located in $path
function version_from_path(string $path, string $default_ver = "") {
    $package_fn = find_fn("package_to_ver");
    $package_files = find_const_arr("PACKAGE_FILES");
    $php_files = array_map('basename', glob($path."/*.php"));
    $all_files = array_merge($package_files, $php_files);

    foreach($all_files as $file) {
        $file_path = "{$path}/{$file}";
        if (file_exists($file_path)) {
            $version = FileData::new($file_path)->read()->reduce($package_fn, "");
            if ($version) { return $version; }
        }
    }
    return $default_ver;
}
