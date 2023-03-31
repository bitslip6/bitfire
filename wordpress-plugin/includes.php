<?php

namespace BitFirePlugin;

use BitFire\Config AS CFG;
use ThreadFin\FileData;

use const BitFire\WAF_ROOT;

use function BitFireBot\verify_bot_as;
use function BitFireSvr\get_wordpress_version;
use function BitFireSvr\trim_off;
use function ThreadFin\get_sub_dirs;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\debug;
use function ThreadFin\ends_with;
use function ThreadFin\find_const_arr;
use function ThreadFin\find_fn;
use function ThreadFin\http2;
#use function ThreadFin\take_links;

define("BitFire\\CMS_INCLUDED", true);

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
        @include $full_path;
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
    if (strpos($path, "/wp-includes/") > 0) { return "wp_core"; }
    if (strpos($path, "/wp-admin/") > 0) { return "wp_core"; }
    $name = basename($path);
    if (in_array($name, ["wp-activate.php", "wp-comments-post.php", "wp-config.php", "wp-config-sample.php", "wp-cron.php", "wp-links-opml.php", "wp-load.php", "wp-login.php", "wp-mail.php", "wp-blog-header.php", "wp-settings.php", "wp-signup.php", "wp-trackback.php", "xmlrpc.php"])) {
        return "wp_core";
    }
    return "unknown";
}

/**
 * find the most recent version in version control that matches of local version.
 * if there are less than 3 newer versions we use trunk, else we use the closest
 * tag to the target version we can find.
 * @param array $tags 
 * @param mixed $ver 
 * @param string $default 
 * @return mixed 
 */
function recent_ver(array $tags, $ver, $default = "trunk") {
    debug("recent_ver(%s, %s)", $tags, $ver);
    $most_recent = $default;
    $num_newer = 0;
    foreach ($tags as $href => $release) {
        $release = trim($release, "/");
        $compare = version_compare($release, $ver);
        // exact match
        if ($compare == 0) {
            return $release;
        }
        // this version is older than target
        if ($compare < 0) {
            $most_recent = $release;
        }
        // version is newer than target
        else {
            $num_newer++;
        }
    }

    // if we have found a version, and we have < 2 newer versions, we just use trunk
    if ($most_recent != $default && $num_newer  < 3) { return $default; }
    return $most_recent;
}


/**
 * convert a path to a source url
 * @param string $name 
 * @param string $path 
 * @param string $ver 
 * @return string 
 */
function path_to_source(string $rel_path, string $type, string $ver, ?string $name=null) : string {

    static $cache = null;
    static $core_ver = null;
    //xdebug_break();

    if ($core_ver == null) {
        $core_ver = get_wordpress_version(CFG::str("cms_root"));
    }
    if ($cache == null) {
        $cache = [];
    }
    $cache_name = "{$type}_{$name}_{$ver}";
    
    if (isset($cache[$cache_name])) {
        $root = $cache[$cache_name];
    } else {
        switch($type) {
            case "wp_plugin":
                $check = "plugins.svn.wordpress.org/{$name}/tags/";
                $resp = http2("GET", $check, "");
                $tags = take_links($resp['content']);
                $ver = recent_ver($tags, $ver, "trunk");
                $plugin_path = ($ver === "trunk") ? "/trunk/" : "/tags/{$ver}/";
                $root = "plugins.svn.wordpress.org/{$name}".$plugin_path;
                
                break;
            case "wp_themes":
                $check = "https://themes.svn.wordpress.org/{$name}/";
                $resp = http2("GET", $check, "");
                $tags = take_links($resp['content']);
                $ver = recent_ver($tags, $ver, "latest");
                $root = "themes.svn.wordpress.org/{$name}/$ver";

                break;
            case "wp_core":
            default:
                $root = "core.svn.wordpress.org/tags/{$core_ver}";
                break;
        }
        debug("map type set [%s] = [%s]", $cache_name, $root);
        $cache[$cache_name] = $root;
    }
    debug("map type [%s] ver [%s] to [%s]", $type, $ver, $root);
    $source = $root . "/" . $rel_path;
    debug("map type [%s]", $source);

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
    $r1 = realpath(CFG::str("cms_root")).DIRECTORY_SEPARATOR;
    $r2 = realpath(CFG::str("cms_content_dir")).DIRECTORY_SEPARATOR;

    if (!ends_with($root, DIRECTORY_SEPARATOR)) { $root .= DIRECTORY_SEPARATOR; }
    $d1 = $r2."plugins";
    $d2 = $r2."themes";
    $d3 = $r2."uploads";
    $t4 = get_sub_dirs(CFG::str("cms_root"));
    $d4 = array_diff($t4, ["{$r1}wp-content", "{$r1}wp-includes", "{$r1}wp-admin"]);
    $t5 = get_sub_dirs(CFG::str("cms_content_dir"));
    $d5 = array_diff($t5, ["{$r2}plugins", "{$r2}themes"]);

    $result = array_merge(get_sub_dirs($d1), get_sub_dirs($d2), get_sub_dirs($d3), $d4, $d5);
    $real = array_map("realpath", $result);
    // make sure we don't scan the whole content directory
    $real2 = array_filter($real, function ($x) use ($r2) {
        $a = trim($x, DIRECTORY_SEPARATOR);
        $b = trim($r2, DIRECTORY_SEPARATOR);
        return $a !== $b;
    });
    $q1 = array_unique($real2);

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

function path_to_plugin_dir(string $path) {

    if (preg_match("/.*?\/wp-content\/(?:plugins|themes)\/([^\/]+)/i", $path, $matches)) {
        return $matches[0];
    }

    return $path;
}

// find a plugin / theme version number located in $path
function version_from_path(string $path, string $default_ver = "0.1") {
    static $cache = [];
    $path = realpath($path);
    $plugin_path = path_to_plugin_dir($path);
    if (contains($path, "plugins")) {
        //xdebug_break();
    }

    // no plugin found
    if ($plugin_path == $path) {
        return CFG::str("wp_version");
    }
    if (isset($cache[$plugin_path])) { return $cache[$plugin_path]; }

    $package_fn = find_fn("package_to_ver");
    $package_files = find_const_arr("PACKAGE_FILES");
    $file_names = glob($plugin_path."/*.php");
    $php_files = ($file_names) ? array_map('basename', $file_names) : [];
    $all_files = array_merge($package_files, $php_files);

    foreach($all_files as $file) {
        $file_path = "{$plugin_path}/{$file}";
        if (file_exists($file_path)) {
            $version = FileData::new($file_path)->read()->reduce($package_fn, "");
            if ($version) {
                // TODO: see if we can find the version in the SVN repo...
                $cache[$plugin_path] = $version;
                return $version;
            }
        }
    }

    $cache[$plugin_path] = $default_ver;
    return $default_ver;
}

function take_links(string $input): array
{
    preg_match_all("/href=['\"]([^'\"]+)['\"].*?>([^<]+)/", $input, $matches);
    $result = array();
    for ($i = 0, $m = count($matches[1]); $i < $m; $i++) {
        $result[$matches[1][$i]] = $matches[2][$i];
    }
    return array_filter($result, function ($x) {
        return $x != '..' && $x != '../' && strpos($x, 'subversion') === false;
    }, ARRAY_FILTER_USE_KEY);
}
