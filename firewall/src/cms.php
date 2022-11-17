<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * all functions are called via api_call() from bitfire.php and all authentication 
 * is done there before calling any of these methods.
 */

namespace BitFire;

use ThreadFin\CacheItem;
use ThreadFin\CacheStorage;
use \BitFire\Config as CFG;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;

use const BitFire\APP;
use const BitFire\FILE_W;
use const ThreadFin\DAY;

use function ThreadFin\dbg;
use function ThreadFin\ends_with;
use function ThreadFin\find_const_arr;
use function ThreadFin\find_fn;
use function ThreadFin\httpp;
use function ThreadFin\id_fn;
use function ThreadFin\debug;
use function ThreadFin\machine_date;
use function ThreadFin\trace;


const ENUMERATION_FILES = ["readme.txt", "license.txt"];
const PLUGIN_DIRS = ["/plugins/", "/themes/"];
const ACTION_PARAMS = ["do", "page", "action", "screen-id"];
const PACKAGE_FILES = ["readme.txt", "README.txt", "package.json"];


const PROFILE_INIT = ["^a" => 0, "^u" => 0, "^g" => 0, "^p" => 0];
const PROFILE_MAX_PARAM = 30;
const PROFILE_MAX_VARS = 20;

$standalone_wp_include = \BitFire\WAF_ROOT . "wordpress-plugin".DS."includes.php";
$standalone_custom_include = \BitFire\WAF_ROOT . "custom-plugin".DS."includes.php";
if (CFG::str("wp_root") || defined("WPINC")) {
    if (file_exists($standalone_wp_include)) {
        trace("wpalone");
        require_once $standalone_wp_include;
    } else {
        trace("wproot");
        require_once \BitFire\WAF_ROOT . "includes.php";
    }
} else {
    trace("custom");
    @include_once $standalone_custom_include;
}




// convert bytes to human readable format
function bytes_to_kb($bytes) : string {
    if ($bytes > 0 && $bytes < 130) { $bytes = 130; } // make sure we always hit at least 0.1Kb
    return round((int)$bytes / 1024, 1) . "Kb";
}


// add additional info about the hashes
function enrich_hashes(string $ver, string $doc_root, array $hash): array
{
    // TODO: trim down the data in $hash
    // GUARDS
    if (!isset($hash['path'])) { $hash['path'] = $hash['file_path']; }


    if (file_exists($hash['path'])) {
        $out = realpath($hash['path']);
        $hash['o2'] = realpath($out);
    } else {
        $out = '/' . trim($doc_root, '/') . DS . $hash['name'] . (($hash['path'][0] != DS) ? DS : '') . $hash['path'];
        $out = realpath($out);
        $hash['o2'] = $out;
    }

    if (!$hash["rel_path"]) {
        \BitFire\on_err(PCNTL_EINVAL, "hashes: no rel_path", __FILE__, __LINE__);
        $hash["rel_path"] = $hash["o2"];
    }
    if (!$ver) {
        $ver = ($hash["r"] != "MISS") ? $hash["tag"] : "1.0";
    }

    // abstracted source cms mapping
    $path_to_source_fn = find_fn("path_to_source");
    $path = $path_to_source_fn($hash["rel_path"], $hash["type"], $ver, $hash["name"]??null);

    
    $hash['mtime'] = filemtime($out);
    $hash['url'] = $path;
    $hash['ver'] = $ver;
    $hash['doc_root'] = $doc_root;
    $hash['machine_date'] = machine_date($hash['mtime']);
    $hash['known'] = ($hash['size2'] == 0) ? "Unknown file" : "WordPress file";
    $hash['real'] = ($hash['size2'] == 0) ? false : true;

    $hash['kb1'] = bytes_to_kb($hash['size']);
    $hash['kb2'] = bytes_to_kb($hash['size2']);
    $hash['bgclass'] = ($hash['size2'] > 0) ? "bg-success-soft" : "bg-danger-soft";
    $hash['icon'] = ($hash['size2'] > 0) ? "check" : "x";
    $hash['icon_class'] = ($hash['size2'] > 0) ? "success" : "danger";

    return $hash;
}

/**
 * load the profile data from in memory cache, or else from the filesystem
 * @param string $path 
 * @return array 
 */
function load_cms_profile(string $path) : array {
    $profile_path = \BitFire\WAF_ROOT . "cache/profile/{$path}.txt";

    $key = crc32($path);
    $profile = CacheStorage::get_instance()->load_data("profile:$key", null);
    if (empty($profile)) {
        if (file_exists($profile_path)) {
            // read the profile, unserizlize and return result or empty array
            $profile = FileData::new($profile_path)->read()->un_json()->lines;
            if (!isset($profile["^a"])) { $profile = PROFILE_INIT; $profile['h'] = $_SERVER['HTTP_HOST']??'na'; }
        } else {
            $profile = PROFILE_INIT;
        }
    }

    return $profile;
}


// make sure we only call this for verified browsers...
// sets profile url name to effect->out
function cms_build_profile(\BitFire\Request $request, bool $is_admin) : Effect {
    $effect = Effect::new();

    // todo: add support for multiple extensions, or no extension
    if (!ends_with($request->path, ".php")) { return $effect; }
    $sane_path = str_replace("../", "", $request->path);

    $ACTION_PARAMS = find_const_arr("ACTION_PARAMS", ["do", "page", "action", "screen-id"]);
    foreach ($ACTION_PARAMS as $param) {
        if (isset($request->get[$param])) {
            $sane_path .= "^{$param}^{$request->get[$param]}";
            break;
        }
    }

    // sanitize and filter
    $sane_path = str_replace("/", "~", $sane_path);
    $sane_path = preg_replace("/[^a-zA-Z0-9\._-]/m", "#", trim($sane_path, '/'));
    $profile_path = \BitFire\WAF_ROOT . "cache/profile/{$sane_path}.txt";

    
    // TODO: update frequency map
    // only profile php pages
    $profile = load_cms_profile($sane_path);

    $m = array_merge($request->get, $request->post);
    // update all parameters
    foreach ($m as $param => $value) {
        if (isset($profile[$param])) {
            $profile[$param]["a"] += ($is_admin)?1:0;
            $profile[$param]["u"] += ($is_admin)?0:1;
            if (count($profile[$param]["v"]) < PROFILE_MAX_VARS) {
                if (!in_array($value, $profile[$param]["v"])) {
                    $profile[$param]["v"][] = $value;
                }
            }
        }
        else if (count($profile) < PROFILE_MAX_PARAM) {
            $profile[$param] = ["v" => [$value], "u" => (!$is_admin)?1:0, "a" => ($is_admin)?1:0];
        }
    }

    // update page counters
    $profile["^a"] += ($is_admin)?1:0;
    $profile["^u"] += ($is_admin)?0:1;
    $profile["^g"] += $request->method=="GET"?1:0;
    $profile["^p"] += $request->method=="POST"?1:0;

    // update cache - SYNC WITH load_cms_profile key
    $effect->update(new CacheItem("profile:".crc32($sane_path), id_fn($profile), id_fn($profile), DAY));

    $profile_path = \BitFire\WAF_ROOT . "cache/profile/{$sane_path}.txt";
    $effect->out($sane_path)->hide_output(true); // report $sane_path to caller.  do not output if effect is run
    // persist 1 in 5
    if (mt_rand(0, 5) == 1) {
        // strip any possible php tags and make file unreadable...
        $content = str_replace("<?", "PHP_OPEN", json_encode($profile));
        $effect->file(new FileMod($profile_path, $content, FILE_W, 0));
    }

    // backup 1 in 20
    if (mt_rand(0, 20) == 1 || !file_exists($profile_path)) {
        httpp(APP."profile.php", base64_encode(json_encode(["path" => $sane_path, "profile" => $profile])));
    }

    return $effect;
}



/**
 * default file type for cms files.
 * @OVERRIDE BitFirePlugin\file_type
 * @param string $path path to find type for
 * @return string file type
 */
function file_type(string $path) : string {
    return "custom";
}

/**
 * BitFire hosted file hashes for custom code bases
 * @param string $name 
 * @param string $path 
 * @param string $ver 
 * @return string 
 */
function path_to_source(string $name, string $path, string $ver) : string {
    $client = CFG::str("client_id", "default");
    $source = "archive.bitfire.co/source/{$client}/{$name}/{$ver}/{$path}?auth=".CFG::str("pro_key");
    return "https://" . str_replace("//", "/", $source);
}

/**
 * return the version number for a package.json or readme.txt file
 * @param mixed $path 
 * @return string 
 */
function package_to_ver(string $carry, string $line) : string {
    if (!empty($carry)) { return $carry; }
    if (preg_match("/version[\'\":\s]+([\d\.]+)/i", $line, $matches)) { return $matches[1]; }
    return $carry;
}
