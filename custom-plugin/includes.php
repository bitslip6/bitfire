<?php

namespace BitFirePlugin;

use BitFire\Config AS CFG;

use function ThreadFin\get_sub_dirs;
use function ThreadFin\contains;

define("\BitFire\\CMS_INCLUDED", true);

// list of plugin package files that can be used to determine package versions
// can be an empty list if no such files exist
const ENUMERATION_FILES = ["readme.txt", "license.txt", "package.json", "composer.json"];

// list of directories from document root that can be used to determine package versions
// can be an empty list if no such files exist
const PLUGIN_DIRS = ["/plugins/", "/themes/"];

// list of request parameters used for different api actions or page views
// can be an empty list if no such parameters exist
const ACTION_PARAMS = ["do", "page", "action", "screen-id"];

// files used to determine package versions for plugin malware scan
// can be an empty list if no such files exist
const PACKAGE_FILES = ["readme.txt", "README.txt", "package.json"];


/**
 * file_type is an enumeration of malware scan file types.  
 * These files are stored in separate tables with the 
 * file_type to table mapping function.
 * 
 * @param string $path the full path to the file
 * @return string an enumeration of the file type
 */
function file_type(string $path) : string {
    if (contains($path, "/plugins/")) { return "my_plugin"; }
    else { return "my_core"; }
}


/**
 * mapping function from file types to table names
 * these tables store hashes from different sources
 * 
 * @param string $type the file_type as defined by file_type()
 * @return string the name of the table to store hashes in
 */
function type_to_table(string $type) : string {
    switch ($type) {
        case "my_plugin": return "plugin_hashes";
        case "my_core": return "core_hashes";
        default: return "core_hashes";
    }
}

/**
 * convert a file path to a source path.  If the plugin has HTTP
 * access to original source code, this function should return
 * an HTTP path to the source code.
 * 
 * If no such path exists, this function should return empty string.
 * 
 * @param string $rel_path the relative path to the file, from the plugin root
 *                         path, or the document root if no such path exists 
 * @param string $type     the file type as determined by file_type()
 * @param string $ver      the version of the plugin/theme/core as determined by
 *                         package_to_ver()
 * @param string $name     the plugin/theme/module name for the file 
 *                         (if available)
 * @return string - the url to the source code
 */
function path_to_source(string $rel_path, string $type, string $ver, ?string $name=null) : string {

    $source = "";
    switch($type) {
        case "my_plugin":
            $source = "plugin.svn.my-corp.com/{$name}/tags/{$ver}/{$rel_path}";
            break;
        case "my_core":
            $source = "core.svn.my-corp.com/tags/{$ver}/{$rel_path}";
            break;
    }

    $source = "https://" . str_replace("//", "/", $source);
    return $source;
}


/**
 * when scanning for malware, the system will attempt to identify package
 * version files for identifying original source code and file hashes.
 * 
 * This function should accept any file from PACKAGE_FILES and return
 * the version number of the package. You may create your own package
 * version files in your deployment process and parse them here as well.
 * 
 * This function is called once for every line in the package file.
 * 
 * @param string $carry  the current version number found for the file
 * @param string $line   the next full line of the file
 * @return string 
 */
function package_to_ver(string $carry, string $line) : string {
    // If we have already identified a version number, use that number
    // (assumes first version number is correct).  Remove this
    // line to take the last version number, or change to accept any
    // version number based on any criteria you may have.  State can
    // be stored in local scoped "static" variables (NOT RECOMMENDED!).
    if (!empty($carry)) { return $carry; }

    // matches VeRsIoN: "1.2.3.4"
    if (preg_match("/version[\'\":\s]+([\d\.]+)/i", $line, $matches)) { return $matches[1]; }
    return $carry;
}


/**
 * since many code bases have thousands of files, each top level module
 * directory is scanned individually. This function should return a list
 * of directory paths to scan 1 at a time for malware.
 * 
 * @param string $root  - typically the DOCUMENT_ROOT (includes trailing slash)
 * @return array the list of directories to scan
 */
function malware_scan_dirs(string $root) : array {
    $plugin_dir = "{$root}modules";

    return array_merge(
        get_sub_dirs($plugin_dir),
        ["{$root}includes", "{$root}admin"]);
}

/**
 * wrapper function for cms mail implementation
 * @param string $subject 
 * @param string $message 
 * @return void 
 */
function mail(string $subject, string $message) {
    $domain_list = CFG::arr("valid_domains");
    $domain = end($domain_list);
    $headers = "From: bitfire@$domain\r\nReply-To: no-reply@$domain\r\nX-Mailer: PHP/".phpversion();
    mail(CFG::str("email"), $subject, $message, $headers);
} 