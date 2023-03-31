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
use BitFireSvr\FileHash;
use Exception;
use FineDiff;
use OutOfBoundsException;
use RuntimeException;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;
use ThreadFin\Pair;

use const BitFire\APP;
use const BitFire\FILE_W;
use const ThreadFin\DAY;

use function BitFirePlugin\check_user_cap;
use function BitFirePlugin\version_from_path;
use function BitFireSvr\cms_root;
use function BitFireSvr\hash_file3;
use function BitFireSvr\parse_scan_config;
use function ThreadFin\compress;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\ends_with;
use function ThreadFin\find_const_arr;
use function ThreadFin\find_fn;
use function ThreadFin\id_fn;
use function ThreadFin\debug;
use function ThreadFin\en_json;
use function ThreadFin\file_yield;
use function ThreadFin\get_hidden_file;
use function ThreadFin\HTTP\http2;
use function ThreadFin\HTTP\http3;
use function ThreadFin\icontains;
use function ThreadFin\index_yield;
use function ThreadFin\machine_date;
use function ThreadFin\trace;
use function ThreadFin\un_json;
use function ThreadFin\random_str;
use function ThreadFin\uncompress;

const ENUMERATION_FILES = ["readme.txt", "license.txt"];
const PLUGIN_DIRS = ["/plugins/", "/themes/"];
const PACKAGE_FILES = ["readme.txt", "README.txt", "package.json"];
const RISKY_JS = ["fromCharCode"];
const WP_FN = "|wp_create_user";
const UPLOAD_FN = "|move_uploaded_file";
const VAR_FN = '|\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*';
const USER_FN = "|call_user_func|call_user_func_array|create_function";
const FN1_RX = '/[\@\s\(\);\/](?:header|mail|uudecode|hebrev|hex2bin|str_rot13|eval|proc_open|pcntl_exec|exec|shell_exec|system|passthru%s*)\s*(?:\[[^\]]*?\])?\s*(?:(?:#[^\n]*\n)|(?:\/\/[^\n]*\n)|(?:\/\*.*?\*\/))?\(\s*(?:[\.\$_]*)?/misS';

const CHAR_NL = 10;
const CHAR_HASH = 61;
const CHAR_SLASH = 73;

const PROFILE_INIT = ["^a" => 0, "^u" => 0, "^g" => 0, "^p" => 0, "^c" => []];
const PROFILE_MAX_PARAM = 30;
const PROFILE_MAX_VARS = 20;
const PROFILE_MAX_CAPS = 20;

if (!function_exists("\BitFirePlugin\\file_type")) {
    $standalone_wp_include = \BitFire\WAF_ROOT . "wordpress-plugin" . DS . "includes.php";
    $standalone_custom_include = \BitFire\WAF_ROOT . "custom-plugin" . DS . "includes.php";
    if (file_exists($standalone_wp_include) && file_exists(dirname(__DIR__, 2) . DS . "wp-load.php")) {
        if (file_exists($standalone_wp_include)) {
            trace("wp_alone");
            require_once $standalone_wp_include;
        }
    }
    else if (file_exists(\BitFire\WAF_ROOT . "includes.php")) {
        trace("wp_root");
        include_once \BitFire\WAF_ROOT . "includes.php";
    } else {
        trace("custom");
        $standalone_custom_plugin = \BitFire\WAF_ROOT . "custom-plugin" . DS . "bitfire-plugin.php";
        @include_once $standalone_custom_include;
        @include_once $standalone_custom_plugin;
    }
}


class ScanConfig {
    public $wp_func = true;
    public $includes = true;
    public $access_time = true;
    public $unknown_core = true;
    public $unknown_plugin = false;
    public $non_php = false;
    public $standard_scan = false;

    public $freq_limit = 512;
    public $line_limit = 2048;
    public $random_name_per = 50;

    public $fn_freq_limit = 20;
    public $fn_line_limit = 768;
    public $fn_random_name_per = 30;

    public $quick = true;

    public $extra_regex = true;
}


/**
 * a root class all of our classes 
 * @package ThreadFin
 */
class Entity
{
}


/**
 * a <generic> list of errors
 * @package 
 */
abstract class Typed_List implements \ArrayAccess, \Iterator, \Countable, \JsonSerializable {

    /* @var int $_position */
    protected $_position = 0;
    /* @var array $_list */
    public $_list = [];
    public $associated = false;

    // return the number of items in the list
    public function count(): int
    {
        return count($this->_list);
    }

    // SeekableIterator impl. seek a specific position in the list
    public function seek($position)
    {
        if (!isset($this->_list[$position])) {
            throw new OutOfBoundsException("invalid seek position ($position)");
        }

        $this->_position = $position;
    }

    // SeekableIterator impl. reset the list position to the first element
    public function rewind(): void
    {
        $this->_position = 0;
    }

    // SeekableIterator impl. return the current index
    #[\ReturnTypeWillChange]
    public function key()
    {
        return $this->_position;
    }

    // SeekableIterator impl. move to the next element
    public function next(): void
    {
        ++$this->_position;
    }

    // SeekableIterator impl. check if the current position is valid
    public function valid(): bool
    {
        return isset($this->_list[$this->_position]);
    }

    // ArrayAccess impl. set the value at a specific index
    public function offsetSet($index, $value): void
    {
        if (empty($index)) {
            $this->_list[] = $value;
        } else {
            $this->_list[$index] = $value;
            $this->associated = true;
        }
    }

    // ArrayAccess impl. remove(unset) the value at a specific index
    public function offsetUnset($index): void
    {
        unset($this->_list[$index]);
    }

    // ArrayAccess impl. check if the value at a specific index exists
    public function offsetExists($index): bool
    {
        return isset($this->_list[$index]);
    }

    // Sort the list by key values
    public function ksort(int $flags = SORT_REGULAR): bool
    {
        return ksort($this->_list, $flags);
    }

    public function getIterator(): \Traversable
    {
        return $this;
    }

    /**
     * This method allows us to call json_encode() and not have a "_list" sub-object 
     * @return array the list data
     */
    public function jsonSerialize(): array
    {
        return $this->_list;
    }

    // helper method
    public function empty(): bool
    {
        return empty($this->_list);
    }

    /**
     * append a list to this list
     * @param Typed_List $list 
     * @return void 
     */
    public function append_list(Typed_List $list) {
        file_put_contents("/tmp/list_append.txt", json_encode($list->raw(), JSON_PRETTY_PRINT) . "\n\n", FILE_APPEND);
        if (count($list) > 0) {
            if ($this->associated) {
                $this->_list = array_merge($this->_list, $list->raw());
            } else {
                foreach ($list->_list as $item) {
                    $this->_list[] = $item;
                }
                //echo json_encode($this->_list, JSON_PRETTY_PRINT). "\n";
                //dbg($this, "APPEND");
            }
        }
    }



    public function &raw() { return $this->_list; }

    //public abstract function add($item) : void;
    #[\ReturnTypeWillChange]
    public abstract function offsetGet($index);

    // SeekableIterator impl. return the element at $this->_position.
    // override the return type!
    #[\ReturnTypeWillChange]
    public abstract function current();
}



/**
 * malware analysis
 * 
 * @package BitFire
 */
class Malware extends Entity
{
    /** @var float $frequency */
    public $frequency = 0.0;
    /** @var int $php_count */
    public $php_count = 0;
    /** @var int $location 0 - beginning, 1 - middle, 2 - end */
    public $location = 0;
    /** @var string $pre_text */
    public $pre_text = "";
    /** @var int $content_offset */
    public $content_offset = 0;
    /** @var string $content */
    public $content = "";
    /** @var string $post_text */
    public $post_text = "";
    /** @var string $note */
    public $note = "";
    /** @var int $pre_indent */
    public $pre_indent = "";
    /** @var int $content_indent */
    public $content_indent = 0;
    /** @var int $post_indent */
    public $post_indent = 0;
    /** @var int $file_size */
    public $file_size = 0;
    /** @var File_Info_Block $info */
    public $info;
    /** @var int $max_length */
    public $max_length = 0;
    /** @var int $per_unknown */
    public $per_unknown = 0;

    /** @var string $path */
    public $path;
    public $unique;
    public $known = false;
    public $ctime;
    public $url;
    
    public function __construct() {
        $this->unique = random_str(8);
    }
}




/**
 * a typed list of Malware
 */
class Malware_List extends Typed_List
{
    public $num_scanned = 0;
    public $num_skipped = 0;
    public $complete = 0;
    public $_list = [];

    /**
     * add a new malware item to the list
     * will only add malware with a frequency > 1.0
     * @param null|TF_Error $error 
     * @return void 
     */
    public function add(?Entity $malware) {
        if ($malware != null) {
            assert($malware instanceof Malware, "Malware_List can only contain Malware objects");
            debug("CREATE MALWARE %s", $malware);
            $this->_list[] = $malware;
        }
    }

    /**
     * @return Malware 
     */
    public function offsetGet($index) : ?Malware {
        return $this->_list[$index] ?? null;
    }

    /**
     * @return Malware 
     */
    public function current() : ?Malware {
        return $this->_list[$this->_position];
    }

    public function inc_scanned() {
        $this->num_scanned++;
    }

    public function inc_skipped() {
        $this->num_skipped++;
    }

    public function set_scanned(int $num) {
        $this->num_scanned = $num;
    }

}


/**
 * file metadata for malware analysis
 * @package BitFire
 */
class File_Info_Block
{
    /** @var array float $frequency */
    public $frequency;
    /** @var array float $slash_freq */
    public $slash_freq;
    /** @var array float $hash_freq */
    public $hash_freq;
    /** @var array float $block_freq */
    public $block_freq;
    /** @var int $indentation_level 0-32656 spaces, 32565-64435 tabs */
    public $indent_level;
    /** $var int $lines number of lines in this file info block */
    public $lines;
}

function find_malware(string $file) : ?Malware {
    $malware = NULL;
    return $malware;
}



/**
 * get the path to the hash file
 * @param string $file_path 
 * @param string $rel_path 
 * @return string 
 */
function get_hash_path(string $file_path, string $rel_path) : string {
    $content_dir = CFG::str("cms_content_dir");
    if (contains($file_path, $content_dir)) {
        $strip_root = str_replace($content_dir, "", $file_path);
        $parts=explode(DS, trim($strip_root, DS));
        array_shift($parts);
        array_shift($parts);
        $no_plugin_name = join(DS, $parts);
        $base_root = str_replace($no_plugin_name, "", $strip_root);
    } else {
        $base_root = (contains($file_path, "wp-content")) ? "content-root" : "cms-root";
    }
    return trim(str_replace(DS, "_", $base_root), "_");
}


/**
 * add the hash to the list of passing hashes
 * @param string $hash_path 
 * @param int $crc_path 
 * @param int $crc_trim 
 * @return void 
 */
function add_to_pass_hash(string $hash_path, int $crc_path, int $crc_trim) {
    static $list = null;
    if ($list == null) {
        $list = [];
        register_shutdown_function(function() use (&$list) {
            foreach ($list as $base_root => $file_list) {
                $file_name = get_hidden_file("quick_map".DS.$base_root.".json");
                if (file_exists($file_name)) {
                    $data = json_decode(file_get_contents($file_name), true);
                } else {
                    @mkdir(get_hidden_file("quick_map"));
                    $data = [];
                }
                foreach ($file_list as $crc_path => $crc_trim) {
                    $data[$crc_path] = $crc_trim;
                }
                file_put_contents($file_name, json_encode($data));
            }
        });
    }
    if (!isset($list[$hash_path])) {
        $list[$hash_path] = [];
    }
    $list[$hash_path][$crc_path] = $crc_trim;
}


/**
 * 
 * @param FileHash $hash 
 * @return bool 
 * @throws Exception 
 */
function is_pass_hash(FileHash $hash) : bool {
    static $map = [];
    $base_root = get_hash_path($hash->file_path, $hash->rel_path);
    
    if (!isset($map[$base_root])) {
        $file = get_hidden_file("quick_map".DS.$base_root.".json");
        if (file_exists($file)) {
            $map[$base_root] = json_decode(file_get_contents($file), true);
        } else {
            $map[$base_root] = [];
        }
    }
    if (isset($map[$base_root])) {
        //xdebug_break();
        if (isset($map[$base_root][$hash->crc_path])) {
            return $map[$base_root][$hash->crc_path] == $hash->crc_trim;
        }
    }

    return false;
}

/**
 * TODO, scan plugins and themes, and pull down list of known plugins and themes
 * only send to hash_compare known files
 * @param string $index_file 
 * @param int $skip_files 
 * @return Malware_List 
 * @throws RuntimeException 
 * @throws Exception 
 */
function scan_filesystem(string $index_file, int $skip_files = 0, int $max_files = 120, ?ScanConfig $config = NULL) : Malware_List {
    require_once WAF_SRC . "/server.php";
    $counter = 0;
    $list = new Malware_List();
    $list->complete = 0;
    $type_fn = "\BitFirePlugin\\file_type";

    $plugins = "/wp-content/plugins/";
    $themes = "/wp-content/themes/";

    $batch = [];
    $results = [];
    $unknown = [];
    $allow_map = [];

    if ($config == NULL) { $config = parse_scan_config(CFG::arr("malware_config")); } 

    $passable = [
        1579353588 => 2386763083,
        2008795106 => 3433127016,
        730207289 => 347445098,
        0 => 2042742896,
        2498048709 => 1,
        2639749952 => 1,
        1864550530 => 1,
        3551137528 => 1,
        311902961 => 1
    ];


    // the manual allow list
    $allowed = FileData::new(get_hidden_file("hashes.json"))->read()->un_json()->lines;
    if ($allowed === null || empty($allowed)) { $allowed = [];}
    foreach ($allowed as $file) { $allow_map[$file["path"]] = $file["trim"]; }

    $ver_fn = '\BitFirePlugin\\version_from_path';
    $reg_ex = (!$config->non_php) ? NULL : "/.*\.php/";
    //foreach (index_yield($root_path, $reg_ex, $max_files, $skip_files) as $file) {
    $root = cms_root();
    foreach (index_yield($index_file, $max_files) as $file) {
        if ($file == null) {
            $list->complete = 1;
            break;
        }
        $list->inc_scanned();

        if (isset($allow_map[$file])) {
            $list->inc_skipped();
            continue;
        }

        $file_hashed = hash_file3($file, $type_fn, $ver_fn, $root);
        if (empty($file_hashed) || $file_hashed->skip) { $list->inc_skipped(); continue; }
        // skip files that are not js or php, or do not have malware functions
        //if ($file_hashed->skip) { file_put_contents("/tmp/skipped.txt", "$file\n", FILE_APPEND); }


        // skip known good files
        if ($config->standard_scan == false && is_pass_hash($file_hashed)) { $list->inc_skipped(); continue; }

        // skip empty index files
        if (in_array($file_hashed->crc_trim, [3574178858, 3551137528, 1162311920])) { continue; }

        if (isset($passable[$file_hashed->crc_path])) {
            if ($passable[$file_hashed->crc_path] == 1 || $passable[$file_hashed->crc_path] == $file_hashed->crc_trim) {
                continue;
            }
        }


        
        if ($file_hashed->type == "unknown") {
            $unknown[] = $file_hashed;

        } else {
            $batch[] = $file_hashed;
        }
    }

    if (filesize($index_file) < 256) { $list->complete = 1; }


    $h2 = en_json(["ver" => 1.0, "files" => $batch]);
    $compressed = compress($h2);
    $response = http2("POST", APP."hash_compare2.php", $compressed[0], array("Content-Type" => "application/json", "X-COMPRESSION" => $compressed[2], "ACCEPT-ENCODING"));
    $decoded = un_json($response->content);
    $result = un_json(uncompress($decoded));

    debug("hash_compare result [%d]", count($result));
    foreach ($result as $item) {

        if (isset($item["r"]) && $item["r"] === "PASS") {
            add_to_pass_hash(get_hash_path($item["file_path"], $item["rel_path"]), $item["crc_path"], $item["crc_trim"]);
            continue;
        }

        // TODO: check if we found the actual file...
        if ($item["found"]) {
            $results[] = $item;
        } else {
            $unknown[] = $item;
        }
    }


    // scan for malware in infected WordPress files
    for ($i=0; $i<count($results); $i+=20) {
        $t0 = microtime(true);
        $infected_files = batch_enrich(array_slice($results, $i, 20), $config);
        $t1 = microtime(true);
        foreach ($infected_files as $file) {
            if (isset($file['malware']) && count($file['malware']) > 0) {
                //xdebug_break();
                $list->append_list($file['malware']);
            } else {
                add_to_pass_hash(get_hash_path($file["file_path"], $file["rel_path"]), $file["crc_path"], $file["crc_trim"]);
            }
        }
    }

    foreach ($unknown as $check_file) {
        if (empty($check_file)) { continue; }

        $miss = false;
        $path = "";
        $type = "core";
        if (is_object($check_file)) {
            $path = $check_file->file_path;
            $type = $check_file->type;
            if ($config->unknown_core && $check_file->name == "root" && $check_file->type == "unknown") {
                $type = "ROOT";
                $miss = true;
            }
        } else {
            $path = $check_file["file_path"];
            $type = $check_file["type"];
            if ($config->unknown_core && ($check_file["type"] == "wp_core" || $check_file["table"] == "core") && $check_file["size2"] < 1) {
                $type = "wp_core";
                $miss = true;
            }
            if (intval($check_file["plugin_id"]??0) > 1 && $check_file["r"] == "MISS") {
                /* XXX keep this? lots of false positives, but could help identify hard to find malware... TODO: make this an option
                if ($config->unknown_plugin) {
                $type = "MISS PLUGIN: " . $check_file["plugin_id"];
                    $miss = true;
                }
                */
            }
        }

        if ($miss) {
            $content = file_get_contents($path, false, null, 0, 2048);
            $m = malware_metrics($content, false, $path, $config);
            $m->content = substr($content, 0, 2048);
            $m->note = sprintf("unknown <%s> file", $type);
            $list->add($m);
        } else {

            if (!empty($check_file->file_path)) {
                $known = intval($check_file->plugin_id) > 0 && $check_file["r"] != "MISS";
                $m2 = cms_find_malware($check_file->file_path, $known, 0, $config);
                if (count($m2) > 0) {
                    $list->append_list($m2);
                } else {
                    add_to_pass_hash(get_hash_path($check_file->file_path, $check_file->rel_path), $check_file->crc_path, $check_file->crc_trim);
                }

            } else {
                $known = intval($check_file["plugin_id"]??0) > 0 && $check_file["r"] != "MISS";
                $m2 = cms_find_malware($check_file["file_path"], $known, 0, $config);
                if (count($m2) > 0) {
                    $list->append_list($m2);
                } else {
                    add_to_pass_hash(get_hash_path($check_file["file_path"], $check_file["rel_path"]), $check_file["crc_path"], $check_file["crc_trim"]);
                }
            }
        }
    }
 

    return $list;
}


/**
 * return array of pairs (file, ctime) that have odd access times
 * @param string $directory 
 * @return array 
 */
function odd_access_times(string $directory) : array {
    $files = [];
    $access_count = [];
    $ctime_to_file = [];

    /* scan $directory and stat each file,
     * store access times in hash map
     */
    $dh = opendir($directory);
    while (($file = readdir($dh)) !== false) {
        if ($file == '.' || $file == '..') {
            continue;
        }

        $path = $directory . '/' . $file;
        if (is_file($path)) {
            $stat = stat($path);
            $access_count[$stat['ctime']] = ($access_count[$stat['ctime']] ?? 0) + 1;
            $ctime_to_file[$stat['ctime']][] = $path;
        }
    }
    closedir($dh);

    // remove the most common access time
    asort($access_count);
    array_pop($access_count);
    foreach ($access_count as $time => $count) {
        if (isset($ctime_to_file[$time])) {
            $files = array_merge($files, $ctime_to_file[$time]);
        }
    }

    // map the files with creation time
    $files_with_time = array_map(function($file) {
        return new Pair($file, filectime($file));
    }, $files);


    return $files_with_time;
}


/**
 * pure function to compare content of php code against frequency table
 * @test test_malware/test_char_freq_analysis
 * @param string $content 
 * @param array $compare_freq 
 * @return float 
 * 
 */
function char_freq_analysis(array $test_frequency, array $compare_freq): float
{
    $lines = $test_frequency[10] ?? 1;

    $likely = 0.0;
    // UGLY, split 2x for performance, called a lot
    for ($x = 0; $x <= 64; $x++) {
        if (!isset($test_frequency[$x])) {
            continue;
        }
        $i = $x + 128;
        $test = round(($test_frequency[$x] / $lines), 4);
        if (isset($compare_freq[$i])) {
            if ($test > $compare_freq[$i]["u"]) {
                $rat1 = $test / $compare_freq[$i]["u"];
                if ($rat1 > 1.4) {
                    $likely += ($rat1 - 1.0);
                }
            }
        }
    }
    for ($x = 91; $x <= 96; $x++) {
        if (!isset($test_frequency[$x])) {
            continue;
        }
        $i = $x + 128;
        $test = round(($test_frequency[$x] / $lines), 4);
        if (isset($compare_freq[$i])) {
            if ($test > $compare_freq[$i]["u"]) {
                $rat1 = $test / $compare_freq[$i]["u"];
                if ($rat1 > 1.4) {
                    $likely += ($rat1 - 1.0);
                }
            }
        }
    }
    for ($x = 123; $x <= 126; $x++) {
        if (!isset($test_frequency[$x])) {
            continue;
        }
        $i = $x + 128;
        $test = round(($test_frequency[$x] / $lines), 4);
        if (isset($compare_freq[$i])) {
            if ($test > $compare_freq[$i]["u"]) {
                $rat1 = $test / $compare_freq[$i]["u"];
                if ($rat1 > 1.4) {
                    $likely += ($rat1 - 1.0);
                }
            }
        }
    }

    return round($likely, 2);
}

/**
 * return an array of plugin file info in 5K chuck block sizes
 * @param string $content 
 * @return array 
 */
function get_plugin_file_info(string $content, array $compare_freq): void
{
    $size = strlen($content);
    $index = 0;
    while ($index < $size) {
        $block = substr($content, $index, 5000);
        $index += 5000;
        $info = new File_Info_Block();
        $char_counts = count_chars($block, 1);
        $lines = $char_counts[CHAR_NL] ?? 1;
        $info->hash_freq = $char_counts[CHAR_HASH] ?? 0 / $lines;
        $info->slash_freq = $char_counts[CHAR_HASH] ?? 0 / $lines;
        $info->indent_level = get_line_indents($block);
        $info->frequency = char_freq_analysis($char_counts, $compare_freq);
        $info->lines = $lines;
    }
}


function get_line_indents(string $input): int
{
    preg_match_all("/^\s+[a-zA-Z\$]/mis", $input, $matches, PREG_OFFSET_CAPTURE);
    $spaces = 0;
    $tabs = 0;
    foreach ($matches[0] as $match) {
        $counts = count_chars($match[0], 1);
        $spaces += $counts[32] ?? 0;
        $tabs += $counts[9] ?? 0;
    }
    $lines = max(1, substr_count($input, "\n"));
    $spaces /= $lines;
    $tabs /= $lines;

    $base = min(floor($spaces), 0x7FFF);
    $off = min(floor($tabs), 0x7FFF) << 15;
    return intval($base | $off);
}

function indent_to_space(int $input): int
{
    return $input & 0x7FFF;
}
function indent_to_tab(int $input): int
{
    $n1 = indent_to_space($input);
    $core = $input - $n1;
    return $core << 15;
}


/**
 * find list of malware in a file
 * @param string $path 
 * @return array 
 */
function cms_find_malware(string $path, bool $known, int $batch_size, ScanConfig $config): Malware_List
{
    $file = FileData::new($path);
    if (!$file->exists) {
        debug("cms check file does not exist [%s]", $path);
        return new Malware_List();
    }
    $content = $file->raw();
    return cms_find_malware_str($content, $known, $path, $config);
}

class High_Frequency
{
    /** @var string $content */
    public $content = "";
    /** @var float $frequency */
    public $frequency = 0.0;
}

/**
 * take a code input sample $content, and return the 4K chuck with the highest frequency
 * @param array $frequency_table - the comparison table 
 * @param string $content  - the content to check
 * @return High_Frequency 
 */
function frequency_analysis(array $frequency_table, string $content): High_Frequency
{
    $index = 0;
    $size = strlen($content);
    $freq = new High_Frequency();
    while ($index < $size) {
        $sample = substr($content, $index, 4096);
        $char_counts = count_chars($sample, 1);
        $frequency = char_freq_analysis($char_counts, $frequency_table);
        if ($frequency > $freq->frequency) {
            $freq->content = $sample;
            $freq->frequency = $frequency;
        }
        $index += 4096;
    }
    return $freq;
}

function malware_creator(string $path, string $per_unknown, bool $php_count, $frequency, $max_len, $size, $known): callable
{
    return function (string $content, string $pre, string $post, string $note) use ($known, $per_unknown, $php_count, $frequency, $max_len, $size, $path): Malware {

        $malware = new Malware();
        $malware->pre_text = $pre;
        $malware->post_text = $post;
        $malware->content = $content;
        $malware->note = $note;
        $malware->path = $path;
        $malware->known = $known;
        $malware->ctime = filectime($path);

        $malware->content_indent = get_line_indents($content);
        $malware->pre_indent = get_line_indents($pre);
        $malware->post_indent = get_line_indents($post);
        
        $malware->frequency = $frequency;
        $malware->max_length = $max_len;
        $malware->file_size = $size;
        $malware->per_unknown = $per_unknown;
        $malware->php_count = $php_count;

        //if ($malware->content_indent < $malware->pre_indent && $malware->content_indent < $malware->post_indent) {
        //    $malware->frequency += 3.0;
        //}
        return $malware;
    };
}


/**
 * return a list of all variable names from $contents
 * @param string $contents 
 * @return array array keys are variable names
 */
function get_names(string $contents) {

    $name_list = [];
    $tokens = token_get_all($contents);

    for ($i = 0, $count = count($tokens); $i < $count; $i++) {
        if ($tokens[$i][0] === T_VARIABLE) {
            if ($tokens[$i][0] === T_VARIABLE) {

                $len = strlen($tokens[$i][1]);
                $num_cap = strlen(preg_replace("/[^A-Z]/", "", $tokens[$i][1]));
                // split on caps only if we have mostly lower case.  prevents splitting EvIlStR into single chars
                $split_regex = (($len/3) > $num_cap) ? '/((?=[A-Z])|_|\$)/' : '/(?=_|\$)/';

                $bits = preg_split($split_regex, $tokens[$i][1]);
                foreach ($bits as $bit) {
                    if (!empty($bit)) {

                        $bit_lower = strtolower(str_replace('$', '', $bit));
                        if (in_array($bit_lower, ['_COOKIE', '_POST', '_GET'])) {
                            continue;
                        }
                        $name_list[$bit_lower] = 1;
                    }
                }
            }
        }
    }

    return $name_list;
}


/**
 * map a list of php file token names to a percentage of found tokens
 * @param array $token_names 
 * @return int 
 */
function not_found_percentage(array $token_names, array $allow_tokens) : int {
    $found = $not_found = 0;
    $f = "";
    $n = "";
    foreach ($token_names as $token => $count) {
        // skip the super common tokens
        if ($token == '$_COOKIE' || $token == '$_POST' || $token ==  '$_GET') { continue; }
        // split on caps only if we have mostly lower case.  prevents splitting EvIlStR into single chars
        $bits = preg_split('/((?=[A-Z])|_|\$)/', $token);

        foreach ($bits as $bit) {
            // skip variable names that are 1 char long
            if (strlen($bit) < 2) { continue; }
            if (isset($allow_tokens[$bit])) {
                $f .= ", $bit";
                $found++;
            } else {
                $n .= ", $bit";
                $not_found++;
            }
        }
    }

    // if we don't have enough tokens, we can't really make a good guess
    if ($found + $not_found == 0) {
        $not_found_per = 0;
    } else {
        $not_found_per = round(($not_found / ($found + $not_found)) * 100);
        debug("F[%s] N[%s] %d/%d = per:%d", $f, $n, $found, $not_found, $not_found_per);
    }

    return $not_found_per;
}

/**
 * DUP from cms_find_malware_str
 * @param string $content 
 * @param bool $known 
 * @param string $file_name 
 * @param ScanConfig $config 
 * @return Malware 
 * @throws Exception 
 */
function malware_metrics(string $content, bool $known, string $file_name, ScanConfig $config): Malware 
{
    static $allow_tokens = null;
    static $freq = null;
    $size = strlen($content);
    $m =  new Malware();
    $m->ctime = filectime($file_name);
    $m->file_size = filesize($file_name);
    $m->frequency = 0.0;
    $m->max_length = $size;
    $m->path = $file_name;
    $m->per_unknown = 0;
    $m->unique = random_str(10);

    if ($size < 10) {
        return $m;
    }
    

    debug("search for malware in file [%s] len:%d", $file_name, $size);
    // only load the allow tokens 1x
    $file = (file_exists(getcwd() . "/tokens.json")) ? getcwd() . "/tokens.json" : WAF_ROOT . "cache/tokens2.json";
    if (empty($allow_tokens) || time() > filemtime($file)) {
        debug("reload allow tokens");
        $allow_tokens = FileData::new($file)->read()->un_json()->lines;
    }
    $file = (file_exists(getcwd() . "/frequency.json")) ? getcwd() . "/frequency.json" : WAF_ROOT . "cache/char_frequency.json";
    if ($freq === null || time() > filemtime($file)) {
        $freq = un_json(FileData::new($file)->raw());
    }
    // if file is known, then we will only have a partial diff and we should not try to find tags
    // since there will be none.
    // if the file is unknown with no tags, we can return early!
    // if the file is unknown, we need a php tag to start with
    if (!$known && preg_match_all("/\<\?.*?([^\"']\?>[^\"']|$)/isDSu", $content, $matches)) {
        $c1 = array_reduce(array_values($matches[0]), function ($carry, $x) { // use ($file_name, $content) {
            return $carry . preg_replace("/(\<\?php|\?\>)/", "", $x);
        }, "");
        
        // clean up common junk
        $c1 = preg_replace("/\s*_\w\s*\(\s*[\'\"][^\'\"]+.*\;/", "", $c1);
    }
    // if the file is unknown and has no php tag, we can ignore it
    else if (!$known) {
        // bail out early, it's not actually php SMH
        return $m;
    }
    // the file is known, so we can just use the content since the DIFF function only returns code with php functions 
    else {
        $c1 = $content;
    }

    // trim off comments and svg paths
    // TODO: switch to php token parse...
    // we are already parsing tokens in get_names, so we can just use that
    $line_no = 0;
    // remove comments
    $c2 = preg_replace("/(\/\/|#).*$/m", "", $c1);
    $c3 = preg_replace("/\/\*.*?\*\//ms", "", $c2);
    $c3 = preg_replace("/\<path\s+.*?[\<\>;]/ms", "", $c3);

    $frequency = frequency_analysis($freq, $c3);
    $token_names = get_names("<?php\n$c1");
    $not_found_per = not_found_percentage($token_names, $allow_tokens);
    
    // find the longest line
    $lines = explode("\n", "$c3\n");
    $max_line = "";
    $max_len = array_reduce($lines, function ($carry, $x) use (&$line_no, &$max_line) {
        static $ctr = 0;
        $ctr++;
        $len = strlen($x);
        if ($len > $carry) {
            $line_no = $ctr;
            $max_line = $x;
            return $len;
        }
        return $carry;
    }, 0);

    $m->frequency = $frequency->frequency;
    $m->per_unknown = $not_found_per;
    $m->max_length = $max_len;

    return $m;
}


function cms_find_malware_str(string $content, bool $known, string $file_name, ScanConfig $config): Malware_List
{
    static $allow_tokens = null;
    static $freq = null;
    $size = strlen($content);
    $list = new Malware_List();
    if ($size < 10) {
        return $list;
    }

    /*
    if (contains($file_name, "malware-test")) {
        xdebug_break();
    }
    */
    debug("search for malware in file [%s] len:%d", $file_name, $size);
    // only load the allow tokens 1x
    $file = (file_exists(getcwd() . "/tokens.json")) ? getcwd() . "/tokens.json" : WAF_ROOT . "cache/tokens2.json";
    if ($allow_tokens === null || time() < filemtime($file) + 20) {
        debug("reload allow tokens");
        $allow_tokens = FileData::new($file)->read()->un_json()->lines;
    }
    $file = (file_exists(getcwd() . "/frequency.json")) ? getcwd() . "/frequency.json" : WAF_ROOT . "cache/char_frequency.json";
    if ($freq === null || time() < filemtime($file) + 20) {
        $freq = un_json(FileData::new($file)->raw());
    }

    // if file is known, then we will only have a partial diff and we should not try to find tags
    // since there will be none.
    // if the file is unknown with no tags, we can return early!
    // if the file is unknown, we need a php tag to start with
    if (!$known && preg_match_all("/\<\?.*?([^\"']\?>[^\"']|$)/isDSu", $content, $matches)) {

        $c1 = array_reduce(array_values($matches[0]), function ($carry, $x) { // use ($file_name, $content) {
            return $carry . preg_replace("/(\<\?php|\?\>)/", "", $x);
        }, "");

    }
    // if the file is unknown and has no php tag, we can ignore it
    else if (!$known) {
        // echo "search for malware in file [$file_name]\n$content\n\n";
        // bail out early, it's not actually php SMH
        return $list;
    }
    // the file is known, so we can just use the content since the DIFF function only returns code with php functions 
    else {
        $c1 = $content;
    }

    // trim off comments and svg paths
    // TODO: switch to php token parse...
    // we are already parsing tokens in get_names, so we can just use that
    $php_count = 1;
    $line_no = 0;
    // remove comments
    $c2 = preg_replace("/(\/\/|#).*$/m", "", $c1);
    $c3 = preg_replace("/\/\*.*?\*\//ms", "", $c2);
    $c3 = preg_replace("/\<path\s+.*?[\<\>;]/ms", "", $c3);
    // clean up common junk
    $c3 = preg_replace("/\s*_\w\s*\(\s*[\'\"][^\'\"]+.*\;\s*[\'\"]?\>?/", "", $c3);

    $code_len = strlen($c3);

    $frequency = frequency_analysis($freq, $c3);
    /*
    // get the lowest frequency based on any known existing allowed frequency tables
    if ($frequency->frequency > $config->fn_freq_limit || $frequency->frequency > $config->freq_limit) {
        $file_list = glob(WAF_ROOT . "cache/char_frequency_*.json");
        foreach ($file_list as $file) {
            $freq = un_json(FileData::new($file)->raw());
            $frequency2 = frequency_analysis($freq, $c3);
            if ($frequency2->frequency < $frequency->frequency) {
                $frequency = $frequency2;
            }
        }
    }
    */

    $token_names = get_names("<?php\n$c1");
    $not_found_per = not_found_percentage($token_names, $allow_tokens);
    
    // find the longest line
    $lines = explode("\n", "$c3\n");
    $max_line = "";
    $max_len = array_reduce($lines, function ($carry, $x) use (&$line_no, &$max_line) {
        static $ctr = 0;
        $ctr++;
        $len = strlen($x);
        if ($len > $carry) {
            $line_no = $ctr;
            $max_line = $x;
            return $len;
        }
        return $carry;
    }, 0);

    $malware_factory = malware_creator($file_name, $not_found_per, $php_count, $frequency->frequency, $max_len, $size, $known);


    // long line malware
    if ($config->line_limit > 0 && $max_len > $config->line_limit) {
        debug("LONG LINE MALWARE");
        /** @var Malware $m */
        $m = $malware_factory(
            substr($max_line, 0, 4096),
            substr($lines[$line_no-(max($line_no-1, 0))], 0, 1024),
            substr($lines[(min($line_no+1, count($lines)-1))], 0, 1024),
            "Long line: $max_len characters");
        $list->add($m);
    }

    // we can bail out early iff we have already detected malware
    /*
    if ($list->count() > 0) {
        debug("BASIC MALWARE: maxlen: %d, freq %d, not found %d [%s]", $max_len, $frequency->frequency, $not_found_per, $file_name);
        return $list;
    }
    debug("DETECT MALWARE: maxlen: %d, freq %d, not found %d [%s](%d)", $max_len, $frequency->frequency, $not_found_per, $file_name, $code_len);
    */

    // build the function search regex
    $extra_functions = UPLOAD_FN;
    // check for ord() and chr() call only if file has malware markers...
    if ($not_found_per > 40 || $frequency->frequency > 20) {
        $extra_functions .= "|ord";
    }
    if ($code_len < 5192 || $not_found_per > $config->fn_random_name_per || $max_len > $config->fn_line_limit || $frequency->frequency > $config->fn_freq_limit) {
        debug("adding dynamic function names to regex found:%d, len:%d, freq:%d file[%s]", $not_found_per, $max_len, $frequency->frequency, $file_name);
        $extra_functions .= VAR_FN . USER_FN;
    }
    if ($config->wp_func) {
        $extra_functions .= WP_FN;
    }
    $regex = sprintf(FN1_RX, $extra_functions);

    if (preg_match_all($regex, $c3, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
        for ($i = 0; $i < count($matches) && count($list) < 2; $i++) {
            $fn_name = $matches[$i][0][0];

            // let's inspect 12 characters before the function name, to see if it is a function definition
            $fun_len = max(0, $matches[$i][0][1] - 12);
            $inspect_str = substr($c3, $fun_len, 12);
            if (contains($inspect_str, "function")) {
                continue;
            }


            // check all found matches for header with location redirect
            if (stripos($fn_name, "header") !== false) {
                if (stripos($fn_name, "location") === false &&
                    stripos($fn_name, "$\w") === false) {
                    debug("remove header missing location [%s]", $file_name);
                    continue;
                }
            }

            // if the function call contains call with raw user input, flag it
            if (stripos($fn_name, '$_') !== false) {
                $m = $malware_factory(
                    substr($matches[$i][0][0], 0, 1024),
                    offset_pre_text($c3, $matches[$i][0][1], 512, $size),
                    offset_post_text($c3, $matches[$i][0][1], 512, $size),
                    "Dynamic function call with raw user input: $fn_name");
                $list->add($m);

                continue;
            }

            // if the function call is dynamic, make sure it passes the minimum frequency requirements
            if (strstr($fn_name, "call_user") !== false || strpos(substr($fn_name, 0, 4), "$") !== false) {
                if ($config->fn_freq_limit <= $frequency->frequency || $config->fn_random_name_per <= $not_found_per || $config->fn_line_limit <= $max_len) {
                    $m = $malware_factory(
                        substr($lines[$line_no], 0, 1024),
                        offset_pre_text($c3, $matches[$i][0][1], 512, $size),
                        offset_post_text($c3, $matches[$i][0][1], 512, $size),
                        "Dangerous dynamic function call: $fn_name");// . $frequency->frequency . ", " . $not_found_per . ", " . $max_len . " | " .$config->fn_line_limit);
                    $list->add($m);
                } else {
                    debug("skipping dynamic function call [%s]", $file_name);
                }
                continue;
            }

            //debug("found malware: %s, [%s] size:(%d)", $file_name, $matches[$i][0][0], $code_len);
            // $samples[] = [$matches[$i][0][0], $matches[$i][0][1], "dangerous function call"];
            $m = $malware_factory(
                substr($lines[$line_no], 0, 3196),
                offset_pre_text($c3, $matches[$i][0][1], 512, $size),
                offset_post_text($c3, $matches[$i][0][1], 512, $size),
                "Dangerous function call: $fn_name");
            $list->add($m);
        }

        // compact the array
        debug("%s has %d malware after step 2",  $file_name, count($list));
    }

    

    // no malware found, find malware in non php include files
    if (count($list) < 1 && $config->non_php) {
        //debug("search for include malware in %s", $c3);
        if (preg_match_all("/^[^|;][^\w\'\"\$]*(?:include|require)(?:_once)?\s*([^\);]+)\s*\)\s*?;/mis", $c3, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
        // debug("INCLUDE MALWARE FOUND [%s]", $matches[0][1][0]);
        foreach ($matches as $inc) {
            $check = $inc[1][0];
            /*
            $cnt = count_chars($check);

            $low = array_filter($cnt, function ($x, $y) {
                    return $y < 65;
            }, ARRAY_FILTER_USE_BOTH);
            $high = array_filter($cnt, function ($x, $y) {
                    return $y >= 65;
            }, ARRAY_FILTER_USE_BOTH);

            $sum_low = array_sum($low);
            $sum_high = array_sum($high);

            if ($sum_low > 5 && $sum_low > $sum_high) {
                print_r($matches);
                printf ("sum low/high [%d/%d]\n", $sum_low, $sum_high);
                debug("sum low/high [%d/%d]", $sum_low, $sum_high);
                $m = $malware_factory(
                    $check,
                    offset_pre_text($c3, $inc[0][1], 512, $size),
                    offset_post_text($c3, $inc[0][1], 512, $size),
                    "Including malware PHP file: $check");
                $list->add($m);
            }
            */
            if (icontains($check, ["\x", "chr(", "ord(", "base64("])) {
                $m = $malware_factory(
                    $check,
                    offset_pre_text($c3, $inc[0][1], 512, $size),
                    offset_post_text($c3, $inc[0][1], 512, $size),
                    "Including malware PHP file: $check");
                $list->add($m);
            }
            else {
                debug("check [%s]", $check);
                if (preg_match("/\.(jpg|jpeg|gif|ico|txt|png|webp)\s*['\"]/mis", $check)) {
                    $m = $malware_factory(
                        $check,
                        offset_pre_text($c3, $inc[0][1], 512, $size),
                        offset_post_text($c3, $inc[0][1], 512, $size),
                        "Dangerous include file: $check");
                    $list->add($m);
                    debug("found included image [%d]", count($list));
                }
            }
        }
        }
	}

    // use the custom search expression
    if (strlen($config->extra_regex) > 1) {
        if ($config->extra_regex[0] == "/") {
            if (preg_match($config->extra_regex, $c3, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
                foreach ($matches as $inc) {
                    $m = $malware_factory(
                        $inc[0][0],
                        offset_pre_text($c3, $inc[0][1], 512, $size),
                        offset_post_text($c3, $inc[0][1], 512, $size),
                        "custom regex");
                    $list->add($m);
                }
            }
        } else {
            if ($pos = stripos($c3, $config->extra_regex)) {
                $m = $malware_factory(
                    offset_post_text($c3, $pos, 96, $size),
                    offset_pre_text($c3, $pos, 512, $size),
                    offset_post_text($c3, $pos, 512, $size),
                    "custom regex");
                $list->add($m);
            }
        }
    }

    /*

    // if frequency is high, or the malware is at the beginning/end of the file, return it
    if (count($samples) > 0) {

        foreach ($samples as $sample) {

            //$m = $malware_factory($sample[0], $matches[1], $matches[2], "double php tag");
            //$list->add($m);

            $offset = $sample[1];
            $malware = new Malware();
            $malware->content_offset = $offset;
            $malware->file_size = $size;
            $malware->php_count = $php_count;
            $malware->content = $sample[0];
            $malware->location = 1; //$location;
            $malware->file_size = $size;
            $malware->content_indent = get_line_indents($malware->content);
            $malware->note = $sample[2];

            $match_len = strlen($malware->content);
            $pre1 = max(0, $offset - 256);
            $pre2 = min(256, $offset);
            $malware->pre_text = substr($c3, $pre1, $pre2);
            $malware->pre_indent = get_line_indents($malware->pre_text);

            $offset += $match_len;
            $post2 = min(256, $size - $offset);
            $malware->post_text = substr($c3, $offset, $post2);
            $tmp = substr($c3, $offset + 2048, min(256, $size - $offset - 2048));
            $malware->post_indent = get_line_indents($tmp);

            if ($malware->content_indent < $malware->pre_indent && $malware->content_indent < $malware->post_indent) {
                $frequency->frequency += 3.0;
            }
            $malware->frequency = round($frequency->frequency, 2);
            $list->add($malware);
            //$x  = json_encode($list, JSON_PRETTY_PRINT);
            if (count($list) >= 10) {
                return $list;
            }
        }
    }

    debug("malware size [%d] [%s]", count($list), $file_name);

    // todo: update to UTF8 chars
    // TODO: add FN2_RX
    $dynamic_fn = "/.{0,192}(\\$[_A-Za-z]\p{L}*\s*\([^;]+;).{0,192}/sim";
    if (preg_match_all($dynamic_fn, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER, max(0, $offset-128))) {
        if ($frequency == -1) {
            $path = WAF_ROOT."cache/char_frequency.json";
            $freq = un_json(FileData::new($path)->raw());

            // is the malware near beginning or end?  - ALWAYS REPORT
            // check indentation level, functions per line and comments.
            $frequency = char_freq_analysis($content, $freq);
        }
        $malware[] = $matches;
    }

    // refactor to simpler format
    $final = [];
    foreach($malware as $fn) {
        foreach ($fn as $instance) {
            $final[] = [$instance[0][1], $instance[0][0], $instance[1][1], $instance[1][0]];
        }
    }
    */

    if ($config->freq_limit > 0) {
        // first, lets find all of the files that have some unusual character frequencies
        if ($frequency->frequency > $config->freq_limit) {
            $m = $malware_factory(substr($frequency->content, 0, 2048), "", "", "unusual character frequency");
            $m->frequency = $frequency->frequency;
            debug("FREQUENCY MALWARE");
            $list->add($m);
        }
    }

    // check the percentage of unknown variable names
    if ($config->random_name_per > 0) {
        // if we have a lot of unknown tokens, we can assume it's malware 
        $num_tokens = count($token_names);
        if ($not_found_per > $config->random_name_per && $num_tokens > 3) {
            // remove known names from list
            foreach ($token_names as $name) { if (isset($allow_tokens[$name])) { unset($token_names[$name]); } }
            $list->add($malware_factory(substr($content, 0, 4096), "", "", "{$not_found_per}% Unknown variable names: " .  substr(join(", ", array_keys($token_names)), 0, 2048)));
        }
    }

    return $list;
}

function offset_pre_text(string $content, int $offset, int $len, int $strlen) {
    $len = min(512, $offset);
    return substr($content, max($offset - $len, 0), min($len, $offset));
}

function offset_post_text(string $content, int $offset, int $len, int $strlen) {
    //$mlen = min(512, $len - $offset);
    return substr($content, $offset, $len);
}


// convert bytes to human readable format
function bytes_to_kb($bytes): string
{
    if ($bytes > 0 && $bytes < 130) {
        $bytes = 130;
    } // make sure we always hit at least 0.1Kb
    return round((int)$bytes / 1024, 1) . "Kb";
}


/**
 * take any function $fn and return a function that will accumulate the result
 * $fn first parameter should be the accumulator (or NULL on first call)
 * passing RETURN_LOG to the returned function will return the accumulated result
 * passing CLEAN_LOG to the returned function will reset the accumulator
 * @param callable $fn 
 * @return callable the accumulator function
 */
function accrue_reduce(callable $fn): callable
{
    return function (...$args) use ($fn) {
        static $result = NULL;
        if (isset($args[0])) {
            if ($args[0] === ACTION_RETURN) {
                return $result;
            } else if ($args[0] === ACTION_CLEAN) {
                $result = NULL;
            }
        }
        $result = $fn($result, ...$args);
        return NULL;
    };
}

/**
 * render diff opcodes into a string
 * @param null|string $carry 
 * @param string $opcode 
 * @param string $from 
 * @param int $from_offset 
 * @param int $from_len 
 * @return string 
 */
function opcode_add_only_php(?string $carry, string $opcode, string $from, int $from_offset, int $from_len): string
{
    assert(strlen($from) >= ($from_offset + $from_len), "from_offset + from_len is greater than the length of the string");
    assert(in_array($opcode, ['i', 'd', 'c', 'r', 'z']), "invalid opcode");

    // debug("opcode: [%s] from_offset: %d, from_len: %d, carry: %s", $opcode, $from_offset, $from_len, $carry);
    if ($opcode === 'i') {
        // only insert the code if it contians stuff that looks like php code
        if (preg_match("/\w+\s*\(/", $from)) {
            return $carry . substr($from, $from_offset, $from_len);
        }
    }
    return (empty($carry)) ? "" : $carry;
}

/**
 * this function renders an opcode into a string
 * opcode z resets the string, r will return the created string
 * @param mixed $opcode the opcode to render (must be one of i, d, c, r, z)
 * @param mixed $from the original string
 * @param mixed $from_offset starting offset
 * @param mixed $from_len string length from offset
 * @return string|void 
 */
function opcode_add_only($opcode, $from, $from_offset, $from_len)
{
    static $text = "";
    assert(strlen($from) >= ($from_offset + $from_len), "from_offset + from_len is greater than the length of the string");
    assert(in_array($opcode, ['i', 'd', 'c', 'r', 'z']), "invalid opcode");

    if ($opcode === 'i') {
        // make sure we always grab enough characters BEFORE the diff to capture a <?php tag
        $from_offset = max(0, $from_offset - 6);
        $text .= substr($from, $from_offset, $from_len);
    } else if ($opcode === 'z') {
        $text = "";
    } else if ($opcode === 'r') {
        return $text;
    }
}


// add additional info about the hashes
function enrich_hashes($mh, array $hash): array
{
    debug("enrich1 [%s]", json_encode($hash));
    // TODO: trim down the data in $hash
    // GUARDS
    /*
    if (!isset($hash['path'])) {
        $hash['path'] = $hash['file_path'];
    }
    */

    // abstracted source cms mapping
    $hash['ver'] = version_from_path($hash['file_path']);
    $path_to_source_fn = find_fn("path_to_source");
    $path = $path_to_source_fn($hash["rel_path"], $hash["type"], $hash["ver"], $hash["name"] ?? null);


    $hash['url'] = $path;
    $hash['machine_date'] = machine_date($hash['ctime']);
    $hash['kb1'] = bytes_to_kb($hash['size']);
    $hash['kb2'] = bytes_to_kb($hash['size2'] ?? 0);

    $hash['known'] = ($hash['size2'] ?? 0 > 0) ? "WordPress file " : "Unknown file";
    $hash['real'] = ($hash['size2'] ?? 0 > 0) ? true : false;
    $hash['bgclass'] = ($hash['size2'] ?? 0 > 0) ? "bg-success-soft" : "bg-danger-soft";
    $hash['icon'] = ($hash['size2'] ?? 0 > 0) ? "check" : "x";
    $hash['icon_class'] = ($hash['size2'] ?? 0 > 0) ? "success" : "danger";


    if (!isset($hash['r']) || $hash['r'] !== "PASS") {
        if (!empty($mh)) {
            $ch = http3("GET", $hash['url']);
            $hash['ch'] = $ch;
            curl_multi_add_handle($mh, $ch);
        } else {
            $response = http2("GET", $hash['url']);
            $hash['ch'] = $response->content;
        }
    }

    return $hash;
}



function enrich_hashes2(array $hash, $mh, ?ScanConfig $config = null) : array {

    //debug("enrich_hashes2: %s (%s)", json_encode($hash), gettype($mh));

    $known = true;
    if (isset($hash['ch'])) {
        if (!empty($mh)) {
            $content = curl_multi_getcontent($hash['ch']);
            $l = strlen($content);
            curl_multi_remove_handle($mh, $hash['ch']);
            debug("multi http3 content len: %d", $l);
        } else {
            $content = $hash['ch'];
            $l = strlen($content);
            debug("raw http3 content len: %d", $l);
        }
        if ($l < 300) {
            if (stristr($content, "404 Not Found") !== false) {
                $known = false;
                $content = "";
            }
        }


        unset($hash['ch']);


        $local = file_get_contents($hash['file_path']);
        $fn = accrue_reduce('\BitFire\opcode_add_only_php');
        //opcode_add_only('z', "", 0, 0);
        $op_codes = FineDiff::getDiffOpcodes($content, $local, FineDiff::$paragraphGranularity);
        //debug("opcode [%s]", $op_codes);
        FineDiff::renderFromOpcodes($content, $op_codes, $fn);
        $text = $fn(ACTION_RETURN);
        $hash['diff'] = $text;

        if (strlen($text) > 10) {
            $filename = basename($hash['file_path']);
            debug("diff len: %d [%s] = [%s]\n%s\n\n", strlen($text), $filename, $hash['url'], substr($text, 0, 4096));
            if ($config == null) {
                $config = parse_scan_config(CFG::arr("malware_config"));
            }
            $hash['malware'] = cms_find_malware_str($text, $known, $hash['file_path'], $config);
            /*
            if (count($hash['malware']) > 0) {
                $malware = $hash['malware'][0];
                $malware->url = $hash['url'];
            }
            debug("malware: %s", json_encode($hash['malware']));
            */
        }
    }
    if (!isset($hash['malware'])) {
        $hash['malware'] = new Malware_List();
    }

    return $hash;
}

/**
 * load the profile data from in memory cache, or else from the filesystem
 * @param string $path 
 * @return array 
 */
function load_cms_profile(string $path): array
{
    $profile_path = \BitFire\WAF_ROOT . "cache/profile/{$path}.txt";

    $key = crc32($path);
    $profile = CacheStorage::get_instance()->load_data("profile:$key", null);
    if (empty($profile)) {
        if (file_exists($profile_path)) {
            // read the profile, unserizlize and return result or empty array
            $profile = FileData::new($profile_path)->read()->un_json()->lines;
            if (!isset($profile["^a"])) {
                $profile = PROFILE_INIT;
                $profile['h'] = $_SERVER['HTTP_HOST'] ?? 'na';
            }
        } else {
                $profile = PROFILE_INIT;
        }
    }

    return $profile;
}

function make_sane_path(Request $request): string
{
    // todo: add support for multiple extensions, or no extension
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
    return $sane_path;
}



// make sure we only call this for verified browsers...
// sets profile url name to effect->out
function cms_build_profile(\BitFire\Request $request, bool $is_admin): Effect
{
    // disable profiling except for custom sites
    $effect = Effect::new();
    return $effect;

    // only build profiles for php paths
    if (!ends_with($request->path, ".php")) {
        return $effect;
    }

    // only build a profile if was have  a config dir
    if (!defined(WAF_INI)) {
        return $effect;
    }

    if (defined(WAF_INI)) {
        $path_dir = dirname(WAF_INI, 1) . "/profile";
        if (!file_exists($path_dir)) {
            mkdir($path_dir, 0775, true);
        }
        $sane_path = make_sane_path($request);
        if (!empty($path_dir)) {
            $profile_path = "$path_dir/{$sane_path}.txt";
        }
        // something went wrong!
        else {
            return $effect;
        }
    }


    // TODO: update frequency map
    // only profile php pages
    $profile = load_cms_profile($sane_path);

    $m = array_merge($request->get, $request->post);
    $filter_params = CFG::arr("filtered_logging");
    // update all parameters
    foreach ($m as $param => $value) {
        if (in_array($param, $filter_params)) {
            continue;
        }

        if (isset($profile[$param])) {
            $profile[$param]["a"] += ($is_admin) ? 1 : 0;
            $profile[$param]["u"] += ($is_admin) ? 0 : 1;
            if (count($profile[$param]["v"]) < PROFILE_MAX_VARS) {
                if (!in_array($value, $profile[$param]["v"])) {
                    $profile[$param]["v"][] = $value;
                }
            }
        } else if (count($profile) < PROFILE_MAX_PARAM) {
            $profile[$param] = ["v" => [$value], "u" => (!$is_admin) ? 1 : 0, "a" => ($is_admin) ? 1 : 0];
        }
    }

    // update page counters
    $profile["^a"] += ($is_admin) ? 1 : 0;
    $profile["^u"] += ($is_admin) ? 0 : 1;
    $profile["^g"] += $request->method == "GET" ? 1 : 0;
    $profile["^p"] += $request->method == "POST" ? 1 : 0;
    if (function_exists("\BitFirePlugin\check_user_cap")) {
        if (!isset($profile["^c"])) {
            $profile["^c"] = [];
        }
        $used_caps = check_user_cap(null, null, null, null);
        if (count($used_caps) > 0 && count($profile["^c"]) < PROFILE_MAX_CAPS) {
            $caps = join(",", $used_caps);
            if (isset($profile["^c"][$caps])) {
                $profile["^c"][$caps]++;
            } else {
                $profile["^c"][$caps] = 1;
            }
        }
    }
    // update cache - SYNC WITH load_cms_profile key
    $effect->update(new CacheItem("profile:" . crc32($sane_path), id_fn($profile), id_fn($profile), DAY));

    $effect->out($sane_path)->hide_output(true); // report $sane_path to caller.  do not output if effect is run
    // persist 1 in 5
    if (mt_rand(0, 5) == 1) {
        // strip any possible php tags and make file unreadable...
        $content = str_replace("<?", "PHP_OPEN", json_encode($profile));
        $effect->file(new FileMod($profile_path, $content, FILE_W, 0));
    }

    // backup 1 in 20
    if (mt_rand(0, 20) == 1 || !file_exists($profile_path)) {
        // backup the profile after we serve the page
        register_shutdown_function(function () use ($sane_path, $profile) {
            http2("POST", APP . "profile.php", base64_encode(json_encode(["path" => $sane_path, "profile" => $profile])));
        });
    }

    return $effect;
}



/**
 * default file type for cms files.
 * @OVERRIDE BitFirePlugin\file_type
 * @param string $path path to find type for
 * @return string file type
 */
function file_type(string $path): string
{
    return "custom";
}

/**
 * BitFire hosted file hashes for custom code bases
 * @param string $name 
 * @param string $path 
 * @param string $ver 
 * @return string 
 */
function path_to_source(string $name, string $path, string $ver): string
{
    $client = CFG::str("client_id", "default");
    $source = "archive.bitfire.co/source/{$client}/{$name}/{$ver}/{$path}?auth=" . CFG::str("pro_key");
    return "https://" . str_replace("//", "/", $source);
}

/**
 * return the version number for a package.json or readme.txt file
 * @param mixed $path 
 * @return string 
 */
function package_to_ver(string $carry, string $line): string
{
    if (!empty($carry)) {
        return $carry;
    }
    if (preg_match("/version[\'\":\s]+([\d\.]+)/i", $line, $matches)) {
        return $matches[1];
    }
    return $carry;
}
