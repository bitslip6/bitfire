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

use ArrayAccess;
use ThreadFin\CacheItem;
use ThreadFin\CacheStorage;
use \BitFire\Config as CFG;
use Countable;
use JsonSerializable;
use OutOfBoundsException;
use Serializable;
use stdClass;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;

use const BitFire\APP;
use const BitFire\FILE_W;
use const ThreadFin\DAY;

use function BitFirePlugin\check_user_cap;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\ends_with;
use function ThreadFin\find_const_arr;
use function ThreadFin\find_fn;
use function ThreadFin\httpp;
use function ThreadFin\id_fn;
use function ThreadFin\debug;
use function ThreadFin\machine_date;
use function ThreadFin\trace;
use function ThreadFin\un_json;

const ENUMERATION_FILES = ["readme.txt", "license.txt"];
const PLUGIN_DIRS = ["/plugins/", "/themes/"];
const ACTION_PARAMS = ["do", "page", "action", "screen-id"];
const PACKAGE_FILES = ["readme.txt", "README.txt", "package.json"];
const RISKY_JS = [ "fromCharCode" ];
const FN1_RX = '/[^\w](?:wp_create_user|uudecode|ord|chr|call_user_func|call_user_func_array|hebrev|hex2bin|str_rot13|eval|proc_open|pcntl_exec|exec|shell_exec|system|passthru|move_uploaded_file|stream_wrapper_register|create_function)\s*(?:(?:#[^\n]*\n)|(?:\/\/[^\n]*\n)|(?:\/\*.*?\*\/))?\([^\)]*\)/misS';
const FN2_RX = '/[^\w](?:call_user_func|base64_decode|call_user_func_array|rename)\s*(?:(?:#.*?)|(?:\/\/.*?)|(?;\/\*.*?\*\/))?\(/misS';

const CHAR_NL = 10;
const CHAR_HASH = 61;
const CHAR_SLASH = 73;

const PROFILE_INIT = ["^a" => 0, "^u" => 0, "^g" => 0, "^p" => 0, "^c" => []];
const PROFILE_MAX_PARAM = 30;
const PROFILE_MAX_VARS = 20;
const PROFILE_MAX_CAPS = 20;

$standalone_wp_include = \BitFire\WAF_ROOT . "wordpress-plugin".DS."includes.php";
if (CFG::str("wp_version") || defined("WPINC")) {
    if (file_exists($standalone_wp_include)) {
        trace("wp_alone");
        require_once $standalone_wp_include;
    } else {
        trace("wp_root");
        require_once \BitFire\WAF_ROOT . "includes.php";
    }
} else {
    trace("custom");
    $standalone_custom_include = \BitFire\WAF_ROOT . "custom-plugin".DS."includes.php";
    $standalone_custom_plugin = \BitFire\WAF_ROOT . "custom-plugin".DS."bitfire-plugin.php";
    @include_once $standalone_custom_include;
    @include_once $standalone_custom_plugin;
}



/**
 * a root class all of our classes 
 * @package ThreadFin
 */
class Entity {
} 


/**
 * a <generic> list of errors
 * @package 
 */
abstract class Typed_List implements \ArrayAccess, \Iterator, \Countable, \JsonSerializable {

    private int $_position = 0;
    public array $_list = [];

    // return the number of items in the list
    public function count(): int {
        return count($this->_list);
    }

    // SeekableIterator impl. seek a specific position in the list
    public function seek($position) {
        if (!isset($this->_list[$position])) {
            throw new OutOfBoundsException("invalid seek position ($position)");
        }
  
        $this->_position = $position;
    }

    // SeekableIterator impl. reset the list position to the first element
    public function rewind() : void {
        $this->_position = 0;
    }

    // SeekableIterator impl. return the current index
    public function key() : mixed {
        return $this->_position;
    }

    // SeekableIterator impl. move to the next element
    public function next(): void {
        ++$this->_position;
    }

    // SeekableIterator impl. check if the current position is valid
    public function valid() : bool {
        return isset($this->array[$this->_position]);
    }

    // ArrayAccess impl. set the value at a specific index
    public function offsetSet($index, $value) : void {
        $this->_list[$index] = $value;
    }

    // ArrayAccess impl. remove(unset) the value at a specific index
    public function offsetUnset($index) : void {
        unset($this->_list[$index]);
    }

    // ArrayAccess impl. check if the value at a specific index exists
    public function offsetExists($index) : bool {
        return isset($this->_list[$index]);
    }

    // Sort the list by key values
    public function ksort(int $flags = SORT_REGULAR): bool {
        return ksort($this->_list, $flags);
    }

    public function getIterator(): \Traversable {
        return $this;
    }

    /**
     * This method allows us to call json_encode() and not have a "_list" sub-object 
     * @return array the list data
     */
    public function jsonSerialize() : array {
        return $this->_list;
    }

    // helper method
    public function empty() : bool {
        return empty($this->_list);
    }


    //public abstract function add($item) : void;
    public abstract function offsetGet($index) : mixed;

    // SeekableIterator impl. return the element at $this->_position.
    // override the return type!
    public abstract function current() : mixed;
}



/**
 * malware analysis
 * 
 * @package BitFire
 */
class Malware extends Entity {
    public float $frequency;
    public int $php_count;
    /** @var int $location 0 - beginning, 1 - middle, 2 - end */
    public int $location; 
    public string $pre_text;
    public int $content_offset;
    public string $content;
    public string $post_text;
    public int $pre_indent;
    public int $content_indent;
    public int $post_indent;
    public int $file_size;
    public File_Info_Block $info;
}




/**
 * a typed list of Malware
 */
class Malware_List extends Typed_List {

    /**
     * add a new malware item to the list
     * will only add malware with a frequency > 1.0
     * @param null|TF_Error $error 
     * @return void 
     */
    public function add(?Entity $malware) : void {
        assert($malware instanceOf Malware, "Malware_List can only contain Malware objects");

        if ($malware && $malware->frequency >= 1.0) {
            $this->_list[] = $malware;
        }
    }

    public function offsetGet($index) : Malware {
        return $this->_list[$index] ?? null;
    }

    public function current() : Malware {
        return $this->array[$this->_position];
    }
}


/**
 * file metadata for malware analysis
 * @package BitFire
 */
class File_Info_Block {
    /** @var array float $frequency */
    public array $frequency;
    /** @var array float $slash_freq */
    public array $slash_freq;
    /** @var array float $hash_freq */
    public array $hash_freq;
    /** @var array float $block_freq */
    public array $block_freq;
    /** @var int $indentation_level 0-32656 spaces, 32565-64435 tabs */
    public int $indent_level;
    /** $var int $lines number of lines in this file info block */
    public int $lines;
}



/**
 * pure function to compare content of php code against frequency table
 * @test test_malware/test_char_freq_analysis
 * @param string $content 
 * @param array $compare_freq 
 * @return float 
 * 
 */
function char_freq_analysis(array $test_frequency, array $compare_freq) : float {
    $lines = $test_frequency[10]??1;

    $likely = 0.0;
    // UGLY, split 2x for performance, called a lot
    for ($x = 0; $x<=64; $x++) {
        if (!isset($test_frequency[$x])) { continue; }
        $i = $x+128;
        $test = round(($test_frequency[$x]/$lines), 4);
        if (isset($compare_freq[$i])) {
            if ($test > $compare_freq[$i]["u"]) {
                $rat1 = $test / $compare_freq[$i]["u"];
                if ($rat1 > 1.4) {
                    $likely += ($rat1 - 1.0);
                }
            }
        }
    }
    for ($x = 91; $x<=96; $x++) {
        if (!isset($test_frequency[$x])) { continue; }
        $i = $x+128;
        $test = round(($test_frequency[$x]/$lines), 4);
        if (isset($compare_freq[$i])) {
            if ($test > $compare_freq[$i]["u"]) {
                $rat1 = $test / $compare_freq[$i]["u"];
                if ($rat1 > 1.4) {
                    $likely += ($rat1 - 1.0);
                }
            }
        }
    }
    for ($x = 123; $x<=126; $x++) {
        if (!isset($test_frequency[$x])) { continue; }
        $i = $x+128;
        $test = round(($test_frequency[$x]/$lines), 4);
        if (isset($compare_freq[$i])) {
            if ($test > $compare_freq[$i]["u"]) {
                $rat1 = $test / $compare_freq[$i]["u"];
                if ($rat1 > 1.4) {
                    $likely += ($rat1 - 1.0);
                }
            }
        }
    }

    return $likely;
}

/**
 * return an array of plugin file info in 5K chuck block sizes
 * @param string $content 
 * @return array 
 */
function get_plugin_file_info(string $content, array $compare_freq) : void {
    $size = strlen($content);
    $index = 0;
    while ($index < $size) {
        $block = substr($content, $index, 5000);
        $index += 5000;
        $info = new File_Info_Block();
        $char_counts = count_chars($block, 1);
        $lines = $char_counts[CHAR_NL]??1;
        $info->hash_freq = $char_counts[CHAR_HASH]??0 / $lines;
        $info->slash_freq = $char_counts[CHAR_HASH]??0 / $lines;
        $info->indent_level = get_line_indents($block);
        $info->frequency = char_freq_analysis($char_counts, $compare_freq);
        $info->lines = $lines;
    }
}


function get_line_indents(string $input) : int {
    preg_match_all("/^\s+[a-zA-Z\$]/mis", $input, $matches, PREG_OFFSET_CAPTURE);
    $spaces = 0;
    $tabs = 0;
    foreach ($matches[0] as $match) {
        $counts = count_chars($match[0], 1);
        $spaces += $counts[32]??0;
        $tabs += $counts[9]??0;
    }
    $lines = max(1, substr_count($input, "\n"));
    $spaces /= $lines;
    $tabs /= $lines;

    $base = min($spaces, 0x7FFF);
    $off = min($tabs, 0x7FFF) << 15;
    return intval($base | $off);
}

function indent_to_space(int $input) : int {
    return $input & 0x7FFF;
}
function indent_to_tab(int $input) : int {
    $n1 = indent_to_space($input);
    $core = $input -$n1;
    return $core << 15;
}


/**
 * find list of malware in a file
 * @param string $path 
 * @return array 
 */
function cms_find_malware(string $path) : Malware_List {
    $file = FileData::new($path);
    if (!$file->exists) { debug("cms check file does not exist [%s]", $path); return []; }
    $content = $file->raw();

    $frequency = -1;
    $char_counts = [];
    $list = new Malware_List();


    $php_count = 1;
    if (preg_match_all(FN1_RX, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
        if ($frequency == -1) {
            $freq = un_json(FileData::new(WAF_ROOT."cache/char_frequency.json")->raw());
            $char_counts = count_chars($content, 1);
            $frequency = char_freq_analysis($char_counts, $freq);
        }
        // if the malware is at the front or end of the file, we assume it's not a false positive
        $location = 1;
        $offset = max(1024, $file->size * 0.1);
        $num_matches = count($matches);
        // is the malware at the beginning or end of the file?
        if ($matches[0][0][1] < $offset) {
            $location = 0;
        } else if ($matches[$num_matches-1][0][1]+$offset > $file->size) {
            $location = 2;
        }
        $php_count = substr_count($content, "<?php");
        $frequency += ($php_count > 1) ? 1.0 : 0.0;
        $frequency += ($location != 1) ? 1.0 : 0.0;
    }

    // if frequency is high, or the malware is at the beginning/end of the file, return it
    if ($frequency > 1.0) {

        foreach ($matches as $match) {


            // debug(" # found malware [%s]", print_r($match, true));

            $offset = $match[0][1];
            $malware = new Malware();
            $malware->content_offset = $offset;
            $malware->file_size = $file->size; 
            $malware->php_count = $php_count;
            $malware->content = $match[0][0];
            $malware->location = $location;
            $malware->file_size = $file->size;
            $malware->content_indent = get_line_indents($malware->content);

            $match_len = strlen($malware->content);
            $pre1 = max(0, $offset-256);
            $pre2 = min(256, $offset);
            $malware->pre_text = substr($content, $pre1, $pre2);
            $malware->pre_indent = get_line_indents($malware->pre_text);

            $offset += $match_len;
            $post2 = min(256, $file->size-$offset);
            $malware->post_text = substr($content, $offset, $post2);
            $tmp = substr($content, $offset+2048, min(256, $file->size-$offset-2048));
            $malware->post_indent = get_line_indents($tmp);

            if ($malware->content_indent < $malware->pre_indent && $malware->content_indent < $malware->post_indent) {
                $frequency += 1.0;
            }
            $malware->frequency = round($frequency, 2);
            $list->add($malware);
            $x  = json_encode($list, JSON_PRETTY_PRINT);
            if (count($list) >= 10) { return $list; }
        }
    }

    // todo: update to UTF8 chars
    // TODO: add FN2_RX
    /*
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

    //$r = [$final, $frequency];
    return $list;
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
        $hash["rel_path"] = $hash["o2"];
    }
    if (empty($ver) && $hash["r"] != "MISS") {
        $ver = $hash["tag"];
    }
    if (empty($ver)) {
        $ver = "1.0";
    }

    // abstracted source cms mapping
    $path_to_source_fn = find_fn("path_to_source");
    $path = $path_to_source_fn($hash["rel_path"], $hash["type"], $ver, $hash["name"]??null);

    
    $hash['mtime'] = filemtime($out);
    $hash['url'] = $path;
    $hash['ver'] = $ver;
    $hash['doc_root'] = $doc_root;
    $hash['machine_date'] = machine_date($hash['mtime']);
    $hash['known'] = ($hash['size2']??0 == 0) ? "Unknown file" : "WordPress file";
    $hash['real'] = ($hash['size2']??0 == 0) ? false : true;

    $hash['kb1'] = bytes_to_kb($hash['size']);
    $hash['kb2'] = bytes_to_kb($hash['size2']??0);
    $hash['bgclass'] = ($hash['size2']??0 > 0) ? "bg-success-soft" : "bg-danger-soft";
    $hash['icon'] = ($hash['size2']??0 > 0) ? "check" : "x";
    $hash['icon_class'] = ($hash['size2']??0 > 0) ? "success" : "danger";
    $hash['malware'] = cms_find_malware($out);

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

function make_sane_path(Request $request) : string {
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
function cms_build_profile(\BitFire\Request $request, bool $is_admin) : Effect {
    $effect = Effect::new();
    if (!ends_with($request->path, ".php")) { return $effect; }

    $sane_path = make_sane_path($request);
    $profile_path = \BitFire\WAF_ROOT . "cache/profile/{$sane_path}.txt";

        
    // TODO: update frequency map
    // only profile php pages
    $profile = load_cms_profile($sane_path);

    $m = array_merge($request->get, $request->post);
    $filter_params = CFG::arr("filter_logging");
    // update all parameters
    foreach ($m as $param => $value) {
        if (in_array($param, $filter_params)) { continue; }

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
    if (function_exists("\BitFirePlugin\check_user_cap")) {
        if (!isset($profile["^c"])) { $profile["^c"] = []; }
        $used_caps = check_user_cap(null, null, null, null);
        if (count($used_caps) > 0 && count($profile["^c"]) < PROFILE_MAX_CAPS) {
            $caps = join(",", $used_caps);
            if (isset($profile["^c"][$caps])) { $profile["^c"][$caps]++; }
            else { $profile["^c"][$caps] = 1; }
        }
    }
    // update cache - SYNC WITH load_cms_profile key
    $effect->update(new CacheItem("profile:".crc32($sane_path), id_fn($profile), id_fn($profile), DAY));

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
