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
use FineDiff;
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
use function ThreadFin\http2;
use function ThreadFin\machine_date;
use function ThreadFin\mark;
use function ThreadFin\trace;
use function ThreadFin\un_json;

const ENUMERATION_FILES = ["readme.txt", "license.txt"];
const PLUGIN_DIRS = ["/plugins/", "/themes/"];
const ACTION_PARAMS = ["do", "page", "action", "screen-id"];
const PACKAGE_FILES = ["readme.txt", "README.txt", "package.json"];
const RISKY_JS = ["fromCharCode"];
const FN1_RX = '/[\s\(\)](?:wp_create_user|header|mail|move_uploaded_file|uudecode|ord|chr|call_user_func|call_user_func_array|hebrev|hex2bin|str_rot13|eval|proc_open|pcntl_exec|exec|shell_exec|system|passthru|move_uploaded_file|stream_wrapper_register|create_function|\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)\s*(?:\[[^\]]*?\])?\s*(?:(?:#[^\n]*\n)|(?:\/\/[^\n]*\n)|(?:\/\*.*?\*\/))?\(/misS';
//const FN1_RX = '/[^\w](?:wp_create_user|uudecode|ord|chr|call_user_func|call_user_func_array|hebrev|hex2bin|str_rot13|eval|proc_open|pcntl_exec|exec|shell_exec|system|passthru|move_uploaded_file|stream_wrapper_register|create_function|\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff])*\s*(?:\[[^\]]*?\])?\s*(?:(?:#[^\n]*\n)|(?:\/\/[^\n]*\n)|(?:\/\*.*?\*\/))?\(/misS';
const FN2_RX = '/[^\w](?:call_user_func|base64_decode|call_user_func_array|rename)\s*(?:(?:#.*?)|(?:\/\/.*?)|(?;\/\*.*?\*\/))?\(/misS';
// [value] => /(\s|\.)(wp_bp_activity|wp_bp_activity_meta|wp_bp_invitations|wp_bp_notifications|wp_bp_notifications_meta|wp_bp_optouts|wp_bp_xprofile_data|wp_bp_xprofile_fields|wp_bp_xprofile_groups|wp_bp_xprofile_meta|wp_commentmeta|wp_comments|wp_links|wp_options|wp_postmeta|wp_posts|wp_signups|wp_term_relationships|wp_term_taxonomy|wp_termmeta|wp_terms|wp_usermeta|wp_users|wp_wfblockediplog|wp_wfblocks7|wp_wfconfig|wp_wfcrawlers|wp_wffilechanges|wp_wffilemods|wp_wfhits|wp_wfhoover|wp_wfissues|wp_wfknownfilelist|wp_wflivetraffichuman|wp_wflocs|wp_wflogins|wp_wfls_2fa_secrets|wp_wfls_settings|wp_wfnotifications|wp_wfpendingissues|wp_wfreversecache|wp_wfsnipcache|wp_wfstatus|wp_wftrafficrates)(\b|\.|\-\-\s|#)/i

const CHAR_NL = 10;
const CHAR_HASH = 61;
const CHAR_SLASH = 73;

const PROFILE_INIT = ["^a" => 0, "^u" => 0, "^g" => 0, "^p" => 0, "^c" => []];
const PROFILE_MAX_PARAM = 30;
const PROFILE_MAX_VARS = 20;
const PROFILE_MAX_CAPS = 20;

$standalone_wp_include = \BitFire\WAF_ROOT . "wordpress-plugin" . DS . "includes.php";
$standalone_custom_include = \BitFire\WAF_ROOT . "custom-plugin" . DS . "includes.php";
if (CFG::str("wp_version") || defined("WPINC") || !file_exists($standalone_custom_include)) {
    if (file_exists($standalone_wp_include)) {
        trace("wp_alone");
        require_once $standalone_wp_include;
    } else if (file_exists(\BitFire\WAF_ROOT . "includes.php")) {
        trace("wp_root");
        include_once \BitFire\WAF_ROOT . "includes.php";
    }
} else {
    trace("custom");
    $standalone_custom_plugin = \BitFire\WAF_ROOT . "custom-plugin" . DS . "bitfire-plugin.php";
    @include_once $standalone_custom_include;
    @include_once $standalone_custom_plugin;
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
abstract class Typed_List implements \ArrayAccess, \Iterator, \Countable, \JsonSerializable
{

    protected int $_position = 0;
    public array $_list = [];

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
        $this->_list[$index] = $value;
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
    public float $frequency;
    public int $php_count;
    /** @var int $location 0 - beginning, 1 - middle, 2 - end */
    public int $location;
    public string $pre_text;
    public int $content_offset;
    public string $content;
    public string $post_text;
    public string $note;
    public int $pre_indent;
    public int $content_indent;
    public int $post_indent;
    public int $file_size;
    public File_Info_Block $info;
}




/**
 * a typed list of Malware
 */
class Malware_List extends Typed_List
{

    /**
     * add a new malware item to the list
     * will only add malware with a frequency > 1.0
     * @param null|TF_Error $error 
     * @return void 
     */
    public function add(?Entity $malware): void
    {
        assert($malware instanceof Malware, "Malware_List can only contain Malware objects");

        $this->_list[] = $malware;
    }

    public function offsetGet($index): Malware
    {
        return $this->_list[$index] ?? null;
    }

    public function current(): Malware
    {
        return $this->_list[$this->_position];
    }
}


/**
 * file metadata for malware analysis
 * @package BitFire
 */
class File_Info_Block
{
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
function cms_find_malware(string $path, bool $known, int $batch_size): Malware_List
{
    $file = FileData::new($path);
    if (!$file->exists) {
        debug("cms check file does not exist [%s]", $path);
        return [];
    }
    $content = $file->raw();
    return cms_find_malware_str($content, $known, $batch_size, $path);
}

class High_Frequency
{
    public string $content = "";
    public float $frequency = 0.0;
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

function malware_creator(string $file_name, bool $known, int $batch_size): callable
{
    return function (string $content, string $pre, string $post, string $note) use ($file_name): Malware {

        $malware = new Malware();
        $malware->pre_text = $pre;
        $malware->post_text = $post;
        $malware->content = $content;
        $malware->note = $note;
        $malware->frequency = 0.0;

        $malware->content_indent = get_line_indents($content);
        $malware->pre_indent = get_line_indents($pre);
        $malware->post_indent = get_line_indents($post);

        if ($malware->content_indent < $malware->pre_indent && $malware->content_indent < $malware->post_indent) {
            $malware->frequency += 3.0;
        }
        return $malware;
    };
}

function cms_find_malware_str(string $content, bool $known, int $batch_size, string $file_name = ""): Malware_List
{
    $size = strlen($content);
    $samples = [];
    $frequency = -1;
    $list = new Malware_List();

    $malware_factory = malware_creator($file_name, $known, $batch_size);
    $freq = un_json(FileData::new(WAF_ROOT . "cache/char_frequency.json")->raw());
    // if file is known, then we will only have a partial diff and we should not try to find tags
    // since there will be none.
    // if the file is unknown with no tags, we can return early!
    // if the file is unknown, we need a php tag to start with
    if (!$known && preg_match_all("/\<\?.*?(\?>|$)/isDSu", $content, $matches)) {
        $c1 = array_reduce(array_values($matches[0]), function ($carry, $x) use ($file_name, $content) {
            return $carry . preg_replace("/(\<\?php|\?\>)/", "", $x);
        }, "");
    }
    // if the file is unknown and has no php tag, we can ignore it
    else if (!$known) {
        // bail out early, it's not actually php SMH
        file_put_contents("/tmp/debug.log", "no php found in $file_name\n\n$content\n\n", FILE_APPEND);
        return $list;
    }
    // the file is known, so we can just use the content since the DIFF function only returns code with php functions 
    else {
        $c1 = $content;
    }
    $frequency = frequency_analysis($freq, $c1);
    //file_put_contents("/tmp/freq.log", json_encode([$file_name, $frequency->frequency, $frequency->content], JSON_PRETTY_PRINT) . "\n", FILE_APPEND);
    // first, lets find all of the files that have some unusual character frequencies
    if ($frequency->frequency > 19.1) {
        $m = $malware_factory($frequency->content, "", "", "unusual character frequency");
        $m->frequency = $frequency->frequency;
        //$list->add($m);
    }


    $php_count = 1;
    $log = ["file" => $file_name];
    // remove comments
    $c2 = preg_replace("/(\/\/|#).*$/m", "", $c1);
    $c3 = preg_replace("/\/\*.*?\*\//ms", "", $c2);
    $c3 = preg_replace("/\<path\s+.*?[\<\>;]/ms", "", $c3);
    $code_len = strlen($c3);

    // if (contains($file_name, "crew")) { debug("crew c3: [%s]", $c3); }

    // double php tag for known files is a red-flag
    /*
    if ($known && preg_match("/(.{5,128}\?>)\s*(<\?php.{32,128})/mis", $c3, $matches)) {
        $log["match2"] = $matches;
        $m = $malware_factory("(appended PHP tags)", $matches[1], $matches[2], "double php tag");
        $list->add($m);
    }
    */

    if (preg_match_all(FN1_RX, $c3, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
        for ($i = 0; $i < count($matches); $i++) {
            // check all found matches for header with location redirect
            if (stripos($matches[$i][0][0], "header") !== false) {
                if (
                    stripos($matches[$i][0][0], "location") === false &&
                    stripos($matches[$i][0][0], "$\w") === false
                ) {
                    debug("remove header missing location [%s]", $file_name);
                    continue;
                }
            }
            // check for common pattern in known files
            if (($known || $frequency->frequency <= 1.0) &&
                (contains($matches[$i][0][0], "call_user_func") || contains($matches[$i][0][0], "$"))
            ) {
                debug("remove ($known) call_user_func|\$fn [%s] freq (%f)", $file_name, $frequency->frequency);
                continue;
            }

            // lets inspect 12 characters before the function name, to see if it is a function definition
            $fun_len = max(0, $matches[$i][0][1] - 12);
            $inspect_str = substr($c3, $fun_len, 12);
            if (contains($inspect_str, "function")) {
                debug("not adding function definition names [%s]", $matches[$i][0][0]);
                continue;
            }

            debug("found malware: %s, [%s] size:(%d)", $file_name, $matches[$i][0][0], $code_len);

            /*
            // unknown files have malware listed as "front of file" (default)
            $location = 0;
            // if the malware is at the front or end of the file, we assume it's not a false positive
            if ($known || $batch_size > 5) {
                // if the file is known, we check the location of the found malware, must be near the front or end
                $location = 1;
                $offset = min(max(1512, $code_len * 0.1), 4096);
                $num_matches = count($matches);
                // is the malware at the beginning or end of the file?
                if ($matches[0][0][1] < $offset) {
                    $location = 0;
                } else if ($matches[$num_matches-1][0][1]+$offset > $code_len) {
                    $location = 2;
                }
                $frequency->frequency += ($location != 1) ? 1.1 : 0.0;
            }
            */


            $samples[] = $matches[$i][0];
        }

        // compact the array
        debug("%s has %d malware after step 2",  $file_name, count($samples));

        if (count($samples) > 0) {
            $log["match1"] = $samples;
        }
    }

    // no malware found, find malware in non php include files
    if (count($samples) < 1) {
        if (preg_match_all("/\s?(?:include|require)(?:_once)?\s*[^Ss\/]\(?([^\.\)]*)\.(:?jpg|jpeg|png|webp|gif)\w+['\"\s\)]+;/mis", $c3, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
            // if the malware is at the front or end of the file, we assume it's not a false positive
            $log["match3"] = $matches;
            for ($i = 0; $i < count($matches); $i++) {
                $samples[] = $matches[$i][0];
            }
        }
    }

    $log["frequency"] = $frequency;
    $log["samples"] = $samples;
    // file_put_contents("/tmp/malware.log", json_encode($log, JSON_PRETTY_PRINT), FILE_APPEND);

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
function enrich_hashes(string $ver, string $doc_root, int $batch_size, array $hash): array
{
    // TODO: trim down the data in $hash
    // GUARDS
    if (!isset($hash['path'])) {
        $hash['path'] = $hash['file_path'];
    }


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
    $path = $path_to_source_fn($hash["rel_path"], $hash["type"], $ver, $hash["name"] ?? null);


    $hash['mtime'] = filemtime($out);
    $hash['url'] = $path;
    $hash['ver'] = $ver;
    $hash['doc_root'] = $doc_root;
    $hash['machine_date'] = machine_date($hash['mtime']);
    $hash['kb1'] = bytes_to_kb($hash['size']);
    $hash['kb2'] = bytes_to_kb($hash['size2'] ?? 0);

    $hash['known'] = ($hash['size2'] ?? 0 > 0) ? "WordPress file " : "Unknown file";
    $hash['real'] = ($hash['size2'] ?? 0 > 0) ? true : false;
    $hash['bgclass'] = ($hash['size2'] ?? 0 > 0) ? "bg-success-soft" : "bg-danger-soft";
    $hash['icon'] = ($hash['size2'] ?? 0 > 0) ? "check" : "x";
    $hash['icon_class'] = ($hash['size2'] ?? 0 > 0) ? "success" : "danger";


    //mark("prefetch");
    if (!isset($hash['r']) || $hash['r'] !== "PASS") {
        $local = file_get_contents($hash['path']);
        $result = http2("GET", $path);
        if (empty($result["content"]) && contains($path, "plugin")) {
            $trunk = preg_replace("/tags\/[^\/]+/", "trunk", $path);
            $result = http2("GET", $trunk);
        }


        $fn = accrue_reduce('\BitFire\opcode_add_only_php');
        //opcode_add_only('z', "", 0, 0);
        $op_codes = FineDiff::getDiffOpcodes($result['content'], $local, FineDiff::$paragraphGranularity);
        //debug("opcode [%s]", $op_codes);
        FineDiff::renderFromOpcodes($result['content'], $op_codes, $fn);
        $text = $fn(ACTION_RETURN);
        $hash['diff'] = $text;

        $hash['malware'] = cms_find_malware_str($text, $hash['size2']??0 > 0, $batch_size, $hash['path']);
    } else {
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
    $effect = Effect::new();
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
            httpp(APP . "profile.php", base64_encode(json_encode(["path" => $sane_path, "profile" => $profile])));
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
