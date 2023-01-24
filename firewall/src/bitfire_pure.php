<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * helper methods for the BitFire, each method in this file should be pure
 */
namespace BitFire;
use Exception;
use BitFire\Config as CFG;
use ThreadFin\CacheStorage;
use ThreadFin\MaybeBlock;
use ThreadFin\Effect as Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;

use const ThreadFin\DAY;

use function ThreadFin\dbg;
use function ThreadFin\find;
use function ThreadFin\httpp;
use function ThreadFin\map_mapvalue;
use function ThreadFin\partial_right as BINDR;
use function ThreadFin\random_str;
use function ThreadFin\set_if_empty;
use function ThreadFin\utc_date;
use function ThreadFin\utc_microtime;
use function ThreadFin\debug;
use function ThreadFin\get_hidden_file;
use function ThreadFin\trace;
use function ThreadFin\un_json;

/**
 * dashboard view helper
 * @depricated
 */
function to_meta(array $line) {
    assert(isset($line["rate"]), "missing required field 'rate'");
    assert(isset($line["rate"]["rr"]), "missing required field ['rate']['rr']");
    assert(isset($line["browser"]), "missing required field ['browser']");
    assert(isset($line["valid"]), "missing required field ['browser']['valild']");
    return "rate:".($line['rate']['rr']??0).", valid:".($line['browser']['valid']??0);
}

function code_class($code) : int {
    assert(!empty($code), "empty code in code_class");
    assert($code < 100000, "invalid code class >10000");
    assert($code > 0, "invalid code class <1");
    return intval(floor($code / 1000) * 1000);
}

/**
 * returns true if the block should be reported and not blocked...
 */
function is_report(Block $block) : bool {
    $class = code_class($block->code);
    assert(isset(FEATURE_CLASS[$class]), "missing $class from FEATURE_CLASS");

    $value = Config::str(FEATURE_CLASS[$class]);
    if (empty($value)) { return false; }

    $r = (substr($value, 0, 6) === "report" || substr($value, 0, 5) === "alert");
    return $r;
}


/**
 * helper function for api dashboard
 */
function alert_or_block($config) : string {
    if ($config == 'report' || $config == 'alert') { return 'report'; }
    if (!$config) { return 'off'; }
    return 'on';
}

function map_exception(array $raw) : \BitFire\Exception {
    return new \BitFire\Exception($raw['code']??0, $raw['uuid']??'none', $raw['parameter']??null, $raw['url']??null, $raw['host']??null);
}



/**
 * returns $block if it doesn't match the block exception
 */
function match_block_exception(?Block $block, \BitFire\Exception $exception, string $host, string $url) : ?Block {
    if ($block == NULL) { return NULL; }
    // make sure that every non default paramater matches
    if ($exception->host !== NULL && $host !== $exception->host) { return $block; }
    if ($exception->url !== NULL && $url !== $exception->url) { return $block; }
    if ($exception->parameter !== NULL && $block->parameter !== $exception->parameter) { return $block; }
    if ($exception->code !== 0) {
        $ex_class = code_class($exception->code);
        $bl_class = code_class($block->code);
        // handle entire blocking class
        if ($ex_class === $bl_class) { return NULL; } 
        // handle specific code class
        if ($block->code !== $exception->code) { return $block; }
    }
    debug("filtered block exception - code: [%d] param [%s], uuid [%s]", $exception->code, $exception->parameter, $exception->uuid);
    return NULL;
}


/**
 * load exceptions from disk, map to object
 * @return array of \BitrFire\Exception
 */
function load_exceptions() : array {
    $file = get_hidden_file("exceptions.json");
    return FileData::new($file)->read()->un_json()->map('\BitFire\map_exception')();
}

function match_exception(\BitFire\Exception $ex1, \BitFire\Exception $ex2) : bool {
    if (!empty($ex1->code) && $ex1->code != $ex2->code) { return false; }
    if (!empty($ex1->host) && $ex1->host != $ex2->host) { return false; }
    if (!empty($ex1->parameter) && $ex1->parameter != $ex2->parameter) { return false; }
    if (!empty($ex1->url) && $ex1->url != $ex2->url) { return false; }
    return true;
}

/**
 * PURE
 * remove an exception from the list
 */
function remove_exception(\BitFire\Exception $ex) : Effect {
    $filename = get_hidden_file("exceptions.json");
    $exceptions = array_filter(load_exceptions(), function(\BitFire\Exception $test) use ($ex) { return ($ex->uuid === $test->uuid) ? false : true; }); 
    $effect = Effect::new(new FileMod($filename, json_encode($exceptions, JSON_PRETTY_PRINT), FILE_W));
    return $effect;
}

/**
 * add exception to list.  returns a list containing only 1 $ex 
 * PURE
 * @param Exception $ex 
 * @param array $exceptions 
 * @return array 
 */
function add_exception_to_list(\BitFire\Exception $ex, array $exceptions = []) : array {
    $ex = set_if_empty($ex, "uuid", random_str(8));
    $match_exception_fn = BINDR("\BitFire\match_exception", $ex);
    // exception is not in the list
    if (!find($exceptions, $match_exception_fn)) {
        $ex->date_utc = date(DATE_RFC3339);
        $exceptions[] = $ex;
    }
    return $exceptions;
}





/**
 * returns a maybe of the block if no exception exists
 */
function filter_block_exceptions(Block $block, array $exceptions, \BitFire\Request $request) : MaybeBlock {
    $r = (array_reduce($exceptions, BINDR('\BitFire\match_block_exception', $request->host, $request->path), $block));

    return MaybeBlock::of($r);
}

function process_server2(array $server) : Request {
    $url = parse_url(filter_input(INPUT_SERVER, 'REQUEST_URI') ?? '//localhost/');
    $request = new Request();
    $request->ip = process_ip($server);
    $request->host = parse_host_header($server['HTTP_HOST'] ?? '');
    $request->agent = strtolower($server['HTTP_USER_AGENT'] ?? '');
    $request->path = ($url['path'] ?? '/');
    $request->method = ($server['REQUEST_METHOD'] ?? 'GET');
    $request->port = intval($server['SERVER_PORT'] ?? 8080);
    $request->scheme = ($server['HTTP_X_FORWARDED_PROTO']??$server['REQUEST_SCHEME']??'http');

    $headers = new Headers();
    $headers->requested_with = ($server['HTTP_X_REQUESTED_WITH'] ?? '');
    $headers->fetch_mode = ($server['HTTP_SEC_FETCH_MODE'] ?? '');
    $headers->encoding = ($server['HTTP_ACCEPT_ENCODING'] ?? '');
    $headers->accept = ($server['HTTP_ACCEPT'] ?? '');
    $headers->content = ($server['HTTP_CONTENT_TYPE'] ?? '');
    $headers->dnt = ($server['HTTP_DNT'] ?? '');
    $headers->upgrade_insecure = ($request->scheme === 'http') ? ($server['HTTP_UPGRADE_INSECURE_REQUESTS'] ?? '') : '';
    $headers->content_type = ($server['HTTP_CONTENT_TYPE'] ?? 'text/html');
    $headers->referer = $_SERVER['HTTP_REFERER'] ?? '';

    $request->headers = $headers;
    return $request;
}


function process_ip(array $server) : string {
    $header_name = Config::str_up('ip_header', 'REMOTE_ADDR');
    $ip = "n/a";
    switch ($header_name) {
        case "FORWARDED":
            $ip = get_fwd_for($server[$header_name] ?? '127.0.0.1');
            break;
        case "REMOTE_ADDR":
        case "X-FORWARDED-FOR":
        default:
            $ip = getIP($server[$header_name] ?? '127.0.0.1');
            break;
    }

    return $ip;
}


function freq_map(array $inputs) : array {
    $r = array();
    foreach($inputs as $key => $value) {
        if (is_string($value)) {
            $r[$key] = get_counts($value);
            continue;
        }
        else if (is_array($value)) {
            $r[$key] = array_reduce($value, '\\BitFire\\get_counts_reduce', []);
            continue;
        } 
        // probably an int, so we wont have any counts...
        $r[$key] = [];
    }
    return $r;
}

function process_request2(array $get, array $post, array $server, array $cookies = []) : Request {
    $request = process_server2($server);
    $fn = BINDR('\\BitFire\\each_input_param', CFG::enabled("block_profanity"));
    $request->get = map_mapvalue($get, $fn);
    $request->post = map_mapvalue($post, $fn);
    $request->cookies = map_mapvalue($cookies, $fn);
    $request->get_freq = freq_map($request->get);
    $request->post_len = $server["CONTENT_LENGTH"] ?? 0;
    if ($server["REQUEST_METHOD"] === "POST") {
        $request->post_raw = file_get_contents("php://input");
        // handle json encoded post data
        if ($server["CONTENT_TYPE"]??"" === "application/json" && !empty($request->post_raw)) {
            $x = json_decode($request->post_raw, true);
            if (is_array($x)) {
                trace("CT:AJOK");
                $request->post = array_merge($request->post, $x);
            } else {
                trace("CT:AJERR");
                debug("JSON ERR [%s]", substr($request->post_raw, 0, 2048));
            }
        }
        $request->post_freq = freq_map($request->post);
    } else {
        $request->post_raw = "N/A";
        $request->post_freq = [];
        $request->post = [];
    }

    return $request;
}

function flatten_list($key, $value = "") : string {
    return (is_array($value)) ? flatten($value) : "^$key:$value";
}

function flatten($data) : string {
    if (is_array($data)) {
        $r = "";
        foreach ($data as $key => $value) {
            $r .= flatten_list($key, $value);
        }
        return $r;
    } else {
        return (string)$data;
    }
}


function each_input_param($in, bool $block_profanity) : ?string {
    // we don't inspect numeric values because they would pass all tests
    if (is_numeric($in)) { return $in; }

    // flatten arrays
    if (is_array($in)) { $in = flatten($in); }

    $value = strtolower(urldecode($in));
    if ($block_profanity) {
        $value = \BitFire\replace_profanity($value);
    }
    return html_entity_decode($value);
}


// remove port numbers from http host headers, always returns a string of some length
// PURE
function parse_host_header(string $header) : string {
    // strip off everything after the first port
    $header .= ':'; // ensure we have one :
    return \strtolower(\substr($header, 0, \strpos($header, ':')));
}

// count characters, but not latin unicode characters with umlots, etc
// PURE
function get_counts(string $input) : array {
    // match any unicode character in the letter or digit category, 
    // and count the remaining characters 
    if (empty($input)) { return array(); }
    $input2 = \preg_replace('/[\p{L}\d]/iu', '', $input);
    if (empty($input2)) { return array(); }
    return \count_chars($input2, 1);
}

function get_counts_reduce(array $carry, string $input) : array {
    // match any unicode character in the letter or digit category, 
    // and count the remaining characters 
    $counts = get_counts($input);
    foreach (\array_keys($counts) as $key) {
        $carry[$key] = (isset($carry[$key])) ?
            $carry[$key] + ($counts[$key] ?? 0):
            ($counts[$key] ?? 0);
    }
    return $carry;
}

/**
 * parse out the forwarded header
 */ 
function get_fwd_for(string $header) : string {
    if (preg_match('/for\s*=\s*["\[]*([0-9\.\:])+/i', $header, $matches)) {
        return $matches[1];
    }
    return $header;
}

// converts a remote_addr into an ipv4 address if at all possible
// handles ipv6 as well 
// PURE
function getIP(string $remote_addr = '127.0.0.2') : string {
    $parts = explode(",", $remote_addr);
    return trim($parts[0]??$remote_addr);
}

// return true if  request[path] contains url_match
function url_contains(\BitFire\Request $request, string $url_match) : bool {
    return stristr($request->path, $url_match) !== false;
}



/**
 * returns filtered profanity 
 * pure
 */
function replace_profanity(string $data) : string {
    return preg_replace('/('.PROFANITY.')/', '@#$!%', $data);
}

/**
 * bulky header match
 */
function bulky_header_match(string $header) : bool {
    return !(
            (stristr($header, "content-security-policy") != false) ||
            (stristr($header, "report-to") != false) ||
            (stristr($header, "referer-policy") != false)
        );
}

/**
 * filter out the bulky headers
 */
function filter_bulky_headers(array $headers) : array {
    return array_filter($headers, '\BitFire\bulky_header_match');
}


/**
 * side effect of logging blocks
 * todo: move out of bitfire_pure
 */
function post_request(\BitFire\Request $request, ?Block $block, ?IPData $ip_data) : void {
    $response_code = http_response_code();

    // add browser data if available
    $bot = $whitelist = false;
    $bot_filter = BitFire::get_instance()->bot_filter;
    $valid = -1;
    if ($bot_filter !== null) {
        $bot = $bot_filter->browser->bot??'';
        $valid = $bot_filter->browser->valid??'';
        $whitelist = $bot_filter->browser->whitelist ?? false;
    }
    if (empty($block)) {
        if (!$bot && $response_code <= 302) { return; } 
        if ($bot && $whitelist) { return; }
    }

    //if ($block === null) { $block = BitFire::new_block(31002, "return code, NOTICE", strval($response_code), $request->agent, 0)(); }

    $class = (!empty($block)) ? code_class((int)$block->code) : 0; 
    $data = make_log_data($request, $block, $ip_data);
    $data["bot"] = $bot;
    $data["response"] = $response_code;
    $data["whitelist"] = $whitelist;
    $data["valid"] = $valid;
    // add debug log if not included in the response headers
    //if (!CFG::enabled('debug_header')) {
    $data["debug"] = debug(null);
    $data["trace"] = trace(null);
    //}
    $data["classId"] = $class;
    $data["headers"] = filter_bulky_headers(headers_list());
    if (function_exists('getallheaders')) {
        $data["rhead"] = \getallheaders();
    }
    
    $cache = CacheStorage::get_instance();
    
    $ip = ip2long($request->ip);
    $cache->update_data("metrics-".utc_date('G'), function ($metrics) use ($class, $ip) {
        $metrics[$class] = ($metrics[$class]??0) + 1;
        $ip = ($ip < 100000) ? ip2long('127.0.0.1') : $ip; 
        $metrics[$ip] = ($metrics[$ip]??0) + 1;
        return $metrics;
    }, function() { return \BitFire\BITFIRE_METRICS_INIT; } , DAY);

    $content = json_encode($data)."\n";
    httpp(APP."blocks.php", $content, array("Content-Type" => "application/json"));
}

/**
 * create the base log data
 */
function make_log_data(\BitFire\Request $request, ?Block $block, ?IPData $ip_data) : array {

    if ($block == NULL) { $block = new Block(0, "n/a", "n/a", "n/a"); }
    
    $data = array(
        "ip" => $request->ip,
        "scheme" => $request->scheme,
        "ua" => $request->agent ?? '',
        "url" => $request->host . ':' . $request->port . $request->path,
        "params" => \BitFire\Pure\param_to_str($request->get, Config::arr("filtered_logging")),
        "post" => \BitFire\Pure\param_to_str($request->post, Config::arr("filtered_logging")),
        "verb" => $request->method,
        "ts" => utc_microtime(),
        "tv" => utc_date("D H:i:s ") . utc_date('P'),
        "eventid" => $block->code,
        "item" => $block->parameter,
        "name" => $block->pattern,
        "match" => $block->value,
        "ver" => BITFIRE_VER,
        "pass" => $block->code === 0 ? true : false,
        "refid" => $block->uuid
    );
    if (isset($_SERVER['HTTP_REFERER'])) {
        $data["referer"] = $_SERVER['HTTP_REFERER'];
    }
    
    // add ip data to the log
    if ($ip_data != NULL && $ip_data->rr > 0) {
        $data['rr1m'] = $ip_data->rr;
        $data['ref'] = $ip_data->ref;
        $data['404'] = $ip_data->ctr_404;
        $data['500'] = $ip_data->ctr_500;
    }

    return $data;
}




const BLOCK_MAP = array(1 => 'short_block_time', 2 => 'medium_block_time', 3 => 'long_block_time');


/**
 * add static IP block for $block->block_time
 * depends on CFG : block time, response_code, allow_ip_block, GLOBAL BLOCK_MAP
 */
function block_ip(?Block $block, ?Request $req) : Effect {
    if (!CFG::enabled('allow_ip_block') || !$block || $block->block_time < 1) { return new Effect(); }

    debug("add IP block");
    return \BitFire\Pure\ip_block($block, $req, 
        CFG::int(BLOCK_MAP[$block->block_time]??'short_block_time', 600));
}

namespace BitFire\Pure;
use \ThreadFin\Effect as Effect;
use \BitFire\Block as Block;
use \BitFire\Request as Request;
use ThreadFin\FileMod;

use const BitFire\FILE_RW;

use function \ThreadFin\partial_right as BINDR;
use function ThreadFin\utc_time;

/**
 * pure implementation of ip file blocking
 * TEST: test_pure.php:test_ip_block
 */
function ip_block(Block $block, Request $request, int $block_time) : Effect {
    $blockfile = \BitFire\BLOCK_DIR . '/' . $request->ip;
    $exp = time() + $block_time;
    $block_info = json_encode(array('time' => utc_time(), "block" => $block, "request" => $request));
    return 
        Effect::new()->file(new FileMod($blockfile, $block_info, FILE_RW, $exp));

}

/**
 * pure param to string with name filtering and sub array support
 */
function param_to_str(array $params, array $filter) : string {
    $post_params = array();
    foreach ($params as $key => &$val) {
        if ($filter[$key] ?? false) {
            $val = "**REDACTED**";
        } else if (is_array($val) === true) {
            $val = implode(',', $val);
        }
        $post_params[] = $key.'='.$val;
    }
    return implode('&', $post_params);
}


/**
 * pure method to json encode $data and append write to $filename 
 * @param string $filename 
 * @param mixed $data 
 * @return Effect 
 */
function json_to_file_effect(string $filename, $data) : Effect {
    $encoder = bindr('json_encode', (strpos($filename, 'pretty') > 0) ? JSON_PRETTY_PRINT : 0);
    $content = join(",\n", array_map($encoder, $data)) . "\n";
    $file = new FileMod($filename, $content, FILE_RW, 0, true);
    return Effect::new()->file($file);
}