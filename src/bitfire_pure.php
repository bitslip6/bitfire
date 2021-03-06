<?php
namespace BitFire;
use TF\MaybeBlock;
use BitFire\Config as CFG;
use TF\Effect as Effect;

use function TF\utc_date;

/**
 * dashboard view helper
 */
function to_meta(array $line) {
    return "rate:".($line['rate']['rr']??0).", valid:".($line['browser']['valid']??0);
}

function code_class(int $code) : int {
    return intval(floor($code / 1000) * 1000);
}

/**
 * returns true if the block should be reported and not blocked...
 */
function is_report(Block $block) : bool {
    $class = code_class($block->code);
    if (!isset(FEATURE_CLASS[$class])) { return true; } // unknown class, set to report mode. PROGRAMMING ERROR

    $value = Config::str(FEATURE_CLASS[$class]);
    return (substr($value, 0, 6) === "report" || substr($value, 0, 5) === "alert");
}


/**
 * helper function for api dashboard
 */
function alert_or_block($config) : string {
    if ($config === 'report' || $config === 'alert') { return 'report'; }
    if (!$config) { return 'off'; }
    return 'block';
}

function map_exception(array $raw) : \BitFire\Exception {
    return new \BitFire\Exception($raw['code']??0, $raw['uuid']??'none', $raw['parameter']??null, $raw['url']??null, $raw['host']??null);
}

/**
 * returns $block if it doesn't match the block exception
 */
function match_block_exception(?Block $block, Exception $exception, string $host, string $url) : ?Block {
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
    \TF\debug("filtered block exception - code: {$exception->code} param: {$exception->parameter} uuid: {$exception->uuid}");
    return NULL;
}


/**
 * load exceptions from disk
 */
function load_exceptions() : array {
    $decoded = false;
    if (file_exists(WAF_DIR."cache/exceptions.json")) {
        $decoded = json_decode(file_get_contents(WAF_DIR."cache/exceptions.json"), true);
    }
    $exceptions = (!$decoded) ? array() : $decoded;
    \TF\debug("loaded exceptions " . count($exceptions));

    return array_map('\BitFire\map_exception', $exceptions);
}

function match_exception(\BitFire\Exception $ex1, \BitFire\Exception $ex2) : bool {
    if ($ex1->code != $ex2->code) { return false; }
    if ($ex1->host != $ex2->host) { return false; }
    if ($ex1->parameter != $ex2->parameter) { return false; }
    if ($ex1->url != $ex2->url) { return false; }
    \TF\debug("match exception");
    return true;
}

/**
 * remove an exception from the list
 */
function remove_exception(\BitFire\Exception $ex) {
    $exceptions = array_filter(load_exceptions(), function(\BitFire\Exception $test) use ($ex) { return ($ex->uuid === $test->uuid) ? false : true; }); 
    file_put_contents(WAF_DIR."cache/exceptions.json", json_encode($exceptions, JSON_PRETTY_PRINT), LOCK_EX);
}

// add an exception to the cache/exceptions.json file, return true if successful
function add_exception(\BitFire\Exception $ex) : bool {
    $exceptions = load_exceptions();
    $ex->uuid = ($ex->uuid !== NULL) ? $ex->uuid : \TF\random_str(8);
    $ex2 = array_filter($exceptions, \TF\compose("\TF\\not", \TF\partial_right("\BitFire\match_exception", $ex)));
    \TF\debug("filtered exceptions " . count($ex2));
    $ex2[] = $ex;
    file_put_contents(WAF_DIR."cache/exceptions.json", json_encode($ex2, JSON_PRETTY_PRINT), LOCK_EX);
    return count($ex2) >= count($exceptions) ;
}


/**
 * returns a maybe of the block if no exception exists
 */
function filter_block_exceptions(Block $block, array $exceptions, \BitFire\Request $request) : MaybeBlock {
    return MaybeBlock::of(array_reduce($exceptions, \TF\partial_right('\BitFire\match_block_exception', $request->host, $request->path), $block));
}

function process_server2(array $server) : Request {
    $url = parse_url($server['REQUEST_URI'] ?? '//localhost/');
    $request = new Request();
    $request->ip = process_ip($server);
    $request->host = parse_host_header($server['HTTP_HOST'] ?? '');
    $request->agent = strtolower($server['HTTP_USER_AGENT'] ?? '');
    $request->path = ($url['path'] ?? '/');
    $request->method = ($server['REQUEST_METHOD'] ?? 'GET');
    $request->port = ($server['SERVER_PORT'] ?? 8080);
    $request->scheme = ($server['REQUEST_SCHEME'] ?? 'http');

    $headers = new Headers();
    $headers->requested_with = ($server['HTTP_X_REQUESTED_WITH'] ?? '');
    $headers->fetch_mode = ($server['HTTP_SEC_FETCH_MODE'] ?? '');
    $headers->encoding = ($server['HTTP_ACCEPT_ENCODING'] ?? '');
    $headers->accept = ($server['HTTP_ACCEPT'] ?? '');
    $headers->content = ($server['HTTP_CONTENT_TYPE'] ?? '');
    $headers->dnt = ($server['HTTP_DNT'] ?? '');
    $headers->upgrade_insecure = ($request->scheme === 'http') ? ($server['HTTP_UPGRADE_INSECURE_REQUESTS'] ?? null) : null;
    $headers->content_type = ($server['HTTP_CONTENT_TYPE'] ?? 'text/html');

    $request->headers = $headers;
    return $request;
}


function process_ip(array $server) : string {
    $header_name = strtoupper(Config::str('ip_header', 'REMOTE_ADDR'));
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
        $r[$key] = (is_array($value)) ? 
            array_reduce($value, '\\BitFire\\get_counts_reduce', array()) :
            get_counts($value);
    }
    return $r;
}

function process_request2(array $get, array $post, array $server, array $cookie = array()) : Request {
    $request = process_server2($server);
    $request->get = \TF\map_mapvalue($get, '\\BitFire\\each_input_param');
    $request->post = \TF\map_mapvalue($post, '\\BitFire\\each_input_param');
    $request->cookies = \TF\map_mapvalue($cookie, '\\BitFire\\each_input_param', false);
    $request->get_freq = freq_map($request->get);
    $request->post_freq = freq_map($request->post);
    $request->post_raw = ($server['REQUEST_METHOD']??'GET' == "POST") ? file_get_contents("php://input") : "";

    return $request;
}


function each_input_param($in, bool $block_profanity = true) : ?string {
    // we don't inspect numeric values because they would pass all tests
    if (is_numeric($in)) { return NULL; }

    // flatten arrays
    if (is_array($in)) { $in = implode("^", $in); }

    $value = strtolower(urldecode($in));
    if ($block_profanity && Config::enabled("block_profanity")) {
        $value = \BitFire\replace_profanity($value);
    }
    return (Config::enabled('decode_html')) ? html_entity_decode($value) : strval($value);
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
    $input2 = \preg_replace('/[\p{L}\d]/iu', '', $input, -1, $count);
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

// return leftmost forwarded for header
// converts a remote_addr into an ipv4 address if at all possible
// handles ipv6 as well 
// PURE
function getIP(string $remote_addr = '127.0.0.2') : string {
    
    $parts = explode(",", $remote_addr);
    return trim($parts[0]??$remote_addr);
    
    // Known prefix
    $v4mapped_prefix_bin = hex2bin('00000000000000000000ffff');

    // Parse
    $addr_bin = inet_pton($remote_addr);
    if ($addr_bin === FALSE ) {
        return $remote_addr;
    }

    // Check prefix, and map ipv4 inside ipv6 address
    if(substr($addr_bin, 0, strlen($v4mapped_prefix_bin)) == $v4mapped_prefix_bin) {
        $addr_bin = substr($addr_bin, strlen($v4mapped_prefix_bin));
    }

    // Convert back to printable address in canonical form
    $x = inet_ntop($addr_bin);
    return ($x == "::1") ? '127.0.0.1' : $x;
}

// return true if  request[path] contains url_match
function url_contains(\BitFire\Request $request, string $url_match) : bool {
    return stristr($request->path, $url_match) !== false;
}




// TODO: add override for additional uniqueness 
function cache_unique(string $prefix = '') : string {
    return $prefix . \TF\take_nth($_SERVER['HTTP_ACCEPT_LANGUAGE']??'', ',', 0) . '-' . $_SERVER['SERVER_NAME']??'default';
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
 */
function post_request(\BitFire\Request $request, ?Block $block, ?IPData $ip_data) : void {
    //@file_put_contents("/tmp/log.txt", "POST REQUEST: " .var_export($block, true). "\n" . var_export($ip_data, true) ."\n\n", FILE_APPEND);
    $response_code = http_response_code();
    if ($block === null && $response_code < 300) { return; } 

    // add browser data if available
    $bot = $whitelist = false;
    $bot_filter = BitFire::get_instance()->bot_filter;
    $valid = -1;
    if ($bot_filter !== null) {
        $bot = $bot_filter->browser->bot??'';
        $valid = $bot_filter->browser->valid??'';
        $whitelist = $bot_filter->browser->whitelist ?? false;
    }

    if ($block === null && !$whitelist) { $block = new Block(31000, "n/a", "unknown bot", $request->agent, 0); }
    else if ($block === null) { $block = new Block(31002, "return code", strval($response_code), $request->agent, 0); }


    $class = code_class($block->code);
    $data = make_post_data($request, $block, $ip_data);
    $data["bot"] = $bot;
    $data["response"] = $response_code;
    $data["whitelist"] = $whitelist;
    $data["valid"] = $valid;
    $data["classId"] = $class;
    $data["headers"] = filter_bulky_headers(headers_list());
    if (function_exists('getallheaders')) {
        $data["rhead"] = \getallheaders();
    }
    
    // cache the last 25 blocks in memory if block file is disabled
    $cache = \TF\CacheStorage::get_instance();
    if (Config::disabled(CONFIG_BLOCK_FILE)) {
        $cache->rotate_data("log_data", $data, 15);
    }
    $ip = ip2long($request->ip);
    $cache->update_data("metrics-".\TF\utc_date('G'), function ($metrics) use ($class, $ip) {
        $metrics[$class] = ($metrics[$class]??0) + 1;
        $ip = ($ip < 100000) ? ip2long('127.0.0.1') : $ip; 
        $metrics[$ip] = ($metrics[$ip]??0) + 1;
        return $metrics;
    }, function() { return \BitFire\BITFIRE_METRICS_INIT; } , \TF\DAY);


    $content = json_encode($data)."\n";
    if (Config::enabled('report_file') && $data["pass"] === true) {
        $file = Config::file('report_file');
        file_put_contents($file, $content, FILE_APPEND);
    }  else if (Config::enabled(CONFIG_BLOCK_FILE)) {
        file_put_contents(Config::file(CONFIG_BLOCK_FILE), $content, FILE_APPEND);
    }
    \TF\bit_http_request("POST", "https://www.bitslip6.com/botmatch/_doc",
    $content, array("Content-Type" => "application/json"));
}

/**
 * create the base log data
 */
function make_post_data(\BitFire\Request $request, Block $block, ?IPData $ip_data) : array {
    
    $data = array(
        "ip" => $request->ip,
        "scheme" => $request->scheme,
        "ua" => $request->agent ?? '',
        "url" => $request->host . ':' . $request->port . $request->path,
        "params" => \BitFire\Pure\param_to_str($request->get, Config::arr("filtered_logging")),
        "post" => \BitFire\Pure\param_to_str($request->post, Config::arr("filtered_logging")),
        "verb" => $request->method,
        "ts" => \TF\utc_microtime(true),
        "tv" => \TF\utc_date("D H:i:s ") . \TF\utc_date('P'),
        "referer" => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
        "eventid" => $block->code,
        "item" => $block->parameter,
        "name" => $block->pattern,
        "match" => $block->value,
        "ver" => BITFIRE_VER,
        "pass" => $block->code === 0 ? true : false,
        "offset" => 0
    );
    
    // add ip data to the log
    if ($ip_data->rr > 0) {
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

    return \BitFire\Pure\ip_block($block, $req, 
        CFG::int(BLOCK_MAP[$block->block_time]??'short_block_time', 600));
}

namespace BitFire\Pure;
use \TF\Effect as Effect;
use \BitFire\Block as Block;
use \BitFire\Request as Request;


/**
 * pure implementation of ip file blocking
 * TEST: test_pure.php:test_ip_block
 */
function ip_block(Block $block, Request $request, int $block_time) : Effect {
    $blockfile = BLOCK_DIR . '/' . $request->ip;
    $exp = time() + $block_time;
    $block_info = json_encode(array('time' => \TF\utc_time(), "block" => $block, "request" => $request));
    return 
        Effect::new()->file(new \TF\FileMod($blockfile, $block_info, LOCK_EX, $exp));

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
