<?php declare(strict_types=1);
namespace BitFire;
use TF\Maybe;

function to_meta(array $line) {
    return "5m:".$line['rate']['rr_5m'].", 1m:".$line['rate']['rr_1m']." ,v:".$line['browser']['valid'].", ref:".$line['rate']['ref'];
}

/**
 * returns true if the block should be reported and not blocked...
 */
function is_report(Block $block) : bool {
    $class = floor(($block->code / 1000)) * 1000;
    $feature_name =  FEATURE_CLASS[$class] ?? 'bitfire_enabled';

    return (Config::str($feature_name) === "report");
}

/**
 * filter reporting features
 */
function reporting(Block $block, array $request) {
    $data = array('time' => date('r'),
        'exec' => number_format(microtime(true) - $GLOBALS['m0'], 6). ' sec',
        'ip' => BitFire::get_instance()->_request[REQUEST_IP],
        'block' => $block,
        'request' => $request);
    $bf = BitFire::get_instance()->bot_filter;
    if ($bf != null) {
        $data['browser'] = $bf->browser;
        $data['rate'] = $bf->ip_data;
    }
    $opts = (strpos(Config::str(CONFIG_REPORT_FILE), 'pretty') > 0) ? JSON_PRETTY_PRINT : 0;
    file_put_contents(Config::str(CONFIG_REPORT_FILE), json_encode($data, $opts) . "\n", FILE_APPEND);
}

/**
 * helper function for api dashboard
 */
function alert_or_block($config) : string {
    if ($config === 'report' || $config === 'alert') { return 'report'; }
    if (!$config) { return 'off'; }
    return 'block';
}

/**
 * returns a maybe of the block if no exception exists
 */
function filter_block_exceptions(Block $block, array $exceptions) : Maybe {
    return Maybe::of(array_reduce($exceptions, '\BitFire\match_block_exception', $block));
}

function process_server(array $server) : array {
    $url = parse_url($server['REQUEST_URI'] ?? '//localhost/');
    return array(
        REQUEST_HOST => parse_host_header($server['HTTP_HOST'] ?? ''),
        "PATH" => $url['path'] ?? '/',
        REQUEST_IP => process_ip($server),
        REQUEST_METHOD => ($server['REQUEST_METHOD'] ?? 'GET'),
        "PORT" => $server['SERVER_PORT'] ?? 8080,
        'REQUESTED_WITH' => ($server['HTTP_X_REQUESTED_WITH'] ?? null),
        'FETCH_MODE' => ($server['HTTP_SEC_FETCH_MODE'] ?? null),
        REQUEST_UA => strtolower($server['HTTP_USER_AGENT'] ?? ''),
        REQUEST_SCHEME => ($server['REQUEST_SCHEME'] ?? 'http'),
        REQUEST_ACCEPT => ($server['HTTP_ACCEPT_ENCODING']??'') . ' . ' . ($server['HTTP_ACCEPT_ENCODING']??''),
        'ACCEPT' => ($server['HTTP_ACCEPT'] ?? ''),
        'UPGRADE_INSECURE' => (($server['REQUEST_SCHEME']??'http') == 'http') ? ($server['HTTP_UPGRADE_INSECURE_REQUESTS'] ?? '') : '',
        'CONTENT_TYPE' => ($server['HTTP_CONTENT_TYPE'] ?? 'text/html')
    );
}

function process_ip(array $server) : string {
    $header_name = strtoupper(Config::str('ip_header', 'REMOTE_ADDR'));
    $ip = "n/a";
    switch ($header_name) {
        case "X-FORWARDED-FOR":
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


// parse the request into a single passable object
// PURE
function process_request(array $get, array $post, array $server, array $cookie = array()) : array {

    $request = process_server($server);
    $request["GET"] = \TF\map_mapvalue($get, '\\BitFire\\each_input_param');
    $request["POST"] = \TF\map_mapvalue($post, '\\BitFire\\each_input_param');
    $request['FULL'] = http_build_query($request['GET']) . " POST " .http_build_query($request['POST']);
    $request[REQUEST_COOKIE] = $cookie;

        
    $get_counts = array();
    // count character frequencies
    foreach($request['GET'] as $key => $value) {
        $get_counts[$key] = (is_array($value)) ? 
            array_reduce($value, '\\BitFire\\get_counts_reduce', array()) :
            get_counts($value);
    }
    $request['GETC'] = $get_counts;
    
    $post_counts = array();
    // count character frequencies
    foreach($request['POST'] as $key => $value) {
        $post_counts[$key] = (is_array($value)) ? 
            array_reduce($value, 'BitFire\\get_counts_reduce', array()) :
            get_counts($value);
    }
    $request['POSTC'] = $post_counts;

    // set the ajax flag
    $request['ajax'] = is_ajax($request);

    return $request;
}

function each_input_param($in) {
    // we don't inspect numeric values because they would pass all tests
    if (is_numeric($in)) { return null; }

    // flatten arrays
    if (is_array($in)) { $in = implode("^", $in); }

    $value = strtolower(urldecode($in));
    if (Config::enabled("block_profanity")) {
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
            $carry[$key] + $counts[$key] :
            $counts[$key];
    }
    return $carry;
}


/**
 * returns true if the request is an ajax request
 * looks for an 'ajax' parameter to $request with the cached value of this call
 * if not found, inspects the request and returns the inspection result
 * TODO: add testing for some file download types? (*cough WF *cough)
 * PURE
 */
function is_ajax(array $request) : bool {
    if (isset($request['ajax'])) { return $request['ajax']; }
    
    $ajax = false;
    if ($request[REQUEST_METHOD] !== 'GET') { $ajax = true; }
    // path is a  wordpress ajax request
    else if (\stripos($request['PATH'], "ajax.php") !== false) { $ajax = true; }
    
    // accept || content type is requested as javascript
    // if the client is looking for something other than html, it's ajax
    else if (\stripos($request['ACCEPT'], 'text/html') === false &&
        \stripos($request['CONTENT_TYPE'], 'text/html') === false) { $ajax = true; }

    // often these are set on fetch or xmlhttp requests
    else if ($request['REQUESTED_WITH'] || $request['FETCH_MODE'] === 'cors' ||
        $request['FETCH_MODE'] === 'websocket') { $ajax = true; }

    // fall back to using upgrade insecure (should only come on main http requests), this should work for all major browsers
    else {
        $ajax = ($request[REQUEST_SCHEME] == "http" && ($request['UPGRADE_INSECURE'] === null || \strlen($request['UPGRADE_INSECURE']) < 1)) ? true : false;
    }
    return $ajax;
}

// opposite of is_ajax
function is_not_ajax(array $request) {
    return !is_ajax($request);
}

/**
 * parse out the forwarded
 */
function get_fwd_for(string $header) {
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
function url_contains(array $request, string $url_match) : bool {
    return stristr($request['PATH'], $url_match) !== false;
}


/**
 * returns $block if it doesn't match the block exception
 */
function match_block_exception(Block $block, array $exception) : Block {
    return $block;
}

// TODO: add override for additional uniqueness 
function cache_unique() {
    $lang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ',';
    $parts = explode(',', $lang);
    return $parts[0] ?? '';
}

/**
 * returns filtered profanity 
 * pure
 */
function replace_profanity(string $data) : string {
    return preg_replace('/('.PROFANITY.')/', '@#$!%', $data);
}



function post_request(array $request, ?Block $block, ?array $ip_data) {
    $response_code = http_response_code();
    if ($block === null && $response_code < 300) { return; } 

    // add browser data if available
    $bot = $whitelist = false;
    $bot_filter = BitFire::get_instance()->bot_filter;
    $valid = -1;
    if ($bot_filter !== null) {
        $bot = $bot_filter->browser['bot'] ?? false;
        $valid = $bot_filter->browser['valid'] ?? -1;
        $whitelist = $bot_filter->browser[AGENT_WHITELIST] ?? false;
    }

    if ($block === null && !$bot) { return; }
    if ($block === null && !$whitelist) { $block = new Block(31000, "n/a", "unknown bot", $request[REQUEST_UA], 0); }
    else if ($block === null) { $block = new Block(31002, "return code", strval($response_code), $request[REQUEST_UA], 0); }


    $class = intval($block->code / 1000) * 1000;
    $data = make_post_data($request, $block, $ip_data);
    $data["bot"] = $bot;
    $data["response"] = $response_code;
    $data["whitelist"] = $whitelist;
    $data["valid"] = $valid;
    $data["classId"] = $class;
    
    // cache the last 15 blocks
    $cache = \TF\CacheStorage::get_instance();
    $cache->rotate_data("log_data", $data, 15);
    $ip = ip2long($request[REQUEST_IP]);
    $cache->update_data("metrics-".date('G'), function ($metrics) use ($class, $ip) {
        $metrics[$class] = ($metrics[$class]??0) + 1;
        $ip = ($ip < 100000) ? ip2long('127.0.0.1') : $ip; 
        $metrics[$ip] = ($metrics[$ip]??0) + 1;
        return $metrics;
    }, \BitFire\BITFIRE_METRICS_INIT, \TF\DAY);


    $content = json_encode($data)."\n";
    if (Config::enabled('report_file') && $block->code === 31002) {
        file_put_contents(Config::str('report_file'), $content, FILE_APPEND);
    }  else if (Config::enabled('block_file')) {
        file_put_contents(Config::str('block_file'), $content, FILE_APPEND);
    }
    \TF\bit_http_request("POST", "https://www.bitslip6.com/botmatch/_doc",
    $content, array("Content-Type" => "application/json"));
}

function make_post_data(array $request, Block $block, ?array $ip_data) {
    
    $data = array(
        "ip" => $request[REQUEST_IP],
        "scheme" => $request[REQUEST_SCHEME],
        "ua" => $request[REQUEST_UA] ?? '',
        "url" => $request[REQUEST_HOST] . ':' . $request['PORT'] . $request[REQUEST_PATH],
        "params" => param_to_str($request['GET'], true),
        "post" => param_to_str($request['POST'], true),
        "verb" => $request[REQUEST_METHOD],
        "ts" => microtime(true),
        "tv" => date("D H:i:s ") . date('P'),
        "referer" => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
        "eventId" => $block->code,
        "item" => $block->parameter,
        "name" => $block->pattern,
        "match" => $block->value,
        "ver" => BITFIRE_VER,
        "pass" => $block->code === 0 ? true : false,
        "offset" => 0
    );
    
    // add ip data to the log
    if (isset($ip_data['rr1m'])) {
        $data['rr1m'] = $ip_data['rr_1m'];
        $data['rr5m'] = $ip_data['rr_5m'];
        $data['ref'] = $ip_data['ref'];
        $data['404'] = $ip_data['404'];
        $data['500'] = $ip_data['500'];
    }

    return $data;
}

/**
 * pure param to string with name filtering and sub array support
 */
function param_to_str(array $params, $filter = false) {
    $post_params = array();
    $filtered_names = Config::arr("filtered_logging");
    foreach ($params as $key => &$val) {
        if ($filtered_names[$key] ?? false) {
            $val = "**FILTERED**";
        } else if (is_array($val) === true) {
            $val = implode(',', $val);
        }
        $post_params[] = $key.'='.$val;
    }
    return implode('&', $post_params);
}



const BLOCK_MAP = array(1 => 'short_block_time', 2 => 'medium_block_time', 3 => 'long_block_time');
function block_ip($block, array $ip_data) : void {
    if (!Config::enabled('allow_ip_block') || !$block || $block->block_time < 1) { return; }
   
    $blockfile = BLOCK_DIR . $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    @file_put_contents($blockfile, $ip_data['ref'] ?? \substr(\uniqid(), 5, 8));

    $exp = time() + Config::int(BLOCK_MAP[$block->block_time]);
    \touch($blockfile, $exp);
    
    \http_response_code(Config::int('response_code', 500));
    include WAF_DIR . DS . "views/block.php";
}
