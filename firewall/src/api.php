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

use ThreadFin\CacheStorage;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;
use ThreadFin\MaybeStr;
use BitFire\Config as CFG;
use LDAP\Result;
use RuntimeException;
use SplFixedArray;
use ThreadFin\CacheItem;
use ThreadFin\Maybe;
use ThreadFinDB\Credentials;
use ThreadFinDB\DB;

use const ThreadFin\DAY;
use const ThreadFin\HOUR;

use function BitFireBot\find_ip_as;
use function BitFireSvr\add_ini_value;
use function BitFireSvr\hash_file3;
use function BitFireSvr\parse_scan_config;
use function BitFireSvr\update_ini_fn;
use function BitFireSvr\update_ini_value;
use function BitFireWP\wp_parse_credentials;
use function BitFireWP\wp_parse_define;
use function ThreadFin\machine_date;
use function ThreadFin\compact_array;
use function ThreadFin\contains;
use function ThreadFin\dbg;
use function ThreadFin\en_json;
use function ThreadFin\ends_with;
use function ThreadFin\file_recurse;
use function ThreadFin\find_fn;
use function ThreadFin\HTTP\http2;
use function ThreadFin\partial_right as BINDR;
use function ThreadFin\partial as BINDL;
use function ThreadFin\random_str;
use function ThreadFin\un_json;
use function ThreadFin\debug;
use function ThreadFin\debugN;
use function ThreadFin\file_index;
use function ThreadFin\file_replace;
use function ThreadFin\get_hidden_file;
use function ThreadFin\HTTP\http_wait;
use function ThreadFin\icontains;
use function ThreadFin\output_profile;
use function ThreadFin\trace;
use function ThreadFinDB\dump_database;

require_once \BitFire\WAF_SRC . "server.php";
require_once \BitFire\WAF_SRC . "cms.php";


/**
 * block metrics
 */
class Metric {
    public $data = array();
    public $total = 0;
}

/**
 * make $dir_name if it does not exist, mode FILE_RW, 0755, etc
 * @impure
 * @return bool true if directory was newly created, or if it exists
 */
function make_dir(string $dir_name, int $mode) : bool {
    if (!file_exists(dirname($dir_name))) {
        return mkdir(dirname($dir_name), $mode, true);
    }
    return true;
}



/**
 * add an exception to exceptions.json
 * @pure
 * @API
 */
function rem_api_exception(\BitFire\Request $r) : Effect {
    assert(isset($r->post['uuid']), "uuid is required");
    $uuid = $r->post['uuid'];

    // an effect and the exception to add
    $effect = Effect::new();

    // load exceptions from disk
    $file = get_hidden_file("exceptions.json");
    $exceptions = FileData::new($file)->read()->un_json();
    if ($exceptions === null) {
        debug("json read error in exceptions.json");
        return $effect->api(false, "exception file corrupted");
    } else {
        $removed = array_filter($exceptions(), function ($x) use ($uuid) {
            return (strtolower($x['uuid']) != strtolower($uuid));
        });
    }

    // nothing added, exception already exists
    if (count($removed) == count($exceptions())) {
        $effect->api(false, "exception does not exist");
    }
    // new exception added
    else if (count($removed) < count($exceptions())) {
        $effect->api(true, "exception removed");
        $effect->file(new FileMod($file, json_encode($removed, JSON_PRETTY_PRINT), FILE_W));
    }
    // any other case
    else {
        $effect->api(false, "unable to remove exception from $file");
    }

    // return the result
    return $effect;
}

/**
 * add an exception to exceptions.json
 * @pure
 * @API
 */
function add_api_exception(\BitFire\Request $r) : Effect {
    assert(isset($r->post['path']), "path is required");
    assert(isset($r->post['code']), "code is required");
    $param = $r->post['param']??NULL;
    $r->post["action"] = "add_exception";
    http2("POST", APP."zxf.php", base64_encode(json_encode($r->post)));

    // an effect and the exception to add

    // special handling of bot exceptions
    $class = code_class($r->post['code']);
    $effect = Effect::new();
    // don't add exceptions for bot blocking
    if ($r->post['code'] == 27000 || $r->post['code'] == 25001 || $r->post['code'] == 24002 || $r->post['code'] == 24001) {
        return $effect->api(true, "exception added", []);
    }

    /*
    if ($class == 24000) {
        assert(isset($r->post['param']), "param is required");
        assert(isset($r->post['value']), "value is required");
        $value = $r->post['value']??NULL;

        //->update_ini_value("botwhitelist[$param_crc]", "AS{$as}", NULL)->api(true, "exception added");
        //$effect = update_ini_fn(function () use ($param_crc, $as, $value) { return "\n; bot exception from:[$value]\nbotwhitelist[$param_crc] = \"AS$as\"\n"; }, WAF_ROOT . "/cache/whitelist_agents.ini", true);

        //$effect = add_ini_value("botwhitelist[$param]", "AS{$as}", NULL, WAF_ROOT . "/cache/whitelist_agents.ini");
        $effect->api(true, "exception added");
        return $effect;
    }
    */

    // all other exceptions, previous block returns...
    $ex = new \BitFire\Exception((int)$r->post['code'], random_str(8), $param, $r->post['path']);

    // custom exception rules here:
    if ($ex->code == FAIL_FILE_BLOCK) {
        $ex->host = null;
    }

    // load exceptions from disk
    $file = get_hidden_file("exceptions.json");
    $exceptions = FileData::new($file)->read()->un_json()->map('\BitFire\map_exception');

    // add new exception (will not double add)
    $updated_exceptions = add_exception_to_list($ex, $exceptions());

    // nothing added, exception already exists
    if (count($updated_exceptions) == count($exceptions())) {
        $effect->api(false, "exception already exists");
    }
    // new exception added
    else if (count($updated_exceptions) > count($exceptions())) {
        $effect->api(true, "exception added", $updated_exceptions);
        $effect->file(new FileMod($file, json_encode($updated_exceptions, JSON_PRETTY_PRINT), FILE_W));
    }
    // any other case
    else {
        $effect->api(false, "unable to add exception to $file");
    }

    // return the result
    return $effect;
}



/**
 * @pure
 * @param Request $r 
 * @return void 
 */
function download(\BitFire\Request $r) : Effect {
    assert(isset($r->get["filename"]), "filename is required");

	$effect = Effect::new();
    $root = \BitFireSvr\cms_root() . "/";
	$filename = trim($r->get['filename'], "/");
    //$path = $root . $filename;
    $path = $r->get['filename'];

    // alert / block download
    if ($filename == "alert" || $filename == "block") {
        $effect->header('Content-Type', 'application/json');
        // TODO: move to server functions
        $config_name = ($filename == "alert") ? get_hidden_file("alerts.json") : get_hidden_file("blocks.json");
        $report_file = \ThreadFin\FileData::new(CFG::file($config_name))->read();
        $report_file->apply_ln('array_reverse')
            ->map('\ThreadFin\un_json');
        $data = json_encode($report_file->lines, JSON_PRETTY_PRINT);
        $filename .= ".json";
    }
	else {
        $effect->header('Content-Type', 'application/x-php');
        // FILE NAME GUARD
        if (! ends_with($filename, "php") || contains($filename, RESTRICTED_FILES)) {
            return $effect->api(false, "invalid file.", ["filename" => $filename]);
        }
        // if file does not exist, or is not in the web root...
        $file = FileData::new($path);
        if (!$file->exists) { return $effect->api(false, "no file.", ["filename" => $path]); }
        else if (!contains($path, $root)) { return $effect->api(false, "Refusing to download files outside of WordPress", ["filename" => $path]); }
        $data = $file->raw();
    }

    if (!isset($r->get['direct'])) {
        $base = basename($filename);
        $effect->header("content-description", "File Transfer")
        ->header('Content-Disposition', 'attachment; filename="' . $base . '"')
        ->header('Expires', '0')
        ->header('Cache-Control', 'must-revalidate')
        ->header('Pragma', 'private')
        ->header('Content-Length', (string)strlen($data));
    }
    $effect->out($data);
    return $effect;
}

function malware_files(\BitFire\Request $request) : Effect {
    $effect = Effect::new();
    $malware_file = WAF_ROOT . "/cache/malware_files.json";
    $data = [
        "total" => intval($request->post["total"]),
        "malware" => intval($request->post["malware"]),
        "time" => time()];
    $file = new FileMod($malware_file, en_json($data), FILE_RW);
    $effect->file($file);
    $effect->api(true, "malware files updated");
    return $effect; 
}

function archive_source(\BitFire\Request $request) : Effect {
    $effect = Effect::new();
    include_once WAF_SRC . "db.php";
    if (!defined("DB_USER")) {
        @include_once CFG::str("cms_root") . "wp-config.php";
    }
    $db_user     = defined( 'DB_USER' ) ? DB_USER : '';
	$db_password = defined( 'DB_PASSWORD' ) ? DB_PASSWORD : '';
	$db_name     = defined( 'DB_NAME' ) ? DB_NAME : '';
	$db_host     = defined( 'DB_HOST' ) ? DB_HOST : '';
    $credentials = new \ThreadFinDB\Credentials($db_user, $db_password, $db_host, $db_name);
    $out_stream = gzopen("bitfire.sql.gz", "wb6");
    $out_fn = BINDR('\ThreadFinDB\gz_output_fn', $out_stream);
    //\ThreadFinDB\dump_database($credentials, $db_name, $out_fn);
    \ThreadFinDB\dump_database($credentials, $out_fn);
    gzclose($out_stream);
    $num_bytes = $out_fun();
    $effect->api(true, "output $num_bytes bytes of SQL", ["bytes" => $num_bytes, "out_file" => "bitfire.sql.gz"]);
    return $effect;
}


/**
 * BROKEN SINCE REFACTOR
 * todo: deprecate and perform this function client side
 * todo: if we don't get a response, check if the root directory exists and mark the plugin/theme as inactive
 */
function diff(\BitFire\Request $request, ?ScanConfig $scanConfig = null) : Effect {
    require_once WAF_SRC . "cms.php";

    $root = \BitFireSvr\cms_root();
    if ($root == null) {
        return Effect::new()->api(false, "WordPress not found");
    }

    // verify valid url
    $url = $request->post["url"]??"";


    if ($scanConfig == null) {
        $scanConfig = parse_scan_config(CFG::arr("malware_config"));
    }

    // invalid request...
    if (!isset($request->post['file_path'])) {
        return Effect::new()->api(false, "Invalid request. file_path parameter required.");
    }

    // TODO: TEST THIS MALWARE SCAN FUNCTION
    if (empty($url)) {
        $malware = cms_find_malware($request->post['file_path'], false, 1, $scanConfig) ;
        return Effect::new()->api(true, "malware listing", ["compressed" => false, "malware" => $malware, "file_path" => $request->post["file_path"]]);
    }

    // TODO: move regex to plugin function
    if (!preg_match("/^https?:\/\/\w+\.svn.wordpress.org\//", $url)) {
        return Effect::new()->api(false, "invalid URL: $url");
    }
    // verify valid path
    $path = $request->post["file_path"];
    //if (!preg_match("#$root#", $path) || !ends_with($path, "php") || contains($path, "config")) {
    if (!ends_with($path, "php")) {
        return Effect::new()->api(false, "invalid file: $path");
    }
    $local_file = FileData::new($path);
    $local = $local_file->raw();
    $len = strlen($local);
    // hard coded WP files that are okay. todo: update with hashes
    $response = http2("GET", $url, "", [
        "User-Agent" => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36",
        "Accept" => "*/*",
        "sec-ch-ua-platform" => "Linux",
        "upgrade-insecure-requests" => "1"]);

    // empty response is 286 bytes (FYI)
    $url2 = preg_replace("/\/tags\/[^\/]+\//", "/trunk/", $url);
    // if we don't have a 200, then 0 out the 404 response.
    if ($url != $url2 && (!$response->success || (!in_array("http/1.1 200", $response->headers) && $response->http_code != 200))) { 
        $response = http2("GET", $url2, "", [
            "User-Agent" => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36",
            "Accept" => "*/*",//"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng",
            "sec-ch-ua-platform" => "Linux",
            "upgrade-insecure-requests" => "1"]);

        // if we don't have a 200, then 0 out the 404 response.
        if (!$response->success || (!in_array("http/1.1 200", $response->headers) && $response->http_code != 200)) { 
            $response->success = false;
            $response->content = "";
        }
    }

    $success = $response->success;// && $local_file->exists;

    if (!$success) {
        $malware = cms_find_malware($request->post['file_path'], false, 1, $scanConfig) ;
        return Effect::new()->api(true, "malware listing", ["compressed" => false, "malware" => $malware, "file_path" => $request->post["file_path"]]);
    }

    $data = array("url" => $request->post['url'], "file_path" => $request->post['file_path'], "compressed" => false);
    if (function_exists("zlib_encode")) {
        $data["zlib_local"] = base64_encode(zlib_encode($local, ZLIB_ENCODING_RAW));
        $data["zlib_orig"] = base64_encode(zlib_encode($response->content, ZLIB_ENCODING_RAW));
        $data["compressed"] = true;
    } else {
        $data["local"] = base64_encode($local);
        $data["orig"] = base64_encode($response->content);
    }
    $effect = Effect::new()->api($success, "data", $data);
    return $effect;
}


/*
function ip_map_domain(string $ip) : MaybeStr {
    $s = MaybeStr::of($ip);
    $s->map('gethostbyaddr');
    $s->map('gethostbynamel');
    $s->

    return $s;
}
*/

function ip_to_domain(string $ip) : ?string {
    $domain = gethostbyaddr($ip);
    debug("fwd: %s [%s]", $ip, $domain);
    if (!empty($domain)) {
        $ips = gethostbynamel($domain);
        if (!empty($ips)) {
            debug("reverse: [%s]", $ips);
            if (in_array($ip, $ips)) {
                if (preg_match("/([a-zA-Z0-9_-]+\.(?:[a-zA-Z]+|xn-\w+))\.?$/", $domain, $matches)) {
                    return $matches[1];
                }
            }
        }
    }
    return null;
}

function bot_action(\BitFire\Request $request) : Effect {

    $effect = Effect::new();
    $id = intval($request->post["bot"]);

    $bot_dir = get_hidden_file("bots");
    $info_file = "{$bot_dir}/{$id}.json";
    if ($request->post["action"] == "rm") {
        $effect->unlink($info_file);
        $effect->api(true, "bot remove", ["id" => $id]);
        return $effect;
    }
    $fd = FileData::new($info_file);
    if ($fd->exists) {
        trace("BOT_RM");
        $bot_data = unserialize($fd->raw(), ["allowed_classes" => ["BitFire\BotInfo"]]);
        if (!$bot_data) {
            $effect->unlink($info_file);
            return $effect->api(false, "unable to load bot file $id");
        }
    } else {
        return $effect->api(false, "bot file $id does not exist");
        
    }
    if ($request->post["action"] == "no") {
        trace("BOT_NO");
        $bot_data->net = "!";
        $effect->api(true, "bot block all", ["id" => $id, "domain" => $bot_data->domain, "net" => $bot_data->net]);
    }
    else if ($request->post["action"] == "any") {
        trace("BOT_ANY");
        $bot_data->net = "*";
        $bot_data->valid = 1;
        $effect->api(true, "bot allow any", ["id" => $id, "domain" => $bot_data->domain, "net" => $bot_data->net]);
    }
    else if ($request->post["action"] == "auth") {//} && contains($bot_data->net, ["!", "*"])) {
        trace("BOT_AUTH");
        $bot_data->net = "";
        $bot_data->domain = "";
        $bot_data->valid = 1;
        $lookup = [];
        $domain_list = [];
        // debug("bot ips [%s]", $bot_data->ips);
        foreach($bot_data->ips as $ip => $value) {
            debug("ip [%s]", $ip);
            if (strlen($ip) < 7) { continue; }
            if (isset($lookup[$ip])) { continue; }
            $lookup[$ip] = true;

            /*
            $domain = gethostbyaddr($ip);
            if (!empty($domain)) {
                if (!strpos($bot_data->domain, $domain) !== false) {
                    $bot_data->domain .= ",$domain";
                }
            }
            */
            $domain = ip_to_domain($ip);
            if (!in_array($domain, $domain_list)) {
                $domain_list[] = $domain;
            }
            $as = find_ip_as($ip);
            if (!empty($bot_data->net)) {
                if (!strpos($bot_data->net, $as) !== false) {
                    $bot_data->net .= ",$as";
                }
            }
        }
        $bot_data->domain = implode(",", $domain_list);
        // make sure we have a domain or net
        if (empty($bot_data->domain) && empty($bot_data->net)) {
            $bot_data->net = "*";
        }
        debug("allowed domain [%s], net [%s]", $bot_data->domain, $bot_data->net);
        $effect->api(true, "bot auth", ["id" => $id, "domain" => $bot_data->domain, "net" => $bot_data->net]);
    }


    // update the bot access file, but keep the modification time the same
    $mtime = filemtime($info_file);
    $effect->file(new FileMod($info_file, serialize($bot_data), FILE_RW, $mtime));
    return $effect;
}


function general_scan(\BitFire\Request $request) : Effect {
    require_once WAF_SRC . "diff.php";
    require_once WAF_SRC . "cms.php";
    $root = \BitFireSvr\cms_root();
    ini_set("max_execution_time", 245);
    $offset = intval($request->post['offset']);

    $config = parse_scan_config(CFG::arr("malware_config"));
    $index_file = get_hidden_file("file.index");
    if ($offset == 0) {
        $reg_ex = ($config->non_php == 1) ? NULL : "/.*\.php/";
        $ctx = fopen($index_file, "w+");
        $write_fn = BINDL('fwrite', $ctx);
        file_index($root, $reg_ex, $write_fn);
        fclose($ctx);
        copy($index_file, $index_file . ".bak");
    }

    // for reading php files
    if (defined("BitFirePRO")) { stream_wrapper_restore("file"); }

    $batch_size = 200;
    $list = scan_filesystem($index_file, $offset, $batch_size, parse_scan_config(CFG::arr("malware_config")));

    $list2 = [];
    foreach ($list as $item) {
        $req_fn = '/[\@\s\(\);\/](?:header|\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*|mail|fwrite|file_put_contents|create_function|call_user_func|call_user_func_array|uudecode|hebrev|hex2bin|str_rot13|eval|proc_open|pcntl_exec|exec|shell_exec|system|passthru%s*)\s*(?:\[[^\]]*?\])?\s*(?:(?:#[^\n]*\n)|(?:\/\/[^\n]*\n)|(?:\/\*.*?\*\/))?\(\s*(?:[\.\$_]*)?/misS';
        if (!preg_match($req_fn, file_get_contents($item->path), $matches)) {
            //file_put_contents("/tmp/unset.txt", $item->path . "\n$req_fn\n\n", FILE_APPEND);
        } else {
            $list2[] = $item;
            //file_put_contents("/tmp/set.txt",  $item->path . "\n" . print_r($matches, true) . "\n\n", FILE_APPEND);
        }
    }


    file_put_contents("/tmp/out.txt", json_encode(array_values($list2), JSON_PRETTY_PRINT) . "\n\n", FILE_APPEND);

    $effect = Effect::new()->api(true, "hashed " . $list->num_scanned . " skipped " . $list->num_skipped . " mem: " . memory_get_peak_usage(), array("basename" => basename($root), "complete" => $list->complete, "found" => count($list2), "dir" => $root, "batch_size" => $batch_size, "skip_count" => $list->num_skipped, "file_count" => $list->num_scanned, "data" => base64_encode(json_encode(array_values($list2)))));
    if (count($list) > 0) {
        http2("POST", "https://bitfire.co/malware.php", base64_encode(json_encode($list->_list)));
    }
    return $effect;
}


/**
 * need to test these 2 enrichment functions
 * @param mixed $ver 
 * @param mixed $dir_without_plugin_name 
 * @param mixed $hash_slice 
 * @return array<array-key, mixed> 
 */
function batch_enrich($hash_slice, ?ScanConfig $config = null) {
    assert(count($hash_slice) < 24, "curl multi can only handle 24 at a time");

    if ($config == null) {
        $config = parse_scan_config(CFG::arr("malware_config"));
    }

    //debug("batch_enrich (%s) (%s) (%s)", $ver, $dir_without_plugin_name, json_encode($hash_slice));

    if (function_exists("curl_multi_init")) {
        $mh = curl_multi_init();
    } else {
        $mh = null;
    }
    $enrich_fn = BINDL('\BitFire\enrich_hashes', $mh);

    // WTF DOES THIS NOT WORK? SEE debug.log [updraftplus]
    $enriched1 = array_map($enrich_fn, $hash_slice);
    //debug("enriched1 : (%s)", json_encode($enriched1));

    // debug("waiting... (%s)", json_encode($hash_slice));
    if (!empty($mh)) {
        http_wait($mh);
    }
    $enriched2 = array_map(BINDR('\BitFire\enrich_hashes2', $mh, $config), $enriched1);
    //debug("enriched2 : (%s)", json_encode($enriched2));

    if (function_exists("curl_multi_close")) {
        curl_multi_close($mh);
    }

    return $enriched2;
}


/**
 * get 24 hour block sums
 */
function get_block_24sum() : array {
    $result = array();
    $cache = CacheStorage::get_instance();
    for($i=0; $i<25; $i++) {
        $data = $cache->load_data("metrics-$i", null);
        if ($data == null) { continue; }
        $sum = 0;
        foreach ($data as $code => $value) {
            if($code < 100000) { $sum += $value; }
        }
        $result[] = $sum;
    }
    
    return $result;
}

/**
 * get totals grouped by code
 */
function get_block_24groups() : Metric {
    $metric = new Metric();
    $cache = CacheStorage::get_instance();
    for($i=0; $i<25; $i++) {
        $data = $cache->load_data("metrics-$i", null);
        if ($data === null) { continue; }
        foreach ($data as $code => $cnt) {
            if ($code === "challenge" || $code === "valid") { continue; }
            if ($code < 100000 && $cnt > 0) { 
                $tmp = $metric->data[$code] ?? 0;
                $metric->data[$code] = $tmp + $cnt;
                $metric->total += $cnt;
            }
        }
    }
    return $metric;
}

function get_ip_24groups() : Metric {

    $total = 0;
    $summary = array();
    $cache = CacheStorage::get_instance();
    for($i=0; $i<25; $i++) {
        $data = $cache->load_data("metrics-$i", null);
        if ($data == null) { continue; }
        foreach ($data as $code => $cnt) {
            if ($code === "challenge" || $code === "valid") { continue; }
            if ($code > 100000 && $cnt > 0) { 
                $tmp = long2ip($code);
                $summary[$tmp] = ($summary[$tmp] ?? 0) + $cnt;
                $total += $cnt;
            }
        }
    }

    return parse_24_groups($summary, $total);
}

function parse_24_groups(array $summary, int $total) : \BitFire\Metric {
    
    $metric = new Metric();
    $metric->total = $total;

    uasort($summary, function ($a, $b) {
        if ($a == $b) { return 0; }
        return ($a < $b) ? -1 : 1;
    });

    if (count($summary) > 10) {
        $metric->data = array_slice($summary, 0, 10);
        $inc = array_sum(array_values(array_slice($summary, 10)));
        $metric->data['other'] = $inc;
    } else {
        $metric->data = $summary;
    }

    return $metric;
}


// FIX RESPONSE: 
function metrics_to_effect(Metric $metrics) : Effect {
    $effect = Effect::new();
    $per = array();
    if ($metrics->total > 0) {
        foreach ($metrics->data as $code => $value) { $per[$code] = (floor($value / $metrics->total) * 1000)/10; }
    } else {
        foreach ($metrics->data as $code => $value) { $per[$code] = 0; }
    }
    $effect->api(true, "", array("percent" => $per, "counts" => $metrics->data, "total" => $metrics->total));
    return $effect;
}

// FIX RESPONSE: 
function get_block_types(\BitFire\Request $request) : Effect {
    return (metrics_to_effect(get_block_24groups()));
}

// FIX RESPONSE: 
function get_hr_data(\BitFire\Request $request) : Effect {
    return (Effect::new()->api(true, "", get_block_24sum()));
}

// FIX RESPONSE: 
function get_ip_data(\BitFire\Request $request) : Effect {
    return (metrics_to_effect(get_ip_24groups()));
}

// FIX RESPONSE: 
function get_valid_data(\BitFire\Request $request) : Effect {
    $cache = CacheStorage::get_instance();
    $response = array('challenge' => 0, 'valid' => 0);
    for($i=0; $i<25; $i++) {
        $data = $cache->load_data("metrics-$i", null);
        if ($data === null) { 
            $cache->save_data("metrics-$i", $response, DAY);
            continue;
        }
        foreach ($data as $code => $cnt) {
            if ($code === "challenge") { $response['challenge'] += $cnt; }
            if ($code === "valid") { $response['valid'] += $cnt; }
        }
    }

    return Effect::new()->api(true, "", $response);
}

// create a new hmac code for validate_code
function make_code(string $secret) : string {
    $iv = strtolower(random_str(12));
    $time = time();
    $hash = hash_hmac("sha256", "{$iv}.{$time}", $secret, false);
    return "{$hash}.{$iv}.{$time}";
}


// validate hmac($iv.$time, $secret)  == $test_hmac, within 6 hours
function validate_raw(string $test_hmac, string $iv, string $time, string $secret) : bool {
    assert(strlen($secret) > 20, "secret key is too short");

    $d3 = hash_hmac("sha256", "{$iv}.{$time}", $secret, false);
    $d4 = hash_hmac("sha256", "{$iv}.{$time}", "default", false);

    $diff = time() - $time;
    //debug("hmac check [$diff] $d3 == $test_hmac");

    if ($diff > HOUR*6) {
        debug("hmac expired (6 hour maximum) [%s] %s", $diff, $test_hmac);
        return false;
    }
    return ($d4 === $test_hmac || $d3 === $test_hmac);
}

// validate $hash was generated with make_code($secret)
function validate_code(string $hash, string $secret) : bool {
    assert(strlen($secret) > 20 && $secret != "default", "secret key is too short");

    $validate_fn = BINDR("\BitFire\\validate_raw", $secret);

    $validator = MaybeStr::of($hash)
    ->then(BINDL("explode", "."))
    ->keep_if(BINDR("\ThreadFin\array_len", 3))
    ->then($validate_fn, true);

    return ($validator->value("bool") || false);
}

/**
 * download a BitFire release
 * @param string $version 
 * @return Effect 
 */
function download_tag(string $version, string $dest) : Effect {
    // download the archive TODO: check checksum
    $link = "https://github.com/bitslip6/bitfire/archive/refs/tags/{$version}.tar.gz";
    $resp_data = http2("GET", $link, "");
    $check_data = http2("GET", "https://bitfire.co/releases/{$version}.md5");
    $test_md5 = md5($resp_data->content);
    // checksum mismatch
    if ($test_md5 !== $check_data->content) {
        return Effect::new()->status(STATUS_ECOM);
    }
    return Effect::new()->status(STATUS_OK)->file(new FileMod($dest, $resp_data->content));
}

// only called for standalone installs, not plugins
function upgrade(\BitFire\Request $request) : Effect {
    $v = preg_replace("/[^0-9\.]/", "", $request->post['ver']);
    if (\version_compare($v, BITFIRE_SYM_VER, '<')) { 
        debug("version not current [%s]", $v);
        return Effect::new()->api(false, "version is not current");
    }

    // ensure that all files are writeable
    file_recurse(\BitFire\WAF_ROOT, function ($x) {
        if (!is_writeable($x)) { 
            return Effect::new()->api(false, "unable to upgrade: $x is not writeable");
        }
    });

    // allow php file manipulation
    stream_wrapper_restore("file");

    // download and verify no errors
    $dest = \BitFire\WAF_ROOT."cache/{$v}.tar.gz";
    $e = download_tag($v, $dest);
    $e->run();
    if ($e->num_errors() > 0) {
        return Effect::new()->api(false, "error downloading and saving release", $e->read_errors());
    }
    

    //  extract archive
    $target = \BitFire\WAF_ROOT . "cache";
    require_once \BitFire\WAF_SRC."tar.php";
    $success = \ThreadFin\tar_extract($dest, $target) ? "success" : "failure";
    

    // replace files
    file_recurse(\BitFire\WAF_ROOT."cache/bitfire-{$v}", function (string $x) use ($v) {
        $base = basename($x);
        if (is_file($x) && $base != "config.ini") {
            $root = str_replace(\BitFire\WAF_ROOT."cache/bitfire-{$v}/", "", $x);
            if (!rename($x, \BitFire\WAF_ROOT . $root)) { debug("unable to rename [%s] - %s", $x, $root); }
        }
    });

    $cwd = getcwd();
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return $effect->api($success, "upgraded with [$dest] in [$cwd]");
}

 
// FIX RESPONSE: 
function delete(\BitFire\Request $request) : Effect {

    $root = \BitFireSvr\cms_root();

    $effect = Effect::new();
    $f = $request->post['value'];
    $name = $request->post['name']??'';

    if (stristr($f, "..") !== false) { return $effect->api(false, "refusing to delete relative path [$f]"); }

    if (strlen($f) > 1) {
        $out1 = basename($f);//$root . $f.".bak.".mt_rand(10000,99999);
        $src = $f;//$root . $f;

        if (!file_exists($src)) { return $effect->api(false, "refusing to delete non-existent file [$src] ($f) ($name)"); } 
        //$src = $root . DIRECTORY_SEPARATOR . $name . DIRECTORY_SEPARATOR . $f;
        //if (!file_exists($src)) { return $effect->api(false, "refusing to delete non-existent file [$src] ($f) ($name)"); } 

        $quarantine_path = realpath(\BitFire\WAF_ROOT."quarantine".DIRECTORY_SEPARATOR);
        debug("moving [%s] to [%s]", $src, $quarantine_path);
        make_dir($quarantine_path, 0755);
        if (!is_writable($src)) { chmod($src, FILE_RW); }
        if (is_writable($src)) {
            if (is_writeable($quarantine_path)) {
                $r = rename($src, $quarantine_path.DIRECTORY_SEPARATOR.$out1.".txt.".mt_rand(10000,99999));
                $effect->api(true, "renamed {$quarantine_path}{$f} ($r)");
            } else {
                $r = unlink($src);
                debug("unable to quarantine [%s] unlink:(%s)", $src, $r);
                $effect->api(true, "deleted {$src} ($r)");
            }
        } else {
            debug("permission error quarantine [%s]", $src);
            $effect->api(false, "delete permissions error '$src'");
        }
    } else {
        $effect->api(false, "no file to delete");
    }
   return  $effect;
}


function set_pass(\BitFire\Request $request) : Effect {
    $effect = Effect::new();
    debug("save pass");
    if (strlen($request->post['pass1']??'') < 8) {
        return $effect->api(false, "password is too short");
    }
    $p1 = hash("sha3-256", $request->post['pass1']??'');
    debug("pass sha3-256 %s ", $p1);
    $pass = file_replace(\BitFire\WAF_INI, "password = 'default'", "password = '$p1'")->run()->num_errors() == 0;
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    exit(($pass) ? "success" : "unable to write to: " . \BitFire\WAF_INI);
}


// TODO: refactor UI to check api success value
function remove_list_elm(\BitFire\Request $request) : Effect {
    $effect = Effect::new();
    // guards
    if (!isset($request->post['config_name'])) { return $effect->api(false, "missing config parameter"); }
    if (!isset($request->post['config_value'])) { return $effect->api(false, "missing config value parameter"); }
    if (!isset($request->post['index'])) { return $effect->api(false, "missing index parameter"); }

    $v = substr($request->post['config_value'], 0, 80);
    $n = $request->post['config_name'];
    if (!in_array($n, \BitFireSvr\CONFIG_KEY_NAMES)) { return $effect->api(false, "unknown parameter name"); }

    $effect = update_ini_value("{$n}[]", "!", "$v");
    if ($effect->read_status() != STATUS_OK) {
        return $effect->api(false, "error updating ini status: " . $effect->read_status());
    }

    // SUCCESS!
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return $effect->api(true, "updated");
}

// modify to use FileData
// FIX RESPONSE: 
function add_list_elm(\BitFire\Request $request) : Effect {
    $effect = Effect::new();

    // guards
    if (!isset($request->post['config_name'])) { return $effect->api(false, "missing config parameter"); }
    if (!isset($request->post['config_value'])) { return $effect->api(false, "missing config value parameter"); }

    $value = substr($request->post['config_value'], 0, 80);
    $name = $request->post['config_name'];
    if (!in_array($name, \BitFireSvr\CONFIG_KEY_NAMES)) { return $effect->api(false, "unknown parameter name"); }

    $effect = add_ini_value("{$name}[]", $value)->api(true, "config.ini updated");
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return $effect;
}

// install always on protection (auto_prepend_file)
function install(?\BitFire\Request $request = null) : Effect {
    // CALL SERVER AND KEEP THIS CHECK HERE
    if (isset($_SERVER['IS_WPE'])) {
        $note = "WPEngine has a restriction which prevents that here.  Please go to WordPress plugin page and disable then re-enable this plugin to activate always-on.";
        return Effect::new()->exit(true, STATUS_FAIL, $note)->api(false, $note);
    }

    $effect = \BitFireSvr\install();
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return $effect;
}

// uninstall always on protection (auto_prepend_file)
function uninstall(\BitFire\Request $request) : Effect {
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return \BitFireSvr\uninstall();
}

/**
 * replace an array value in the ini file
 * @param Request $request 
 * @return Effect 
 */
function replace_array_value(\BitFire\Request $request) : Effect {
    $effect = Effect::new();
    $name = $request->post["param"];

    // remove all lines with $name[]
    $file_no_array = FileData::new(WAF_INI)->read()->filter(function($line) use ($name) {
        return ! contains($line, "{$name}[]");
    });

    // add new values
    $value_list = explode(",", $request->post["value"]);
    foreach ($value_list as $value) {
        if (!empty($value)) {
            $file_no_array->lines[] = "{$name}[] = \"$value\"\n";
        }
    }

    // write the new file
    $effect->file(new FileMod(WAF_INI, join("", $file_no_array->lines)));

    // remove the old cache entry and force a new parse
    $nop = "\ThreadFin\\nop";
    $effect->update(new CacheItem("parse_ini", $nop, $nop, -86400));
    $effect->api(true, "updated");
 
    return $effect;
}


function toggle_config_value(\BitFire\Request $request) : Effect {
    // handle fixing write permissions
    if ($request->post["param"] == "unlock_config") {
        $result = chmod(\BitFire\WAF_INI, 0664);
        return Effect::new()->api(true, "updated 2", ["file" => WAF_INI, "mode" => 0664, "result" => $result]);
    }
    debug("update config [%s]", WAF_INI);

    // ugly fix for missing valid domain line
    $config = FileData::new(WAF_INI)->read()->filter(function($line) {
        return contains($line, "valid_domains[] = \"\"");
    });
    if ($config->num_lines < 1) {
        file_replace(WAF_INI, "; domain_fix_line", "valid_domains[] = \"\"\n; domain_fix_line")->run();
    }
    // update the config file
    $effect = \BitFireSvr\update_ini_value($request->post["param"], $request->post["value"]);
    // handle auto_start install
    if ($request->post["param"] == "auto_start") {
        $effect->chain(\BitFireSvr\install());
    } 
    if ($request->post["param"] == "notification_email") {
        http2("POST", APP."zxf.php", base64_encode(json_encode(["action" => "notify", "name" => $request->post["value"]])));
    }
    $effect->api(true, "updated");
    CacheStorage::get_instance()->save_data("parse_ini", null, -86400);
    return $effect;
}

/**
 * path is crc32 of path, trim is crc32 of trimmed content
 * @param Request $request 
 * @return Effect - the API response
 */
function allow(\BitFire\Request $request) : Effect {
    // preamble
    $file_name = get_hidden_file("hashes.json");
    $effect = Effect::new();
    $data = un_json($request->post_raw);
    if ($data === null) {
        return $effect->api(false, "invalid json sent to BitFire API");
    }

    $ver_fn = '\BitFirePlugin\\version_from_path';
    $type_fn = "\BitFirePlugin\\file_type";
    $hash_file = hash_file3($data['path'], $type_fn, $ver_fn, CFG::str("cms_root"));

    //debug("data\n%s", json_encode($data, JSON_PRETTY_PRINT));
    //$path = intval($data['path']);
    //$trim = crc32(join('', array_map('trim', file_get_contents($path))));

    if (!file_exists($file_name)) { touch($file_name); }

    // load data and filter out this hash
    $file = FileData::new($file_name)
        ->read()
        ->un_json();
    $num1 = count($file->lines);

    $file->filter(function($x) use ($data) { 
            $match = ($x["path"] == $data["filename"]) && ($x["trim"] == $data["id"]);
            return !$match;
        });
    $num2 = count($file->lines);

    // add the hash to the list
    $file->lines[] = [ "path" => $data['path'], "trim" => $hash_file->crc_trim ]; 
    $num3 = count($file->lines);
    debug("allow: %d -> %d -> %d", $num1, $num2, $num3);

    // all good, save the file
    $effect->file(new FileMod($file_name, en_json($file->lines)));
    //debug("effect: " . json_encode($effect, JSON_PRETTY_PRINT));


    // report any errors
    if (count($file->get_errors()) > 0) {
        return $effect->api(false, "error saving file allow list", $file->get_errors());
    }
    return $effect->api(true, "file added to allow list", ["id" => $hash_file->crc_trim, "unique" => $data["unique"]]);
}


function clear_cache(\BitFire\Request $request) : Effect {
    CacheStorage::get_instance()->clear_cache();
    return \ThreadFin\cache_prevent()->api(true, "cache cleared");
}


/**
 * flag a block for review
 * @param Request $request 
 * @return Effect 
 * @throws RuntimeException 
 */
function review(\BitFire\Request $request) : Effect {
    $block_file = \ThreadFin\FileData::new(get_hidden_file("blocks.json"))
        ->read()
        ->map('\ThreadFin\un_json');

    $raw_data = un_json($request->post_raw);
    $uuid = $raw_data['uuid'];
    $blocked = array_filter($block_file->lines, function ($x) use ($uuid) {
        if (isset($x['block'])) {
            if (isset($x['block']['uuid'])) {
            return $x['block']['uuid'] == $uuid;
            }
        }
        return false;
    });

    if (count($blocked) > 0) {
        $data = array_values($blocked);
        $info = http2("POST", "https://bitfire.co/review.php", json_encode($data));

        $uuid = $data[0]['block']['uuid'];
        $review = ["uuid" => $uuid, "name" => $raw_data['name'], "time" => date(DATE_ATOM)];
        $append_review = new FileMod(get_hidden_file("review.json"), json_encode($review) . ",\n", 0, 0, true);
        return Effect::new()->file($append_review)->api(true, "review in progress", ["data" => $info]);
    }
    return Effect::new()->api(false, "reference id not found");
}


function api_call(Request $request) : Effect {
    if (isset($request->get[BITFIRE_COMMAND])) {
        $fn = "\\BitFire\\".htmlspecialchars($request->get[BITFIRE_COMMAND]);
    } else if (isset($request->post[BITFIRE_COMMAND])) {
        $fn = "\\BitFire\\".htmlspecialchars($request->post[BITFIRE_COMMAND]);
    } else {
        return Effect::new()->out("no command")->exit(true);
    }

    trace("api");

    // review cases have no auth, so we execute them here
    if ($fn == "\\BitFire\\review") {
        return \BitFire\review($request)->exit(true);
    }


    if (!in_array($fn, BITFIRE_API_FN)) {
        return Effect::new()->exit(true, STATUS_ENOENT, "no such method [$fn]");
    }

    if (file_exists(WAF_SRC."proapi.php")) { require_once \BitFire\WAF_SRC . "proapi.php"; }

    // verify admin password if user is not a CMS admin. will exit 401 and ask for auth if failure
    $admin_value = (BitFire::get_instance()->cookie->extract("wp")() > 1);
    if ($admin_value < 2) {
        $auth_effect = (function_exists("\\BitFirePlugin\\verify_admin_effect"))
            ? \BitFirePlugin\verify_admin_effect($request) 
            : verify_admin_password($request);
        $auth_effect->run();
    }
    

    $post = (strlen($request->post_raw) > 1 && count($request->post) < 1) ? un_json($request->post_raw) : $request->post;
    if ($post === null) { debug("error json decoding api request"); }

    $code = (isset($post[BITFIRE_INTERNAL_PARAM])) 
        ? $post[BITFIRE_INTERNAL_PARAM]
        : $request->get[BITFIRE_INTERNAL_PARAM]??"";;

    if (trim($request->get["BITFIRE_API"]??"") != "send_mfa" && CFG::str("password") != "configure") {
        if (!validate_code($code, CFG::str("secret"))) {
            return Effect::new()->api(false, "invalid code", ["error" => "invalid / expired code"])->exit(true);
        }
        trace("SMFA");
    }

    $request->post = $post;
    $api_effect = $fn($request);

    assert($api_effect instanceof Effect, "api method did not return valid Effect");
    return $api_effect->exit(true);
}


/**
 * helper binary search. only used in malware scanner
 * TODO: find a better home for this
 * @param array $haystack 
 * @param int $needle 
 * @param int $high 
 * @return bool true if the element is in the list
 */
function in_list(array $haystack, int $needle, int $high) : bool {
    $low = 0;
    $max = 24;
    // handle empty list
    if ($high == 0) { return false; }
      
    while ($low <= $high && $max-- > 0) {
          
        // compute middle index
        $mid = floor(($low + $high) / 2);
   
        // element found at mid
        if($haystack[$mid] == $needle) {
            debug("FOUND @ %d", $mid);
            return true;
        }
  
        // search down
        if ($needle < $haystack[$mid]) {
            //debug("%d < %s (%d, %d) = %d", $needle, $haystack[$mid], $low, $high, $mid);
            $high = $mid -1;
        }
        // search up
        else {
            //debug("%d > %s (%d, %d) = %d", $needle, $haystack[$mid], $low, $high, $mid);
            $low = $mid + 1;
        }
    }
      
    debug("MISSING @ %d", $needle);
    // element x doesn't exist
    return false;
}

function upload_file(string $url, array $post_data, string $path_to_file, string $file_param, ?string $file_name = null) : ?string {
    $data = ""; 
    $boundary = "---------------------".substr(md5(mt_rand(0,32000)), 0, 10); 

    // append post data 
    foreach($post_data as $key => $val) 
    { 
        $data .= "--$boundary\n"; 
        $data .= "Content-Disposition: form-data; name=\"".$key."\"\n\n".$val."\n"; 
    } 

    $data .= "--$boundary\n"; 

    if ($file_name == null) { $file_name = basename($path_to_file); }
    $content = FileData::new($path_to_file)->raw();

    $data .= "Content-Disposition: form-data; name=\"{$file_param}\"; filename=\"{$file_name}\"\n"; 
    $data .= "Content-Type: stream/octet\n"; 
    $data .= "Content-Transfer-Encoding: binary\n\n"; 
    $data .= $content;
    $data .= "\n--$boundary--\n"; 

    $params = array('http' => array( 
           'method' => 'POST', 
           'header' => 'Content-Type: multipart/form-data; boundary='.$boundary, 
           'content' => $data 
        )); 

    $ctx = stream_context_create($params); 
    $fp = fopen($url, 'rb', false, $ctx); 

    if (!$fp) { 
        return debugN("unable to upload file to $url");
    } 

    $response = @stream_get_contents($fp); 
    if ($response === false) { 
        return debugN("unable to read file upload response from $url");
    } 

    return $response;
} 


/**
 * backup the wordpress database 
 * @param Request $request 
 * @return Effect 
 */
function backup_database(Request $request) : Effect {
    $effect = Effect::new();
    require_once WAF_SRC . "db.php";
    require_once WAF_SRC . "wordpress.php";

    // set maximum backup size to allow (uncompressed) (2GB  for pro, 50MB for free)
    $pro = strlen((CFG::str("pro_key")) > 20) ? true : false;
    // check free disk space.  if function is not available assume 1GB
    if (function_exists('diskfreespace')) {
        $space = intval(diskfreespace(CFG::str("cms_content_dir")));
    } else {
        $space = 1024*1024*1024;
    }
    $max_bytes = min($space, (($pro) ? 1024*1024*2024 : 1024*1024*100));
    $sha1 = sha1(CFG::str("secret"));

    // find number of posts and comments included in backup 
    $credentials = \BitFireWP\get_credentials();
    if (empty($credentials)) {
        return $effect->api(false, $message, ["backup_size" => 0, "file" => CFG::str("cms_content_dir") . "no-backup.sql.gz", "store" => "", "status" => "failed - unable to find database credentials"]);
    }
    $db = DB::cred_connect($credentials);
    $prefix = $credentials->prefix;
    $db->enable_log(true);
    $num_posts = $db->fetch("SELECT count(*) as num FROM `{$prefix}posts` p")->col("num")();
    $num_comments = $db->fetch("SELECT count(*) as num FROM `{$prefix}comments` p")->col("num")();

    // backup database to wp-content/db_bitfire.sql.gz
    $backup_file = CFG::str("cms_content_dir")."/db_bitfire.sql.gz";
    $fp = gzopen($backup_file, "wb6");
    $write_fn = BINDL('gzwrite', $fp);
    $info = dump_database($credentials, $write_fn, $max_bytes);
    gzclose($fp);
    
    // check if backup was successful 
    $backup_size = filesize($backup_file);
    $success = ($backup_size < $max_bytes);
    $message = ($success) ? "database backup complete" : "database backup incomplete";

    // send backup to bitfire server
    $response = upload_file("https://bitfire.co/backup.php?backup_full=1",
    ["secret" => $sha1,
     "posts" => $num_posts,
     "domain" => $_SERVER['HTTP_HOST'],
     "comments" => $num_comments], $backup_file, "full");

    return $effect->api($success, $message, ["backup_size" => $backup_size, "file" => $backup_file, "store" => $response, "status" => $info]);
}



function clean_post(Request $request) : Effect {
    require_once WAF_SRC . "db.php";
    require_once WAF_SRC . "wordpress.php";

    $effect = Effect::new();
    $table = ($request->post["type"]??"" === "post") ? "posts" : "comments";
    $key = ($request->post["type"]??"" === "post") ? "id" : "comment_ID";
    $db = \BitFireWP\get_db_connection();
    $db->enable_log(true);
    //$db->enable_simulation(true);
    $prefix = $db->prefix;
    debug("fix %s (%s)", $prefix, $request->post["fix"]);

    if ($request->post["fix"] == "delete") {
        debug("delete %d", $request->post["id"]);
        $db->delete("`{$prefix}`{$table}", [$key => $request->post["id"]]);
    }
    else if ($request->post["fix"] == "clean") {
        $posts = $db->fetch("SELECT $key, post_content FROM `{$prefix}{$table}` WHERE `$key` = {key}", ["key" => $request->post["id"]]);
        // debug(" # sql [%s]", print_r($db, true));
        if (!$posts->empty()) {
            debug("clean %d len: %d", $posts->count(), strlen($posts->data()[0]["post_content"]));
            debug (" href: /<a[^>]*?{$request->post['link']}.*?>(.*)<\/a>/ims");
            $updated = preg_replace("/<a[^>]*?{$request->post['link']}.*?>(.*)<\/a>/ims", "", $posts->data()[0]['post_content']);
            $ret = $db->update("`{$prefix}{$table}`", ["post_content" => $updated], [$key => $request->post["id"]]);
            debug("updated len: %d (%d)", strlen($updated), $ret);
        }
    }
    else if ($request->post["fix"] == "allow") {
        $domain_file = WAF_ROOT . "/cache/good_domains.bin";
        $good_domains = FileData::new($domain_file)->read()->un_json()->lines;
        if ($good_domains === null) { debug("error json decoding good_domains.bin"); $good_domains = []; }
        $good_domains[$request->post["link"]] = true;
        $effect->file(new FileMod($domain_file, json_encode($good_domains, JSON_PRETTY_PRINT)));
    }

    return $effect->api(false, "clean post", ["data" => $db->logs, "errors" => $db->errors]);
}

function bot_allow(Request $request) : Effect {
    $id = $request->post["id"];
    $bot_dir = get_hidden_file("bots");
    $info_file = "{$bot_dir}/{$id}.json";

    $effect = Effect::new();
    /** @var BotData $bot_data */
    $bot_data = json_decode(FileData::new($info_file)->raw(), false);

    if (!empty($bot_data)) {
        if ($request->post["allow"] == "true") {
            $bot_data->net = $request->post["net"];
            $bot_data->domain = $request->post["domain"];
            $bot_data->valid = 1;
        } else {
            $bot_data->valid = 0;
        }
        $effect->file(new FileMod($info_file, json_encode($bot_data, JSON_PRETTY_PRINT)));
    }

    return $effect;
}


function scan_malware(Request $request) : Effect {
    require_once WAF_SRC . "db.php";
    require_once WAF_SRC . "wordpress.php";

    $href_list = [];
    $script_list = [];
    $bad_domains = [];
    $effect = Effect::new();
    $table = ($request->post["type"]??"" === "post") ? "posts" : "comments";
    $key = ($request->post["type"]??"" === "post") ? "id" : "comment_ID";
    $join_col = ($request->post["type"]??"" === "post") ? "post_author" : "user_id";
    $malware_file = WAF_ROOT . "/cache/malware.bin";
    if (!file_exists($malware_file)) {

        if (function_exists('curl_init')) {
            set_time_limit(0);
            $fp = fopen ($malware_file, 'w+');
            $ch = curl_init("https://bitfire.co/malware/malware.bin");
            curl_setopt($ch, CURLOPT_TIMEOUT, 600);
            curl_setopt($ch, CURLOPT_FILE, $fp); 
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_exec($ch); 
            curl_close($ch);
            fclose($fp);
        } else {
            $malware_bin = file_get_contents("https://bitfire.co/malware/malware.bin");
            file_put_contents($malware_file, $malware_bin);
        }
    }
    $half_size = filesize($malware_file) / 2;
    $offset = ($request->post["side"]??"" === "right") ? $half_size : 0;
    $good_domains = FileData::new(WAF_ROOT . "/cache/good_domains.bin")->read()->un_json()->lines;
    $self_url = parse_url(CFG::str("cms_content_url"), PHP_URL_HOST);

    debug(" # malware 1/2 size %d", $half_size);

    // connect to DB
    $db = \BitFireWP\get_db_connection();
    $prefix = $db->prefix;
    if (!$db) {
        return $effect->api(false, "error", ["message" => "could not connect to database"]);
    }
    $max_post = $db->fetch("SELECT max(id) FROM `{$prefix}{$table}`")->col("id")->value("int");

    // load the content from the database
    $posts = $db->fetch("SELECT p.`$key`, post_content, post_title, u.display_name, post_date FROM `{$prefix}{$table}` p LEFT JOIN `{$prefix}users` u ON p.{$join_col} = u.id ORDER BY `$key` ASC LIMIT {page_size} OFFSET {offset}", ["page_size" => 250, "offset" => $request->post["offset"]]);
    if ($posts->empty()) {
        return $effect->api(true, "complete", ["message" => "All $table scanned", "logs" => $db->logs]);
    }

    // load the left or right side of the malware file
    $malware_raw = file_get_contents($malware_file);//, false, null, $offset, $half_size);
    //$malware_raw = file_get_contents($malware_file, false, null, $offset, $half_size);
    $malware = unpack("N*", $malware_raw);
    $malware_total = count($malware);
    //debug("read $malware_total malware hashes [$offset : $half_size] : " . strlen($malware_raw));


    $max_found_id = 0;
    foreach ($posts->data() as $post) {

        // calculate seconds since the post was created/updated
        $parsed = date_parse($post["post_date"]);
        $new_epoch = mktime(
            $parsed['hour'], 
            $parsed['minute'], 
            $parsed['second'], 
            $parsed['month'], 
            $parsed['day'], 
            $parsed['year']
        );
        $seconds = time() - $new_epoch;

        if ($post["id"] > $max_found_id) { $max_found_id = $post["id"]; }

        // find all scripts in the post
        if (preg_match_all("/<script([^>]*)>([^<]*)/ims", $post["post_content"], $scripts)) {
            foreach ($scripts as $script) {
                $script_list[] = [
                    "id" => $post["id"],
                    "title" => $post["post_title"],
                    "author" => $post["display_name"],
                    "date" => $post["post_date"],
                    "days" => ceil($seconds/DAY),
                    "markup" => $script[1]??"",
                    "content" => substr($script[2]??"", 0, 2048)
                ];
            }
        }

        // find all links in the post
        if (preg_match_all("/<a[^>]+>/ims", $post['post_content'], $links)) {
            foreach ($links as $link) {
                // skip link if it is marked nofollow, or user content
                //if (icontains($link[0], ["nofollow", "ugc"])) {
                //    continue;
                //}
                // skip the link if it's not a full path...
                if (!icontains($link[0], "http")) {
                    continue;
                }
                // it's a real link
                if (preg_match("/href\s*=\s*[\"\']?\s*([^\s\"\']+)/ims", $link[0], $href)) {
                    // exclude links to ourself...
                    // $source = substr($href[1], 0, strlen($self_url) + 16);
                    // if (icontains($source, $self_url)) { continue; }

                    // get just the domain name
                    $check_domain = preg_replace("/https?:\/\/([^\/]+).*/ims", '\1', $href[1]);
                    debug(" # href [%s] = [%s]", $href[1], $check_domain);

                    // skip domains we have already allowed
                    if (isset($good_domains[$check_domain])) { continue; }

                    // TODO: add list of Top 1000 domains and check those first to exclude the link here
                    $hash = crc32($check_domain);

                    // only search the malware list 1x
                    if (!isset($bad_domains[$check_domain])) {
                        if (in_list($malware, $hash, $malware_total)) {
                            $bad_domains[$check_domain] = true;
                        } else {
                            debug(" # good domain [%d] %s", $hash, $check_domain);
                            $good_domains[$check_domain] = true;
                        }
                    }

                            
                    if (isset($bad_domains[$check_domain])) {
                        $href_list[] = [
                            "id" => $post["id"],
                            "name" => $post["display_name"],
                            "title" => $post["post_title"],
                            "date" => $post["post_date"],
                            "days" => ceil($seconds/DAY),
                            "markup" => $link[0],
                            "domain" => $check_domain,
                            "type" => $request->post["type"]??"post",
                            "md5" => md5($check_domain),
                            "hash" => $hash
                        ];
                    }
                }
            }
        }
    }

    $next = ($max_found_id < $max_post) ? $offset + 250 : 0;

    return $effect->api(true, "scan complete", [
        "hrefs" => $href_list,
        "offset" => $offset,
        "size" => 250,
        "next_offset" => $next,
        "side" => $request->post['size']??'Left',
        "table" => $table,
        "scripts" => $script_list,
        "good_domains" => $good_domains,
        "bad_domains" => $bad_domains
    ]);
}

