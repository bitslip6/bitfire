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

use ThreadFin as TF;

use ThreadFin\CacheStorage;
use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;
use ThreadFin\MaybeStr;
use BitFire\Config as CFG;

use const ThreadFin\HOUR;

use function BitFireSvr\add_ini_value;
use function BitFireSvr\update_ini_value;
use function ThreadFin\machine_date;
use function ThreadFin\compact_array;
use function ThreadFin\contains;
use function ThreadFin\en_json;
use function ThreadFin\ends_with;
use function ThreadFin\file_recurse;
use function ThreadFin\find_fn;
use function ThreadFin\http2;
use function ThreadFin\httpp;
use function ThreadFin\partial_right as BINDR;
use function ThreadFin\partial as BINDL;
use function ThreadFin\random_str;
use function ThreadFin\un_json;
use function ThreadFin\debug;
use function ThreadFin\file_replace;
use function ThreadFin\trace;

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
function add_api_exception(\BitFire\Request $r) : Effect {
    assert(isset($r->post['path']), "path is required");
    assert(isset($r->post['code']), "code is required");

    // an effect and the exception to add
    $effect = Effect::new();
    $ex = new \BitFire\Exception((int)$r->post['code'], random_str(8), NULL, $r->post['path']);

    // load exceptions from disk
    $file = \BitFire\WAF_ROOT."exceptions.json";
    $exceptions = FileData::new($file)->read()->unjson()->map('\BitFire\map_exception');

    // add new exception (will not double add)
    $updated_exceptions = add_exception_to_list($ex, $exceptions());

    // nothing added, exception already existsj
    if (count($updated_exceptions) == count($exceptions())) {
        $effect->api(false, "exception already exists");
    }
    // new exception added
    else if (count($updated_exceptions) > count($exceptions())) {
        $effect->api(true, "exception added");
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
    assert(isset($r->post["filename"]), "filename is required");

	$effect = Effect::new();
    $root = \BitFireSvr\cms_root();
	$filename = $root . trim($r->post['filename'], "/");

    // GUARD
	if (! ends_with($filename, "php") || contains($filename, RESTRICTED_FILES)) {
        return $effect->api(false, "invalid file.");
    }

    // load data
    $file = FileData::new($filename)->read(true);
    // good file
    if ($file->exists) {
        $data = $file->raw();
        if (!isset($r->post['direct'])) {
            $base = basename($filename);
            $effect->header("content-description", "File Transfer")
            ->header('Content-Type', 'application/octet-stream')
            ->header('Content-Disposition', 'attachment; filename="' . $base . '"')
            ->header('Expires', '0')
            ->header('Cache-Control', 'must-revalidate')
            ->header('Pragma', 'private')
            ->header('Content-Length', (string)strlen($data));
        }
        $effect->out($data);
    } else {
        $effect->api(false, "file does not exist: $filename");
    }
    return $effect;
}

/**
 * todo: depricate and perform this function client side
 */
function diff(\BitFire\Request $request) : Effect {
    $root = \BitFireSvr\cms_root();
    if ($root == null) {
        return Effect::new()->api(false, "WordPress not found");
    }
    //debug("diff %s", en_json($request));

    // verify valid url
    $url = $request->post["url"];
    // TODO: move regex to plugin function
    if (!preg_match("/https?:\/\/\w+\.svn.wordpress.org\//", $url)) {
        return Effect::new()->api(false, "invalid URL: $url");
    }
    // verify valid path
    $path = $request->post["file_path"];
    if (!preg_match("#$root#", $path) || !ends_with($path, "php") || contains($path, "config")) {
        return Effect::new()->api(false, "invalid file: $path");
    }


    $info = http2("GET", $url, "", [
        "User-Agent" => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36",
        "Accept" => "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng",
        "Accept-Encoding" => "gzip, deflate",
        "sec-ch-ua-platform" => "Linux",
        "upgrade-insecure-requests" => "1"]);

    // if we don't have a 200, then 0 out the 404 response.
    if (!in_array("http/1.1 200", $info["headers"])) { $info["success"] = false; $info["content"] = ""; }

    $local = FileData::new($path)->read(true)->raw();
    $success = $info["success"] && strlen($local) > 0;
    $data = array("url" => $request->post['url'], "file_path" => $request->post['file_path'], "compressed" => false);
    if (function_exists("zlib_encode")) {
        $data["zlib_local"] = base64_encode(zlib_encode($local, ZLIB_ENCODING_RAW));
        $data["zlib_orig"] = base64_encode(zlib_encode($info["content"], ZLIB_ENCODING_RAW));
        $data["compressed"] = true;
    } else {
        $data["local"] = base64_encode($local);
        $data["orig"] = base64_encode($info["content"]);
    }
    $effect = Effect::new()->api($success, "data", $data);
    return $effect;
}

// not DRY ripped from dashboard.php
function dump_hash_dir(\BitFire\Request $request) : Effect {
    $root = \BitFireSvr\cms_root();

    if (!empty($root) && isset($request->post['dir']) && strlen($request->post['dir']) > 1) { 
        $ver = trim($request->post['ver'], '/');
        $dirpath = realpath($request->post['dir']);
        $plugin_name = basename($dirpath);
        //FileData::new("{$dirpath}/readme.txt")->read()->apply_ln()

        $type_fn = find_fn("file_type");
        $hash_fn = BINDR('\BitFireSvr\hash_file2', $dirpath, $plugin_name, $type_fn);
        $hashes = file_recurse($dirpath, $hash_fn, '/.*.php/');
        $numfiles = count($hashes);

        // no files to check!
        if ($numfiles == 0) {
            return Effect::new()->api(true, "hashed $numfiles", array("ver" => $ver, "basename" => basename($dirpath), "dir" => $request->post['dir'], "path" => $dirpath, "file_count" => $numfiles, "hit_count" => $numfiles, "success" => true, "data" => base64_encode(json_encode([]))));
        }

        $h2 = en_json(["ver" => $ver, "files" => $hashes]);
        $encoded = base64_encode($h2);

        $result = httpp(APP."hash_compare.php", $encoded, array("Content-Type" => "application/json"));
        $decoded = un_json($result);
        $c1 = count($decoded);
        debug("sent $numfiles hashes receved $c1 hashes");

        $dir_without_pluginname = dirname($dirpath);


        $allowed = FileData::new(\BitFire\WAF_ROOT."cache/hashes.json")->read()->unjson()->lines;
        $allow_map = [];
        foreach ($allowed as $file) { $allow_map[$file["trim"]] = true; }

        //echo "<pre>\n";
        //print_r($allow_map);
        // remove files that passed, (silence is golden)
        $filtered = array_filter($decoded, function ($file) {
            // golden and dolly hashes
            $pass = $file['r'] !== "PASS";
            return $pass;
        });
        

        $num_miss = count($filtered);
        $num_files = count($hashes);

        $filtered = array_filter($filtered, function ($file) use ($allow_map) {
            return !($allow_map[$file["crc_trim"]]??false);
        });


        // if the entire directory is unknown, squash it to a single entry
        if ($numfiles == $num_miss) {
            $compacted = compact_array($filtered);
            $sum = array_sum(array_map(function($x){return filesize($x['file_path']);}, $compacted));
            $sumkb = round($sum/1024, 2);
            // DEBUG
            //file_put_contents("/tmp/nofound.txt", json_encode($decoded, JSON_PRETTY_PRINT));

            $compacted[0]["rel_path"] = "";// basename($hashes[0]->file_path);
            $compacted[0]["mtime"] = filemtime($hashes[0]->file_path);
            $compacted[0]["machine_date"] = machine_date($compacted[0]["mtime"]);

            $compacted[0]["known"] = "Unknown {$compacted[0]["type"]} {$compacted[0]["name"]}";
            $compacted[0]["bgclass"] = "bg-danger-soft";
            $compacted[0]["icon"] = "x";
            $compacted[0]["icon_class"] = "danger";
            $compacted[0]["kb2"] = "0 Files";
            $compacted[0]["kb1"] = count($compacted) . " Files ({$sumkb} Kbytes)";
            $compacted[0]["table"] = "Unknown " . $compacted[0]["table"];
            $compacted = [$compacted[0]];
        } else {
            $enrich_fn = BINDL('\BitFire\enrich_hashes', $ver, $dir_without_pluginname);
            $enriched = array_map($enrich_fn, $filtered);
            $compacted = compact_array($enriched);
        }
        
        return Effect::new()->api(true, "hashed $num_files", array("ver" => $ver, "basename" => basename($dirpath), "dir" => $request->post['dir'], "path" => $dirpath, "file_count" => $num_files, "hit_count" => ($num_files - $num_miss), "success" => ($num_files == count($hashes)), "data" => base64_encode(json_encode($compacted))));
    }
    return Effect::new()->api(false, "server error. please upgrade BitFire.", array("success" => false, "data" => base64_encode('[]')));
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
        if ($data === null) { continue; }
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
    $diff = time() - $time;
    return ($diff) < (HOUR*6) && ($d3 === $test_hmac);
}

// validate $hash was generated with make_code($secret)
function validate_code(string $hash, string $secret) : bool {
    assert(strlen($secret) > 20, "secret key is too short");

    $validate_fn = BINDR("\BitFire\\validate_raw", $secret);

    $pass = MaybeStr::of($hash)
    ->then(BINDL("explode", "."))
    ->keep_if(BINDR("\ThreadFin\arraylen", 3))
    ->then($validate_fn, true)
    ->value("bool");

    return ($pass || false);
}

/**
 * download a BitFire realease
 * @param string $version 
 * @return Effect 
 */
function download_tag(string $version, string $dest) : Effect {
    // download the archive TODO: check checksum
    $link = "https://github.com/bitslip6/bitfire/archive/refs/tags/{$version}.tar.gz";
    $resp_data = http2("GET", $link, "");
    $check_data = http2("GET", "https://bitfire.co/releases/{$version}.md5");
    $test_md5 = md5($resp_data["content"]);
    // checksum missmatch
    if ($test_md5 !== $check_data["content"]) {
        return Effect::new()->status(STATUS_ECOM);
    }
    return Effect::new()->status(STATUS_OK)->file(new FileMod($dest, $resp_data["content"]));
}

// only called for standalone installs, not plugins
function upgrade(\BitFire\Request $request) : Effect {
    $v = preg_replace("/[^0-9\.]/", "", $request->post['ver']);
    if (\version_compare($v, BITFIRE_SYM_VER, '<')) { 
        debug("version not current [%s]", $v);
        return Effect::new()->api(false, "version is not current");
    }

    // ensure that all files are witeable
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
    CacheStorage::get_instance()->save_data("parse_ini2", null, -86400);
    return $effect->api($success, "upgraded with [$dest] in [$cwd]");
}

 
// FIX RESPONSE: 
function delete(\BitFire\Request $request) : Effect {

    $root = \BitFireSvr\cms_root();

    $effect = Effect::new();
    $f = $request->post['value'];

    if (stristr($f, "..") !== false) { return $effect->api(false, "refusing to delete relative path"); }

    if (strlen($f) > 1) {
        $out1 = $root . $f.".bak.".mt_rand(10000,99999);
        $src = $root . $f;
        if (!file_exists($src)) { return $effect->api(false, "refusing to delete relative path"); } 

        $quarantine_path = str_replace($root, \BitFire\WAF_ROOT."quarantine/", $out1);
        make_dir($quarantine_path, FILE_EX);
        if (is_writable($src)) {
            if (is_writeable($quarantine_path)) {
                $r = rename($src, "{$quarantine_path}{$f}");
                $effect->api(true, "renamed {$quarantine_path}{$f}");
            } else {
                $r = unlink($src);
                $effect->api(true, "deleted {$src}");
            }
        } else {
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
    CacheStorage::get_instance()->save_data("parse_ini2", null, -86400);
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
    CacheStorage::get_instance()->save_data("parse_ini2", null, -86400);
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

    $effect = add_ini_value($name, $value)->api(true, "config.ini updated");
    CacheStorage::get_instance()->save_data("parse_ini2", null, -86400);
    return $effect;
}

// install always on protection (auto_prepend_file)
function install(?\BitFire\Request $request = null) : Effect {
    // CALL SERVER AND KEEP THIS CHECK HERE
    if (isset($_SERVER['IS_WPE'])) {
        $note = "WPEngine has a restriction which prevents that here.  Please go to WordPress plugin page and disable then re-enable this plugin to actiate always-on.";
        return Effect::new()->exit(true, STATUS_FAIL, $note)->api(false, $note);
    }

    CacheStorage::get_instance()->save_data("parse_ini2", null, -86400);
    return \BitFireSvr\install();
}

// uninstall always on protection (auto_prepend_file)
function uninstall(\BitFire\Request $request) : Effect {
    CacheStorage::get_instance()->save_data("parse_ini2", null, -86400);
    return \BitFireSvr\uninstall();
}


function toggle_config_value(\BitFire\Request $request) : Effect {
    // NOTE: these are ini encoded on next call, do not encode here.
    $effect = \BitFireSvr\update_ini_value($request->post["param"], $request->post["value"]);
    $effect->api(true, "updated");
    CacheStorage::get_instance()->save_data("parse_ini2", null, -86400);
    return $effect;
}

function allow(\BitFire\Request $request) : Effect {
    // preamble
    $file_name = \BitFire\WAF_ROOT . "cache/hashes.json";
    $effect = Effect::new();
    $data = un_json($request->post_raw);
    //debug("data\n%s", json_encode($data, JSON_PRETTY_PRINT));
    $path = intval($data['path']);
    $trim = intval($data['trim']);
    if (!file_exists($file_name)) { touch($file_name); }

    // load data and filter out this hash
    $file = FileData::new($file_name)
        ->read()
        ->unjson()
        ->filter(function($x) use ($trim, $path) { 
            return $x['path'] != $path && $x['trim'] != $trim;
        });
    //debug("file: " . json_encode($file, JSON_PRETTY_PRINT));

    // add the hash to the list
    $file->lines[] = [ "path" => $path, "trim" => $trim, "file" => $data["filename"]??'?' ]; 
    // all good, save the file
    $effect->file(new FileMod($file_name, en_json($file->lines)));
    //debug("effect: " . json_encode($effect, JSON_PRETTY_PRINT));


    // report any errors
    if (count($file->get_errors()) > 0) {
        return $effect->api(false, "error saving file allow list", $file->get_errors());
    }
    return $effect->api(true, "file added to allow list", ["id" => $trim]);
}


function clear_cache(\BitFire\Request $request) : Effect {
    CacheStorage::get_instance()->clear_cache();
    return \ThreadFin\cache_prevent()->api(true, "cache cleared");
}


function api_call(Request $request) : Effect {
    if (!isset($request->get[BITFIRE_COMMAND])) {
        return Effect::$NULL;
    }
    trace("api");

    $fn_name = htmlspecialchars($request->get[BITFIRE_COMMAND]);
    $fn = "\\BitFire\\$fn_name";
    if (!in_array($fn, BITFIRE_API_FN)) {
        return Effect::new()->exit(true, STATUS_ENOENT, "no such method");
    }

    if (file_exists(WAF_SRC."proapi.php")) { require_once \BitFire\WAF_SRC . "proapi.php"; }

    // verify admin password if user is not a CMS admin. will exit 401 and ask for auth if failure
    $auth_effect = (function_exists("\\BitFirePlugin\\verify_admin_effect"))
        ? \BitFirePlugin\verify_admin_effect($request) 
        : verify_admin_password($requst);
    $auth_effect->run();
    

    $post = (strlen($request->post_raw) > 1 && count($request->post) < 1) ? un_json($request->post_raw) : $request->post;
    $code = (isset($post[BITFIRE_INTERNAL_PARAM])) 
        ? $post[BITFIRE_INTERNAL_PARAM]
        : $request->get[BITFIRE_INTERNAL_PARAM]??"";;

    if (trim($request->get["BITFIRE_API"]??"") != "send_mfa") {
        if (!validate_code($code, CFG::str("secret"))) {
            return Effect::new()->exit(true, STATUS_EACCES, "invalid / expired security code: " . print_r($request->get["BITFIRE_API"]??"X", true));
        }
        trace("SMFA");
    }

    $request->post = $post;
        
    $api_effect = $fn($request);
    assert($api_effect instanceof Effect, "api method did not return valid Effect");
    return $api_effect->exit(true);
}

