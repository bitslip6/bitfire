<?php
namespace BitFire;

use Exception;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RegexIterator;
use TF\CacheStorage;
use TF\MaybeA;

use function TF\bit_http_request;
use function TF\ends_with;
use function TF\map_reduce;
use function TF\str_reduce;

ini_set('display_errors', "on");
ini_set('display_startup_errors', "on");
error_reporting(E_ALL);

const WAF_INI = WAF_DIR . "config.ini";

class Metric {
    /** @var array $data */
    public $data = array();
    /** @var int $total */
    public $total = 0;
}

function add_api_exception(\BitFire\Request $r, \TF\MaybeA $cookie) : string {
    $ex = new \BitFire\Exception((int)$r->post['code'], \TF\random_str(8), NULL, $r->post['path']);
    $added = \BitFire\add_exception($ex);
    return ($added) ? "success" : "fail";
}


/**
 * PURE (except for reading the file)
 * @param Request $r 
 * @param MaybeA $cookie 
 * @return void 
 */
function download(\BitFire\Request $r, \TF\MaybeA $cookie) : void {

	$effect = \TF\Effect::new();
	$filename = $r->get['filename']??"";

	if (strpos($filename, "..") !== false || ! \TF\ends_with($filename, "php")) { $effect->out("invalid file."); }
	else if (!file_exists($filename)) { $effect->out("file does not exist."); }

	else if (!isset($_GET['direct'])) {
		$base = basename($filename);
        $effect->header("content-description", "File Transfer")
		->header('Content-Type', 'application/octet-stream')
		->header('Content-Disposition', 'attachment; filename="' . $base . '"')
		->header('Expires', '0')
		->header('Cache-Control', 'must-revalidate')
		->header('Pragma', 'private')
		->header('Content-Length', (string)filesize($filename));
	}
	$effect->out(file_get_contents($filename));
    $effect->run();
}

function diff(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    require_once WAF_DIR . "/src/server.php";
    require_once WAF_DIR . "/src/wordpress.php";
    $root = \BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']);
    \TF\debug(print_r($request->post, true));

    $orig = \TF\bit_http_request("GET", $request->post['url'], "");
    $local = file_get_contents($root . $request->post['out']);
    $success = strlen($orig) > 0 && strlen($local) > 0;
    $effect = \TF\Effect::new()->out(json_encode(array("success" => $success, "url" => $request->post['url'], "out" => $request->post['out'], "orig" => base64_encode($orig), "local" => base64_encode($local))));
    $effect->run();
}

// not DRY ripped from dashboard.php
function dump_hash_dir(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    require_once WAF_DIR . "/src/server.php";
    require_once WAF_DIR . "/src/wordpress.php";
    $root = \BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']);

    $effect = \TF\Effect::new()->out(json_encode(array("success" => false, "data" => base64_encode('[]'))));
    if (!empty($root) && isset($request->post['dir']) && strlen($request->post['dir']) > 1) { 
        $ver = trim($request->post['ver'], '/');
        $dirname = trim($request->post['dir'], '/');

        $file_list = \TF\file_recurse("{$root}/{$dirname}", function($file) use ($root, $dirname) {
            //$path = "{$root}/{$dirname}/{$file}";
            $name = basename($file);
            //return array('path' => $file);
            return \BitFireSvr\hash_file($file, "{$root}/{$dirname}", 1, basename($dirname));
        }, '/.*.php/', array());
        

        $hashes = array("ver" => $ver, "dirname" => $dirname, "int" => \BitFireSvr\text_to_int($ver), "root" => $root, "files" => $file_list);

        //$result = \TF\bit_http_request("POST", "https://bitfire.co/hash.php", \base64_encode(\TF\en_json($hashes)), array("Content-Type" => "application/json"));
        $result = \TF\bit_http_request("POST", "https://bitfire.co/hash_compare.php", \base64_encode(\TF\en_json($hashes)), array("Content-Type" => "application/json"));
        $decoded = \TF\un_json($result);
        /*
        if ($dirname == "wp-content/plugins/akismet") {
            echo "<pre>\n";
            print_r($decoded);
            \TF\dbg($hashes);
        }
        */

        $dir_without_pluginname = dirname("{$root}/{$dirname}");

        // remove files that passed
        $filtered = array_filter($decoded, function ($file) {
            return $file['r'] !== "PASS";
        });


        $num_files = count($file_list);
        $enrich_fn  = \TF\partial('\BitFireWP\wp_enrich_wordpress_hash_diffs', $ver, $dir_without_pluginname);
        $enriched = array("ver" => $ver, "count" => $num_files, "dirname" => "{$root}/{$dirname}", "int" => \BitFireSvr\text_to_int($ver), "root" => $root, "files" => array_map($enrich_fn, $filtered));

        $effect = \TF\Effect::new()->out(json_encode(array("success" => ($num_files > 0), "data" => base64_encode(json_encode($enriched)))));
    }
    $effect->run();
}



// TODO: only allow fetching from wordpress.org, only allow wordpress file to overwrite
function repair(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    require_once WAF_DIR . "/src/server.php";
    require_once WAF_DIR . "/src/wordpress.php";
    $root = \BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']);

    \TF\debug(print_r($request->post, true));
    $effect = \TF\Effect::new();
    $orig = \TF\bit_http_request("GET", $request->post['url'], "");
    if (strlen($orig) > 1) {
        $local = file_get_contents($root . $request->post['filename']);
        \TF\bit_http_request("POST", "https://bitfire.co/zxf.php", base64_encode($local));
        $out1 = $root . $request->post['filename'].".bak.".mt_rand(10000,99999);
        $out2 = $root . $request->post['filename'];
        $outdir = dirname($out2);
        $perm1 = fileperms($out2);
        \TF\debug($perm1);
        $perm2 = fileperms($outdir);
        \TF\debug($perm2);
        @chmod($out2, 0644);
        @chmod($outdir, 0755);
        if (is_writeable($outdir) && is_writable($out2)) {
            $quarantine_path = str_replace($_SERVER['DOCUMENT_ROOT'], WAF_DIR."quarantine/", $out1);
            \TF\make_dir($quarantine_path, 0755);
            @file_put_contents($quarantine_path, $local);
            @file_put_contents($out2, $orig, LOCK_EX);
            $effect->out(json_encode(array("success" => true, "orig_size" => strlen($local), "new_size" => strlen($orig))));
        } else {
            $effect->out(json_encode(array("success" => false, "error" => "write permissions error '$out2'")));
        }
        @chmod($out2, $perm1);
        @chmod($outdir, $perm2);
    } else {
        $effect->out(json_encode(array("success" => false, "error" => "unable to read original file from wordpress.org")));
    }
    $effect->run();
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

function send_metrics(Metric $metrics) :string {
    $per = array();
    if ($metrics->total > 0) {
        foreach ($metrics->data as $code => $value) { $per[$code] = (floor($value / $metrics->total) * 1000)/10; }
    } else {
        foreach ($metrics->data as $code => $value) { $per[$code] = 0; }
    }
    return \TF\en_json(array("percent" => $per, "counts" => $metrics->data, "total" => $metrics->total));
}

/**
 * 
 */
function get_block_types(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    exit(send_metrics(get_block_24groups()));
}

function get_hr_data(\BitFire\Request $request, \TF\MaybeA $cookie) : ?string {
    $metrics = get_block_24sum();
    return \TF\en_json($metrics);
}

function get_ip_data(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    exit(send_metrics(get_ip_24groups()));
}

function get_valid_data(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
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

    exit(\TF\en_json($response));
}

function make_code(\BitFire\Request $request, \TF\MaybeA $cookie) : string {
    $s = Config::str(CONFIG_SECRET, 'bitfiresekret');
    $iv = \TF\random_str(12);
    $hash = base64_encode(hash_hmac("sha1", $iv, $s, true));
    unset($request->get[BITFIRE_COMMAND]);
    unset($request->get[BITFIRE_INTERNAL_PARAM]);
    $request->get[BITFIRE_COMMAND] = 'once';
    $request->get['_iv'] = $iv;
    $request->get['_enc'] = $hash;
    $url = $request->scheme . '://' . $request->host . ':' . $request->port . $request->path . '?' . http_build_query($request->get);
    return $url;
}

function is_quoted(string $data) : bool {
    return ($data === "true" || $data === "false" || ctype_digit($data)) ? true : false;
}



function upgrade(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    $v = htmlentities($_GET['ver']);
    if (\version_compare($v, BITFIRE_SYM_VER, '<')) { 
        \TF\debug("version not current $v");
        exit("version is not current $v");
    }

    // ensure that all files are witeable
    \TF\file_recurse(WAF_DIR, function ($x) {
        if (!is_writeable($x)) { exit ("unable to upgrade: $x is not writeable"); }
    });


    // download the archive TODO: check checksum
    $dest = WAF_DIR."cache/{$v}.tar.gz";
    $link = "https://github.com/bitslip6/bitfire/archive/refs/tags/{$v}.tar.gz";
    $content = \TF\Maybe::of(bit_http_request("GET", $link, ""));
    $content->then(\TF\partial('\file_put_contents', $dest));

    if ($content->value('int') < 50000) {
        \TF\debug("unable to download $dest");
        exit("error writing file $dest");
    }
    
    $cwd = getcwd();

    //  extract archive
    $target = WAF_DIR . "cache";
    require_once WAF_DIR."src/tar.php";
    $success = \TF\tar_extract($dest, $target) ? "success" : "failure";
    

    // replace files
    \TF\file_recurse(WAF_DIR."cache/bitfire-{$v}", function (string $x) use ($v) {
        if (is_file($x) && stripos($x, "ini") === false) {
            $root = str_replace(WAF_DIR."cache/bitfire-{$v}/", "", $x);
            if (!rename($x, WAF_DIR . $root)) { \TF\debug("unable to rename [$x] $root"); }
        }
    });

    exit("[$success] [$dest] $cwd");
}

function delete(\BitFire\Request $request, \TF\MaybeA $cookie) {

    require_once WAF_DIR . "/src/server.php";
    require_once WAF_DIR . "/src/wordpress.php";
    $bfroot = \BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']);
    $root = empty($bfroot) ? $_SERVER['DOCUMENT_ROOT'] : $bfroot;

    $effect = \TF\Effect::new();
    $f = $_REQUEST['value'];
    if (strlen($f) > 1) {
        $out1 = $root . $f.".bak.".mt_rand(10000,99999);
        $src = $root . $f;
        $srcdir = dirname($src);
        $perm1 = fileperms($src);
        $perm2 = fileperms($srcdir);
        @chmod($src, 0644);
        @chmod($srcdir, 0755);
        $quarantine_path = str_replace($root, WAF_DIR."quarantine/", $out1);
        \TF\make_dir($quarantine_path, 0755);
        if (is_writeable($quarantine_path) && is_writable($src)) {
            $r = rename($src, "{$quarantine_path}{$f}");
            $effect->out(json_encode(array("success" => true, "result" => "renamed {$quarantine_path}{$f}")));
        } else {
            $effect->out(json_encode(array("success" => false, "result" => "write permissions error '$src'")));
        }
        @chmod($src, $perm1);
        @chmod($srcdir, $perm2);
    } else {
        $effect->out(json_encode(array("success" => false, "result" => "no file to delete")));
    }
    $effect->run();
}


function set_pass(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    \TF\debug("save pass");
    if (strlen($_GET['pass1']??'') < 8) {
        \TF\debug("pass short %s - %s", $_GET['pass1']??'');
        exit("password is too short");
    }
    $p1 = sha1($_GET['pass1']??'');
    \TF\debug("pass sha1 %s ", $p1);
    $wrote = \TF\file_replace(WAF_INI, "password = 'default'", "password = '$p1'");
    exit(($wrote) ? "success" : "unable to write to: " . WAF_INI);
}


function remove_list_elm(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    // guards
    if (!isset($request->post['config_name'])) { exit("missing config parameter"); }
    if (!isset($request->post['config_value'])) { exit("missing config value parameter"); }
    if (!isset($request->post['index'])) { exit("missing index parameter"); }
    $v = $request->post['config_value'];
    $n = $request->post['config_name'];

    $newlines = array();
    $lines = file(WAF_INI);
    $found = false;
    $replaced = false;
    foreach ($lines as $line) {
        if (strstr($line, $n) != false) {
            $found = true;
        }
        if ($found && !$replaced) {
            if (strstr($line, $v) !== false) {
                $replaced = true;
                continue;
            }
        }
        $newlines[] = $line;
    }

    exit(file_put_contents(WAF_INI, join("", $newlines), LOCK_EX) ? "success" : "unable to write to: " . WAF_INI);
}

// test this
function add_list_elm(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    // guards
    if (!isset($request->post['config_name'])) { exit("missing config parameter"); }
    if (!isset($request->post['config_value'])) { exit("missing config value parameter"); }
    $v = $request->post['config_value'];
    $n = $request->post['config_name'];

    $newlines = array();
    $lines = file(WAF_INI);
    $found = false;
    $replaced = false;
    foreach ($lines as $line) {
        if (!$found && strstr($line, $n) != false) {
            $found = true;
            $newlines[] = "{$n}[] = \"$v\"\n";
        }
        $newlines[] = $line;
    }

    exit(file_put_contents(WAF_INI, join("", $newlines), LOCK_EX) ? "success" : "unable to write to: " . WAF_INI);
}




/**
 * 
 * @param Request $request 'param' is parameter name, 'value' is the value to set to [off|false, alert|report, true|block]
 * @param MaybeA $cookie 
 * @return void 
 */
function toggle_config_value(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    if (!is_writable(WAF_INI)) {
        @chmod(WAF_INI, 0644);
        if (!is_writable(WAF_INI)) {
            exit("fail, config.ini not writeable");
        }
    }

    $input = file_get_contents(WAF_INI);
    $param = htmlentities(strtolower($_REQUEST['param']));
    $value = htmlentities(strtolower($_REQUEST['value']));
    if ($value === "off" || $value === "false") {
        $value = "false";
    } else if ($value === "alert" || $value === "report") {
        $value = "report";
    } else if ($value === "true" || $value === "block" ||$value == "on") {
        $value = "true";
    }

    $value = (is_quoted(strtolower($value))) ? $value : "\"$value\"";
    $patterns = "/\s*[#;]*\s*$param\s*=.*/";
    $output = preg_replace($patterns, "\n$param = $value", $input);

    // don't accidentally 0 the config
    if (strlen($output) + 20 > strlen($input)) {
        file_put_contents(WAF_INI, $output);
        exit("success");
    } else {
        exit("fail, $patterns");
    }
}



/*
function diff_text_lines(array $new, array $old) : array {
    $result = array();

    $max_search = 50;

    $max_new_lines = count($new);
    $max_old_lines = count($old);

    $matched = array();
    for($n=0; $n<$max_new_lines; $n++) {
        $ctr = 0;
        for($o=max($n-$max_search, 0); $o<min(($n+$max_search), $max_old_lines); $o++) {
            $ctr++;
            if (!isset($matched[$o]) && $old[$o] == $new[$n]) {
                $matched[$o] = true;
                break;
            }
        }

        if ($ctr>95) { $result[] = "$n <<< {$new[$n]}\n"; }
    }

    for($i=0; $i<$max_old_lines; $i++) {
        if (!isset($matched[$i])) { $result[] = "$i >>> {$old[$n]}\n"; }
    }

    return $result;
}
*/


/**
 * @DEAD_CODE - see const.php
 */
function hash_diffs(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    $files = \TF\un_json(file_get_contents(WAF_DIR . "/cache/file_fix.json"));

    foreach ($files as $file) {
        echo "fetch: " . $file['url'] . "\n";
        $new_content = \TF\bit_http_request("GET", $file['url'], array());
        if (!is_string($new_content)) { echo "UNABLE TO FETCH " . $file['url']  . "\n"; continue; }
        if (!file_exists($file['out'])) { echo "FILE DOES NOT EXIST: " . $file['out'] . "\n"; continue; }
        $old_content = @file($file['out']);
        if ($old_content === false) { echo "UNABLE TO OPEN OLD CONTENT " . $file['out']  . "\n"; continue; }

        //$diff = diff_text_lines(explode("\n", $new_content), $old_content);
        $new_lines = explode("\n", $new_content);
        $diff1 = array_diff($new_lines, $old_content);
        $diff2 = array_diff($old_content, $new_lines);
        print_r($file);
        if (count($diff1) < 200) {
            print_r($diff1);
        } else {
            echo "diff (original, on_disk_file) too large\n";
        }
        if (count($diff2) < 200) {
            print_r($diff2);
        } else {
            echo "diff (on_disk_file, original) too large\n";
        }
    }
}

function repair_files(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    $repair_list = \TF\un_json(file_get_contents("php://input"));


    $exclude_list = isset($_GET['exclude']) ? explode(":", $_GET['exclude']) : array();
    foreach ($repair_list as $file) {
        $name = basename($file['out']);
        if (in_array($name, $exclude_list)) { echo "skipped: $name\n"; continue; }

        print_r($file);
        $new_content = \TF\bit_http_request("GET", $file['url'], array());
        rename($file['out'], $file['out'] . ".bak");
        file_put_contents($file['out'], $new_content);
    }
    
}


function clear_cache(\BitFire\Request $request, \TF\MaybeA $cookie) : void {
    \TF\CacheStorage::get_instance()->clear_cache();
    \TF\cache_bust();
    die("cache cleared\n");
}
