<?php
namespace BitFire;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RegexIterator;
use TF\CacheStorage;

use function TF\bit_http_request;
use function TF\ends_with;
use function TF\map_reduce;
use function TF\str_reduce;

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

class Metric {
    public $data = array();
    public $total = 0;
}

function add_api_exception(\BitFire\Request $r) : string {
    $ex = new \BitFire\Exception($r->post['code'], \TF\random_str(8), NULL, $r->post['path']);
    $added = \BitFire\add_exception($ex);
    return ($added) ? "success" : "fail";
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

function parse_24_groups(array $summary, int $total) {
    
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

function send_metrics(Metric $metrics) {
    $per = array();
    if ($metrics->total > 0) {
        foreach ($metrics->data as $code => $value) { $per[$code] = (floor($value / $metrics->total) * 1000)/10; }
    } else {
        foreach ($metrics->data as $code => $value) { $per[$code] = 0; }
    }
    return json_encode(array("percent" => $per, "counts" => $metrics->data, "total" => $metrics->total));

}

/**
 * 
 */
function get_block_types(\BitFire\Request $request) {
    exit(send_metrics(get_block_24groups()));
}

function get_hr_data(\BitFire\Request $request) {
    $metrics = get_block_24sum();
    return json_encode($metrics);
}

function get_ip_data(\BitFire\Request $request) {
    exit(send_metrics(get_ip_24groups()));
}

function get_valid_data(\BitFire\Request $request) {
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

    exit(json_encode($response));
}

function make_code(\BitFire\Request $request) {
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

function upgrade(\Bitfire\Request $request) {
    $v = htmlentities($_GET['ver']);
    if (\version_compare($v, BITFIRE_SYM_VER, '>=')) {

        // ensure that all files are witeable
        \TF\file_recurse(WAF_DIR, function ($x) use ($v) {
            if (is_file($x) 
                && stripos($x, "ini") === false
                && stripos($x, "/.") === false) {
                if (!is_writeable($x)) { exit ("unable to upgrade: $x is not writeable"); }
            }
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
        $f = __FILE__;

        //  extract archive
        $target = WAF_DIR . "cache";
        require_once WAF_DIR."src/tar.php";
        $success = \TF\tar_extract($dest, $target) ? "success" : "failure";
        
        // replace files
        \TF\file_recurse(WAF_DIR."cache/bitfire-{$v}", function ($x) use ($v) {
            if (is_file($x) && stripos($x, "ini") === false) {
                $base = basename($x);
                $path = dirname($x);
                $root = str_replace(WAF_DIR."cache/bitfire-{$v}/", "", $x);
                //echo "base [$base] path [$path]  - [" . WAF_DIR . $root . "]\n";
				if (!rename($x, WAF_DIR . $root)) {
                    // exit("upgrade failed");
                }
            }
        });//, "/.*.php/");

        exit("[$success] [$dest] $cwd [$f]");
    } else {
        \TF\debug("cowardly refusing to download same or older release");
    }
    exit("version too old");
}

function set_pass(\BitFire\Request $request) {
    \TF\debug("save pass");
    if (strlen($_GET['pass1']??'') < 8) {
        \TF\debug("pass short %s - %s", $_GET['pass1']??'');
        exit("password is too short");
    }
    $p1 = sha1($_GET['pass1']??'');
    \TF\debug("pass sha1 %s ", $p1);
    $wrote = \TF\file_replace(WAF_DIR."config.ini", "password = 'default'", "password = '$p1'");
    exit(($wrote) ? "success" : "unable to write to: " . WAF_DIR."config.ini");
}

function toggle_config_value(\BitFire\Request $request) {
    if (!is_writable(WAF_DIR."config.ini")) {
        exit("fail");
    }

    $input = file_get_contents(WAF_DIR."config.ini");
    $param = htmlentities(strtolower($_GET['param']));
    $value = htmlentities(strtolower($_GET['value']));
    if ($value === "off" || $value === "false") {
        $value = "false";
    } else if ($value === "alert" || $value === "report") {
        $value = "report";
    } else if ($value === "true" || $value === "block") {
        $value = "true";
    }

    $value = (is_quoted(strtolower($value))) ? $value : "\"$value\"";
    $patterns = "/\s*$param\s*=.*/";
    $output = preg_replace($patterns, "\n$param = $value", $input);

    // don't accidently 0 the config
    if (strlen($output) + 20 > strlen($input)) {
        file_put_contents(WAF_DIR."config.ini", $output);
        exit("success");
    } else {
        exit("fail");
    }
}


function dump_hashes(\BitFire\Request $request) {
    require_once WAF_DIR . "/src/server.php";
    \TF\debug("search roots: "  . \TF\en_json($_SERVER['DOCUMENT_ROOT']));
    $roots = \BitFireSvr\find_wordpress_root($_SERVER['DOCUMENT_ROOT']);
    $roots = array_filter($roots, function ($x) { 
        $is_old = (stripos($x, "/old") !== false);
        \TF\debug("check root $x [$is_old]");
        return !$is_old;
    });
    \TF\debug("found roots: "  . \TF\en_json($roots));

    // save ref to hashes and match with response...
    $hashes = array_map('\BitFireSvr\get_wordpress_hashes', $roots);
    $hashes = array_filter($hashes, function ($x) { 
        if (count($x['files']) > 1) {
            \TF\debug("num files: " . count($x['files']));
            return true;
        }
        return false;
    });
    //exit(\TF\en_json($hashes));
    //\TF\bit_http_request("POST", "http://bitfire.co/hash.php", "[{'ver':1,'files':[[0,1,2,3,4]}]");
    
/*
    foreach ($hashes as $root)
        $offset = 0;
        while ($offset < count($root['files'])) {
*/
            $result = \TF\bit_http_request("POST", "http://bitfire.co/hash.php?x=9", \base64_encode(\TF\en_json($hashes)), array("Content-Type" => "application/json"));
            $decoded = \TF\un_json($result);

//        }
//    }



    $fix_files = array();
    if ($decoded && count($decoded) > 0) {
        \TF\debug("hash result len " . count($decoded));
        foreach ($decoded as $root) {
            if (is_array($root)) {
                foreach ($root as $file) {
                    //print_r($file);
                    $path = "http://develop.svn.wordpress.org/tags" . $file[0];
                    $parts = explode("/", $file[0]);
                    $out = $file[4] . "/" . join("/", array_slice($parts, 3));
                    $fix_files[] = array('url' => $path, 'out' => $out);
                }
            } else {
                \TF\debug("unknown root!");
            }
        }
    } else {
        \TF\debug("hash result len 0");
    }

    file_put_contents(WAF_DIR . "cache/file_fix.json", \TF\en_json($fix_files));

    exit(\TF\en_json($fix_files));
}

function diff_text_lines(array $new, array $old) : array {
    $result = array();

    $src_line = 0;
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

        //if (!isset($result[$n])) { $result[$n] = -1; }
    }

    for($i=0; $i<$max_old_lines; $i++) {
        if (!isset($matched[$i])) { $result[] = "$i >>> {$old[$n]}\n"; }
    }

    return $result;
}


function hash_diffs(\BitFire\Request $request) {
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

function repair_files(\BitFire\Request $request) {
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


function clear_cache(\BitFire\Request $request) {
    \TF\CacheStorage::get_instance()->clear_cache();
    \TF\cache_bust();
    die("cache cleared\n");
}

if (file_exists(WAF_DIR . "src/proapi.php")) {
    require WAF_DIR . "src/proapi.php";
}

