<?php
namespace BitFire;
use TF\CacheStorage;
use function TF\ends_with;
use function TF\file_recurse;

class Metric {
    public $data = array();
    public $total = 0;
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
    require_once WAF_DIR . "/server.php";
    $root = $_SERVER['DOCUMENT_ROOT'];
    $cmd = "find $root -name 'wp-settings.php'";
    exec($cmd, $r);
    //echo "[$root] [$cmd\n";
    //echo "\n----\n";
    $json = array();
    foreach ($r as $path) {
        $d = dirname($path);
        $full_path = "$d/wp-includes/version.php";
        $wp_version = "0";
        include_once $full_path;
        if ($wp_version === "0") { die("WTF?\n"); }
        $import = \TF\partial_right('\BitFireSvr\hash_file', $wp_version);
        
        //echo "1: recursing: [$d]\n";
        $json[$d] = file_recurse($d, $import);
        //print_r($result);
    }
    echo json_encode($json, JSON_PRETTY_PRINT);
    //print_r($r);
//echo "\n----\n";
    //die("($d) fin\n");
    //json_encode(\BitFireSvr\hash_wp_root($_SERVER['DOCUMENT_ROOT']));
    //$cmd = "find $root -type f -name '*.php' | xargs crc32";
    //exec($cmd, $out);
}

if (file_exists(WAF_DIR . "proapi.php")) {
    require WAF_DIR . "proapi.php";
}
