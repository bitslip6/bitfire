<?php
namespace BitFire;
use TF\CacheStorage;

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
        $data = $cache->load_data("metrics-$i", BITFIRE_METRICS_INIT);
        if (!is_array($data)) { $data = BITFIRE_METRICS_INIT; }
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
        $data = $cache->load_data("metrics-$i", BITFIRE_METRICS_INIT);
        if (!is_array($data)) { $data = BITFIRE_METRICS_INIT; }
        foreach ($data as $code => $cnt) {
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
        $data = $cache->load_data("metrics-$i", BITFIRE_METRICS_INIT);
        if (!is_array($data)) { $data = array(); }
        foreach ($data as $code => $cnt) {
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
function get_block_types(array $request) {
    exit(send_metrics(get_block_24groups()));
}

function get_hr_data(array $request) {
    $metrics = get_block_24sum();
    return json_encode($metrics);
}

function get_ip_data(array $request) {
    exit(send_metrics(get_ip_24groups()));
}

function make_code(array $request) {
    $s = Config::str(CONFIG_SECRET, 'bitfiresekret');
    $iv = substr(base64_encode(openssl_random_pseudo_bytes(16)), 0, 12);
    $hash = base64_encode(hash_hmac("sha1", $iv, $s, true));
    unset($request['GET'][BITFIRE_COMMAND]);
    unset($request['GET']['_secret']);
    $request['GET'][BITFIRE_COMMAND] = 'once';
    $request['GET']['_iv'] = $iv;
    $request['GET']['_enc'] = $hash;
    $url = $request[REQUEST_SCHEME] . '://' . $request[REQUEST_HOST] . ':' . $request['PORT'] . $request[REQUEST_PATH] . '?' . http_build_query($request['GET']);
    return $url;
}


?>
