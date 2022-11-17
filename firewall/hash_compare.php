<?php

use DB\SQL;

use const BitFire\DS;

define("WAF_DIR", "/home/cory/dev/bitfire-plugin/bitfire/firewall/");
if (!defined("WAF_DIR")) {
    define('WAF_DIR', realpath(dirname(__FILE__))); //.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)));
}

require_once WAF_DIR . "src/util.php";
require_once WAF_DIR . "tests/db.php";

/**
 * @param SQL $sql to search
 * @param string $search_col column to search in each sql row 
 * @param int $search_value the target value to find
 * @return int 
 */
function find_closest_value_index(SQL $sql, string $search_col, int $search_value) : int {
    $closest = 9999999999;
    $idx = -1;
    $sqlsz = $sql->size();
    for ($i=0; $i<$sqlsz; $i++) {
        $sz = $sql->row($i)->extract($search_col)->value('int');
        if (abs($sz - $search_value) < $closest) {
            $closest = abs($sz-$search_value);
            $idx = $i;
        }
    }

    return $idx;
}


function enrich_tables(array $hash, \DB\DB $db, string $version) : array {
    static $ids = array();
    // NOTE: early return for core files so we dont set a plugin_id here
    switch ($hash["type"]) {
        case "wp_plugin":
        case "wp_plugins":
            $hash["table"] = "plugin";
            break;
        case "wp_theme":
        case "wp_themes":
            $hash["table"] = "theme";
            break;
        case "wp_core":
        default:
            $hash["table"] = "core";
            return $hash;
            break;
    }
    $table = $hash["table"];
    if (isset($ids[$hash["table"]])) {
        $hash["plugin_id"] = $ids[$hash["table"]];
        return $hash;
    }

    if (!empty($hash["name"])) {
        $sql = $db->fetch("SELECT {$table}_id FROM $table WHERE name = {name}", array("name" => $hash["name"]));

        if ($sql->size() < 1) {
            $hash['info'] = "plugin name not found";
            $hash["plugin_id"] = -1;
            $ids[$hash["name"]] = -1;
        } else {
            $id = $sql->col("{$table}_id")->value('int');
            $ids[$hash["name"]] = $id;
            $hash["plugin_id"] = $id;
            $hash["tag"] = $version;
        }
    }

    return $hash;
}


function validate_hash(array $hash, DB\DB $db) : array {

    // gaurd for word press config file
    if ($hash['file_path'] == '/wp-config.php') { $hash['r'] = 'PASS'; return $hash; }
    if (isset($hash["plugin_id"]) && $hash["plugin_id"] < 0) { $hash["found"] = false; return $hash; }

    $and = "";
    if (isset($hash["plugin_id"])) { $and = " AND {$hash['table']}_id = {$hash['plugin_id']}"; }

    // find the hash
    $sql = $db->fetch("SELECT distinct crc_trim, size, tag FROM hash_{$hash['table']} H WHERE crc_path = {crc_path} $and", $hash);

    // crc checksum does not match
    if ($sql->size() >= 1) {
        $idx = find_closest_value_index($sql, "crc_trim", $hash['crc_trim']);
        $hash['idx'] = $idx;
        $hash['size2'] = 0;
        $hash["found"] = true;
        if ($idx > -1) {
            $row = $sql->row($idx);
            if ($row->extract('crc_trim')->value('int') == $hash['crc_trim']) {
                $hash['crc_expected'] = $row->extract('crc_trim')->value('int');
                $hash['tag'] = $row->extract('tag')->value('string');
                $hash['idx'] = $idx;
                $hash['size2'] = $row->extract('size')->value('int');
                $hash['r'] = "PASS";
            } else {
                $idx = find_closest_value_index($sql, "size", $hash['size']);
                $row = $sql->row($idx);

                $hash['crc_expected'] = $row->extract('crc_trim')->value('int');
                $hash['tag'] = $row->extract('tag')->value('string');
                $hash['idx'] = $idx;
                $hash['size2'] = $row->extract('size')->value('int');
                $hash['r'] = "FAIL";
            }
        }

        if (!isset($hash['r'])) {
            $hash['r'] = "FAIL";
        }
    }
    // file not found in DB
    else {
        $hash['r'] = "MISS";
        $hash['size2'] = 0;
        $hash["found"] = false;
    }

    return $hash;
}


function root_compare(array $data): array
{
    $db = \DB\DB::connect("localhost", "php", "password", "bitfire");
    $db->enable_log(true);

    //echo var_export($data, true);
    if (isset($data['files'])) {
        $files = $data['files'];
        $version = $data['ver'];
        $hash2 = array_map(\TF\partial_right("enrich_tables", $db, $version), array_filter($files));
        $hash3 = array_map(\TF\partial_right("validate_hash", $db), $hash2);
        return $hash3;
    }
    return $data;
}


$sample = <<<EOT
{
    "root": "\/var\/www\/wordpress\/",
    "hashes": [
        {
            "file_path": "\/var\/www\/wordpress\/index.php",
            "rel_path": "\/index.php",
            "size": 405,
            "crc_path": 1864550530,
            "crc_trim": 2847081343,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/wp-activate.php",
            "rel_path": "\/wp-activate.php",
            "size": 7165,
            "crc_path": 3960442955,
            "crc_trim": 2976552062,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/wp-blog-header.php",
            "rel_path": "\/wp-blog-header.php",
            "size": 351,
            "crc_path": 472885168,
            "crc_trim": 1815621155,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/wp-comments-post.php",
            "rel_path": "\/wp-comments-post.php",
            "size": 2338,
            "crc_path": 994865894,
            "crc_trim": 3914987325,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/wp-cron.php",
            "rel_path": "\/wp-cron.php",
            "size": 3939,
            "crc_path": 1351620557,
            "crc_trim": 1620412894,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/wp-links-opml.php",
            "rel_path": "\/wp-links-opml.php",
            "size": 2496,
            "crc_path": 881287467,
            "crc_trim": 3382845463,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/wp-load.php",
            "rel_path": "\/wp-load.php",
            "size": 3900,
            "crc_path": 4278419902,
            "crc_trim": 527830173,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/wp-login.php",
            "rel_path": "\/wp-login.php",
            "size": 47916,
            "crc_path": 2455793430,
            "crc_trim": 1371421745,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/wp-mail.php",
            "rel_path": "\/wp-mail.php",
            "size": 8582,
            "crc_path": 3216323537,
            "crc_trim": 2570566187,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/wp-settings.php",
            "rel_path": "\/wp-settings.php",
            "size": 23025,
            "crc_path": 2150092084,
            "crc_trim": 2197631097,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/wp-signup.php",
            "rel_path": "\/wp-signup.php",
            "size": 31959,
            "crc_path": 1133987612,
            "crc_trim": 815223056,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/wp-trackback.php",
            "rel_path": "\/wp-trackback.php",
            "size": 4747,
            "crc_path": 2393076395,
            "crc_trim": 1008000432,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        },
        {
            "file_path": "\/var\/www\/wordpress\/xmlrpc.php",
            "rel_path": "\/xmlrpc.php",
            "size": 3236,
            "crc_path": 4134485254,
            "crc_trim": 3543344878,
            "crc_expected": null,
            "type": "wp_core",
            "name": "",
            "version": null
        }
    ]
}
EOT;

$s = file_get_contents("php://input");
$in = \TF\un_json(base64_decode($s));
$json = json_encode(root_compare($in), JSON_PRETTY_PRINT);

$encoding = $_SERVER["HTTP_ACCEPT_ENCODING"]??"";
if (\TF\contains($encoding, "br") && function_exists("brotli_compress")) {
  header("Content-Encoding: br");
  $final = brotli_compress($json);
}
else if (\TF\contains($encoding, "gzip") && function_exists("gzencode")) {
  header("Content-Encoding: gzip");
  $final = gzencode($json);
}
else if (\TF\contains($encoding, "deflate") && function_exists("gzencode")) {
  header("Content-Encoding: deflate");
  $final = gzencode($json, -1, FORCE_DEFLATE);
}
else {
  $final = $json;
} 
echo $final;



echo $json;
