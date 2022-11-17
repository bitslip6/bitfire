<?php declare(strict_types=1);

use ThreadFin\Effect;
use ThreadFin\FileData;
use ThreadFin\FileMod;
use ThreadFinDB\Offset;

use const BitFire\WAF_ROOT;

use function ThreadFin\en_json;
use function ThreadFin\partial_right as BINDR;
use function ThreadFinDB\dump_database;

if (!defined("\BitFire\WAF_ROOT")) {
    define('\BitFire\WAF_ROOT', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)));
}

require_once WAF_ROOT."src/db.php";




/**
 * @type integration 
 * @return void 
 */
function test_sql_dump() : void {
    $credentials = new \ThreadFinDB\Credentials("php", "password", "localhost", "wordpress");
    $gz_stream = gzopen("/tmp/backup.sql.gz", "wb6");
    $write_fn = BINDR("\ThreadFinDB\gz_output_fn", $gz_stream);
    $result = dump_database($credentials, "wordpress", $write_fn);
    assert_true(is_array($result), "dump_database did not return an array");

    $is_incomplete = array_reduce($result, function($acc, Offset $val) {
        if ($acc) { return $acc; }
        if ($val->offset != -1) { return true; }
    }, false);

    if ($is_incomplete) {
        $mod = new FileMod(WAF_ROOT."backup.progress", en_json($result));
        Effect::new()->file($mod)->run();
    }
}
