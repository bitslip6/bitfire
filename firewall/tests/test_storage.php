<?php declare(strict_types=1);

use TF\CacheStorage;

use const TF\CUCKOO_HIGH;
use const TF\CUCKOO_PERM;

const NUM_ENTRIES = 54;

use function TF\tar_extract;

if (!defined("\BitFire\WAF_ROOT")) {
    define('\BitFire\WAF_ROOT', realpath(dirname(__DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR)));
}
include_once \BitFire\WAF_SRC."bitfire.php";
include_once \BitFire\WAF_SRC."util.php";
include_once \BitFire\WAF_SRC."storage.php";



function test_shmop_connect() : void {
    \BitFire\Config::set_value('cache_type', 'shmop');
    $storage = CacheStorage::get_instance();
    assert_instanceof($storage, "\TF\CacheStorage", "shmop storage not initialized");
}

function test_shmop_write() : void {
    \BitFire\Config::set_value('cache_type', 'shmop');
    $storage = CacheStorage::get_instance();
    $value1 = "test";
    $storage->save_data("test", $value1, 2);
    $value2 = $storage->load_data("test");
    // phpinfo();

    //echo "$value1 - $value2\n";
    //die();

    assert_eq($value2, $value1, "shmop storage not working");
}

/**
 * @type slow
 */
function test_shmop_read_expired() : void {
    \BitFire\Config::set_value('cache_type', 'shmop');
    $storage = CacheStorage::get_instance();
    $value1 = "test";
    $storage->save_data("test", $value1, 2);
    sleep(4);
    $value2 = $storage->load_data("test");

    assert_eq($value2, $value1, "shmop expired read not working");
}

function test_shmop_defrag() : void {
    \BitFire\Config::set_value('cache_type', 'shmop');
    $storage = CacheStorage::get_instance();
    \TF\cuckoo::defrag();
}


function test_shmop_write_rand() : void {
    \BitFire\Config::set_value('cache_type', 'shmop');
    $storage = CacheStorage::get_instance();

    $values = array();
    for ($i = 0; $i < NUM_ENTRIES; $i++) {
        $values["000{$i}."] = "000{$i}." . \TF\random_str(1512);
    }

    $good_cnt = 0;
    foreach (array_keys($values) as $key) {
        $result = $storage->save_data($key, $values[$key], 200);
        usleep(10000);
        if (!$result) {
            echo "Failed to save $key\n";
            $result = $storage->save_data($key, $values[$key], 200, CUCKOO_HIGH);
            if (!$result) {
                echo "Failed to save $key with HIGH PRI\n";
                $result = $storage->save_data($key, $values[$key], 200, CUCKOO_PERM);
                assert_true($result, "unable to save_data via shmop");
                if ($result) { $good_cnt++; }
            } else {
                $good_cnt++;
                echo "Saved $key with HIGH PRI\n";
            }
        } else { $good_cnt++; }
    }

    assert_eq($good_cnt, NUM_ENTRIES, "only saved $good_cnt of ".NUM_ENTRIES." entries");

    /*
    $idx = 0;
    foreach (array_keys($values) as $key) {
        $value2 = $storage->load_data($key);
        echo $idx++ . "\n";
        assert_eq($value2, $values[$key], "shmop storage read err $key [$value2] != [$values[$key]]");
    }
    */
}

function test_shmop_read() : void {
    \BitFire\Config::set_value('cache_type', 'shmop');
    $storage = CacheStorage::get_instance();

    $good_cnt = 0;
    $bad_cnt = 0;
    for ($i = 0; $i < NUM_ENTRIES; $i++) {
        usleep(10000);
        $d = $storage->load_data("000{$i}.");
        assert_neq($d, null, "unable to load cache entry 000{$i}");
        if ($d == null) {
            echo "unable to load [$i]\n";
            continue;
        }
        $parts = explode(".", $d);
        if ($parts[0] == $i) {
            $good_cnt++;
        } else {
            $bad_cnt++;
            echo "$i MIS MATCH POST DEFRAG!\n";
        }
    }
}
