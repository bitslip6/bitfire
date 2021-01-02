<?php declare(strict_types=1);
namespace TF;

/**
 * shared memory mapping
 */
class shm {
    private static $ctx = false;
    private static $idx = "d";

    public function __construct() {
        while(self::$ctx === false && self::$idx < "g") {
            self::$ctx = @shm_attach(ftok(__FILE__, self::$idx), 4089446, 0600);
            self::$idx++;
        }
    }

    public function purge() {
        shm_remove(self::$ctx);
    }

    public static function read($key, int &$hash = 0) {
        $keyint = hexdec(hash('crc32', $key, false));
        $result = @shm_get_var(self::$ctx, $keyint);
        if ($result !== false) {
            if (is_array($result) && count($result) === 3) {
                if ($result[0] === $key) {
                    if ($result[1] > time()) {
                        return $result[2];
                    }
                }
            }
            shm_remove_var(self::$ctx, $keyint);
        }
        return null;
    }

    public static function read_or_set(string $key, int $ttl, callable $fn) {
        $result = shm::read($key);
        if ($result === false) {
            $result = $fn();
            shm::write($key, $ttl, $result);
        }
    }

    // overwrites existing entries...
    public static function write(string $key, int $ttl, $item, $force = true) {
        $keyint = hexdec(hash('crc32', $key, false));
        /*
        echo "<pre>$key = key: $keyint</pre>\n";

        if (!$force && shm_has_var(self::$ctx, $keyint)) {
            $value = shm::read($key);
            
        }
        */
        /*
        if (shm_has_var(self::$ctx, $keyint)) {
            $keyint = hexdec(hash('crc32b', $key, false));
            echo "<pre>$key = key 2!: $keyint</pre>\n";
        }
        */

        return shm_put_var(self::$ctx, $keyint, array($key, time() + $ttl, $item));
    }
}
