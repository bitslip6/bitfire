<?php
namespace ThreadFin;

/**
 * shared memory mapping
 */
class shm {
    private static $ctx = false;
    private static $idx = "d";

    public function __construct() {
        while(self::$ctx === false && self::$idx < "i") {
            $id = ftok(__FILE__, self::$idx);

            //self::$ctx = @shm_attach($id, 4089446, 0640);
            self::$ctx = @shm_attach($id, 1089446, 0640);
            self::$idx++;
        }
        //debug("shm: NEW REQUEST -- shm: [%s] [%s]", self::$idx, (string)self::$ctx);
    }

    public function purge() {
        @shm_remove(self::$ctx);
    }

    public static function read($key, int &$hash = 0) {
        $keyint = intval(hexdec(hash('crc32', $key, false)));
        $result = @shm_get_var(self::$ctx, $keyint);
        //debug("shm: READ [%s] -- shm: [%d]", $key, $keyint);

        if (isset($result[2]) && $result[0] === $key) {
            if ($result[1] >= time()) {
                //debug("shm: READ result: [%s]",print_r($result, true));
                return $result[2];
            }
            //debug("shm: READ expired\n");
            return null;
        }
        //debug("shm: READ removed var\n");
        @shm_remove_var(self::$ctx, $keyint);
        return null;
    }

    public static function read_or_set(string $key, int $ttl, callable $fn) {
        $result = shm::read($key);
        if ($result === false) {
            debug("shm: READ or set false\n");
            $result = $fn();
            shm::write($key, $ttl, $result);
        }
    }

    // overwrites existing entries...
    public static function write(string $key, int $ttl, $item, $force = true) : bool {
        $keyint = intval(hexdec(hash('crc32', $key, false)));
        $d = array($key, time() + $ttl, $item);
        debug("shm: WRITE [%s]", $keyint);
        return @shm_put_var(self::$ctx, $keyint, $d);
    }
}
