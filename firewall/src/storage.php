<?php
namespace ThreadFin;
use \BitFire\Config as CFG;

/**
 * generic storage interface for temp / permenant storage
 */
interface Storage {
    public function save_data(string $key_name, $data, int $ttl) : bool;
    public function load_data(string $key_name);
    public function load_or_cache(string $key_name, int $ttl, callable $generator);
    public function update_data(string $key_name, callable $fn, callable $init, int $ttl);
}

class CacheItem {
    public $key;
    public $fn;
    public $init;
    public $ttl;

    public function __construct(string $key_name, callable $fn, callable $init, int $ttl) {
        $this->key = $key_name;
        $this->fn = $fn;
        $this->init = $init;
        $this->ttl = $ttl;
    }
}

/**
 * trivial cache abstraction with support for apcu, shared memory and zend opcache 
 */
class CacheStorage implements Storage {
    protected static $_type = 'nop';
    protected static $_instance = null;
    protected $_shmop = null;
    protected $_shm = null;
    public $expires = -1;

    public static function get_instance(?string $type = null) : CacheStorage {
        if (self::$_instance === null || ($type !== null && self::$_type != $type)) {
            //debug("cache new(%d) me(%s) type(%s)", (self::$_instance == null), self::$_type, $type);
            $type = (empty($type) ? CFG::str("cache_type", "nop") : $type);
            self::$_instance = new CacheStorage($type);
        }
        return self::$_instance;
    }

    // fake the current time, to expire all keys on next read
    // set to num of seconds to skip forward.  if $time is 0,
    // default to normal time
    public function fake_time(int $time) {
        if (self::$_type == "shmop") {
            $this->_shmop->fake_time($time);
        }
    }

    /**
     * remove all created semaphores...
     */
    protected function __construct(?string $type = 'nop') {
        if ($type === "apcu" && function_exists('apcu_store')) {
            self::$_type = $type;
        }
        else if ($type === "shmop" && function_exists('shmop_open')) {
            require_once \BitFire\WAF_SRC . "cuckoo.php";
            $this->_shmop = new cuckoo();
            self::$_type = $type;
        }
        else if ($type === "shm" && function_exists('shm_attach')) {
            require_once \BitFire\WAF_SRC . "shmop.php";
            $this->_shm = new shm();
            self::$_type = $type;
        }
        else { self::$_type = 'nop'; }
    }

    // take a key and return an opcode path
    protected function key2name(string $key) : string {
        return \BitFire\WAF_ROOT . "cache/{$key}.profile";
    }

    /**
     * save data to keyname
     * TODO: add flag for not overwitting important data and not writting transient data to opcache 
     * 32 = CUCKOO_LOW
     */
    public function save_data(string $key_name, $data, int $seconds, int $priority = 32) : bool {
        assert(self::$_type !== null, "must call set_type before using cache");
        $storage = array($key_name, $data);
        switch (self::$_type) {
            case "shm":
                return $this->_shm->write($key_name, $seconds, $storage);
            case "shmop":
                return $this->_shmop->write($key_name, $seconds, $storage, $priority);
            case "apcu":
                if ($seconds < 1) { return \apcu_delete("_bitfire:$key_name"); }
                return (bool)\apcu_store("_bitfire:$key_name", $storage, $seconds);
            case "opcache":
                $s = var_export($storage, true);
                $exp = time() + $seconds; 
                $data = "<?php \$value = $s; \$priority = $priority; \$success = (time() < $exp);";
                return file_put_contents($this->key2name($key_name), $data, LOCK_EX) == strlen($data);
            default:
                return false;
        }
    }

    // only lock metrics updates
    public function lock(string $key_name) {
        $sem = null;

        if (strpos($key_name, 'metrics') !== false && function_exists('sem_acquire')) {
            $opt = (PHP_VERSION_ID >= 80000) ? true : 1;
            $sem = sem_get(0x228AAAE7, 1, 0660, $opt);
            if (!sem_acquire($sem, true)) { return null; };
        }
        return $sem;
    }
    
    // unlock the semaphore if it is not null
    public function unlock($sem) {
        if ($sem != null && function_exists('sem_release')) { sem_release(($sem)); }
    }

    /**
     * FIFO buffer or $num_items, ugly, refactor
     */
    public function rotate_data(string $key_name, $data, int $num_items) {
        $sem = $this->lock($key_name);
        $saved = $this->load_data($key_name);
        if (!\is_array($saved)) { $saved = array($data); }
        else { $saved[] = $data; }
        $this->save_data($key_name, array_slice($saved, 0, $num_items), 86400*30);
        $this->unlock($sem);
    }

    /**
     * update cache entry @key_name with result of $fn or $init if it is expired.
     * return the cached item, or if expired, init or $fn
     * @param $fn($data) called with the original value, saves with returned value
     */
    public function update_data(string $key_name, callable $fn, callable $init, int $ttl) {
        $sem = $this->lock($key_name);
        $data = $this->load_data($key_name);
        if ($data === null) { $data = $init(); }
        $updated = $fn($data);
        $this->save_data($key_name, $updated, $ttl);
        $this->unlock($sem);
        return $updated;
    }

    public function load_data(string $key_name, $init = null) {
        assert(self::$_type !== null, "must call set_type before using cache");

        $value = null;
        $success = false;

        switch (self::$_type) {
            case "shm":
                $tmp = $this->_shm->read($key_name);
                $success = ($tmp !== NULL);
                $value = ($success) ? $tmp : NULL;
                break;
            case "shmop":
                $tmp = $this->_shmop->read($key_name);
                $success = ($tmp !== NULL);
                $value = ($success) ? $tmp : NULL;
                break;
            case "apcu":
                $value = \apcu_fetch("_bitfire:$key_name", $success);
                break;
            case "opcache":
                @include($this->key2name($key_name));
                break;
            default: 
                break;
        }

        if ($success) {
            // load failed
            if (is_bool($value)) {
                return $init;
            }
            if (isset($value[0]) && $value[0] == $key_name) {
                return $value[1];
            }
        }

        return $init;
    }

    /**
     * load the data from cache, else call $generator
     */
    public function load_or_cache(string $key_name, int $ttl, callable $generator) {
        if (($data = $this->load_data($key_name)) === null) {
            $data = $generator();
            if (is_array($data)) {
                $s = count($data) . " elements";
            } else {
                $s = (string)$data;
            }
            debug("load_or_cache failed to load $key_name [%s]", $s);
            $this->save_data($key_name, $data, $ttl);
        }
        return $data;
    }

    public function clear_cache() : void {
        switch (self::$_type) {
            case "shmop":
                trace("clear");
                debug("cache clear");
                $value = $this->_shmop->clear();
                break;
        }
    }
}

