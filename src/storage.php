<?php
namespace TF;

/**
 * generic storage interface for temp / permenant storage
 */
interface Storage {
    public function save_data(string $key_name, $data, int $ttl);
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

    public static function get_instance() : CacheStorage {
        if (self::$_instance === null) {
            self::$_instance = new CacheStorage(\Bitfire\Config::str('cache_type', 'nop'));
        }
        return self::$_instance;
    }

    /**
     * remove all created semaphores...
     */
    protected function __construct(?string $type = 'nop') {
        if ($type === "apcu" && function_exists('apcu_store')) {
            self::$_type = $type;
        }
        else if ($type === "shmop" && function_exists('shmop_open')) {
            require_once WAF_DIR . "src/cuckoo.php";
            $this->_shmop = new cuckoo();
            self::$_type = $type;
        }
        else if ($type === "shm" && function_exists('shm_attach')) {
            require_once WAF_DIR . "src/shmop.php";
            $this->_shm = new shm();
            self::$_type = $type;
        }
        else { self::$_type = 'nop'; }
    }

    // take a key and return an opcode path
    protected function key2name(string $key) : string {
        return WAF_DIR . "cache/{$key}.profile";
    }

    /**
     * save data to keyname
     * TODO: add flag for not overwitting important data and not writting transient data to opcache 
     */
    public function save_data(string $key_name, $data, int $seconds) {
        assert(self::$_type !== null, "must call set_type before using cache");
        switch (self::$_type) {
            case "shm":
                $this->_shm->write($key_name, $seconds, $data);
                return;
            case "shmop":
                $this->_shmop->write($key_name, $seconds, $data);
                return;
            case "apcu":
                \apcu_store("_bitfire:$key_name", $data, $seconds);
                return;
            case "opcache":
                $s = var_export($data, true);
                $exp = time() + $seconds; 
                file_put_contents($this->key2name($key_name), "<?php \$value = $s; \$success = (time() < $exp);", LOCK_EX);
                return;
            default:
                return;
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

        // force failure to return null
        return ($success) ? $value : $init;
    }

    /**
     * load the data from cache, else call $generator
     */
    public function load_or_cache(string $key_name, int $ttl, callable $generator) {
        if (($data = $this->load_data($key_name)) === null) {
            $data = $generator();
            $this->save_data($key_name, $data, $ttl);
        }
        return $data;
    }

    public function clear_cache() : void {
        switch (self::$_type) {
            case "shmop":
                $value = $this->_shmop->clear();
                break;
        }
    }
}

/**
 * persistant storage
 */
class FileStorage implements Storage {

    public function __construct() {
    }

    // take a key and return an opcode path
    protected function key2name(string $key) : string {
        return WAF_DIR . "cache/{$key}.profile";
    }

    /**
     * returns num bytes written or false
     */
    public function save_data(string  $key_name, $data, int $ttl) {
        return file_put_contents($this->key2name($key_name), json_encode($data), LOCK_EX);
    }

    /**
     * TODO: check stat mtime if the data is still valid...
     */
    public function load_data(string $key_name) {
        $contents = file_get_contents($this->_write_path . "{$key_name}.profile");
        return ($contents !== false) ? \TF\un_json($contents) : null;
    }

    public function update_data(string $key_name, callable $fn, callable $init, int $ttl) {
        $data = $this->load_data($key_name);
        if ($data === null) { $data = $init; }
        $this->save_data($key_name, $fn($data), $ttl);
    }

    /**
     * load the data from cache, else call $generator
     */
    public function load_or_cache(string $key_name, int $ttl, callable $generator) {
        if (($data = $this->load_data($key_name)) === null) {
            $data = $generator();
            $this->save_data($key_name, $data, $ttl);
        }
        return $data;
    }
}




interface BitInspectStore {
    public function save_page(array $page);
    public function load_page(string $page);
    public function load_page_list();
    public function save_page_list($list);
}

class BitInspectFileStore implements BitInspectStore {
    private $_path;

    public function __construct($path) {

        $cache_path = WAF_DIR . "/cache/pages";
        $d = is_dir(($cache_path));
        $w = is_writable(($cache_path));

        if (!is_dir($cache_path) || !is_writable($cache_path)) {
            $cache_path = sys_get_temp_dir();
        }
        $this->_path = realpath($cache_path) . "/";
    }

    private function request_to_name(array $page) {
        $path = join('/', $page);
        if ($path === "") { $path = "/root"; }
        return "$path.json";
    }

    public function save_page(array $page) {
        $data = json_encode($page);
        $path = $this->_path . $page['name'] . ".json";
        $d = dirname($path);
        debug("save page to: ($d) [$path] : " . strlen($data));
        @mkdir($d, 0750, true);
        return file_put_contents($path, $data);
    }

    public function load_page(string $name) {
        $path = $this->_path . $name . ".json";
        if (!is_file($path)) { return null; }
        $data = file_get_contents($path);
        return ($data !== false) ? \TF\un_json($data) : null;
    }

    public function load_page_list() {
        $path = $this->_path . 'bitfire_pagelist.json';
        if (!is_file($path)) { return null; }
        $data = file_get_contents($path);
        return ($data !== false) ? \TF\un_json($data) : null;
    }

    public function save_page_list($list) {
        $data = json_encode($list);
        file_put_contents($this->_path . 'bitfire_pagelist.json', $data);
    }
}
