<?php declare(strict_types=1);
namespace TF;
/**
 * TODO: refactor and make more DRY, possibly functional
 */

interface Storage {
    public function save_data(string $key_name, $data, int $ttl);
    public function load_data(string $key_name);
    public function load_or_cache(string $key_name, int $ttl, callable $generator, ...$data);
    public function update_data(string $key_name, callable $fn, $init, int $ttl);
}

/**
 * trivial cache abstraction with support for apcu, shared memory and zend opcache 
 */
class CacheStorage implements Storage {
    protected static $_type = 'shmop';
    protected static $_instance = null;
    protected $_shmop = null;
    protected $_shm = null;
    protected $sems = array();

    // a string of, apcu, opcache, shmop, shmem
    public static function set_type(string $cache_type) {
        assert(in_array($cache_type, array('shm', 'shmop', 'apcu', 'nop')));
        self::$_type = $cache_type;
    }

    public static function get_instance() : CacheStorage {
        if (self::$_instance === null) {
            self::$_instance = new CacheStorage(self::$_type);
        }
        return self::$_instance;
    }

    /**
     * remove all created semaphores...
     */
    public function __destruct() {
        foreach ($this->sems as $sem) { sem_remove($sem); }
    }

    protected function __construct($type = 'nop') {
        if ($type !== '') { self::$_type = $type; }
        if (self::$_type === "shmop") {
            require_once WAF_DIR . "cuckoo.php";
            $this->_shmop = new cuckoo();
        }
        if (self::$_type === "shm") {
            require_once WAF_DIR . "shmop.php";
            $this->_shm = new shm();
        }
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
                $s = var_export($data);
                $exp = time() + $seconds; 
                file_put_contents($this->key2name($key_name), "<?php \$value = $s; \$success = (time() < $exp);", LOCK_EX);
                return;
            default:
                return;
        }
    }

    public function lock(string $key) {
        $sem = null;
        if (function_exists('sem_acquire')) {
            $opt = (PHP_VERSION_ID >= 80000) ? true : 1;
            $sem = sem_get(crc32($key), 1, 0600, $opt);
            if (!sem_acquire($sem, true)) { return null; };
            $this->sems[] = $sem;
        }
        return $sem;
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
        if (function_exists('sem_acquire')) { sem_release(($sem)); }
    }

    public function update_data(string $key_name, callable $fn, $init, int $ttl) {
        $sem = $this->lock($key_name);
        $data = $this->load_data($key_name);
        if ($data === null) { $data = $init; }
        $updated = $fn($data);
        $this->save_data($key_name, $updated, $ttl);
        if (function_exists('sem_acquire')) { sem_release(($sem)); }
        return $updated;
    }

    public function load_data(string $key_name, $init = null) {
        assert(self::$_type !== null, "must call set_type before using cache");

        $value = null;
        $success = false;
        switch (self::$_type) {
            case "shm":
                $value = $this->_shm->read($key_name);
                $success = ($value !== null);
                break;
            case "shmop":
                $value = $this->_shmop->read($key_name);
                $success = ($value !== null);
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
        return ($success !== false) ? $value : $init;
    }

    /**
     * load the data from cache, else call $generator
     */
    public function load_or_cache(string $key_name, int $ttl, callable $generator, ...$params) {
        assert(self::$_type !== null, "must call set_type before using cache");
        if (($data = $this->load_data($key_name)) === null) {
            $data = $generator(...$params);
            $this->save_data($key_name, $data, $ttl);
        }
        return $data;
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
        return file_put_contents($this->key2name($key_name), json_encode($data, true), LOCK_EX);
    }

    /**
     * TODO: check stat mtime if the data is still valid...
     */
    public function load_data(string $key_name) {
        $contents = file_get_contents($this->_write_path . "{$key_name}.profile");
        return ($contents !== false) ? json_decode($contents, true) : null;
    }

    public function update_data(string $key_name, callable $fn, $init, int $ttl) {
        $data = $this->load_data($key_name);
        if ($data === null) { $data = $init; }
        $this->save_data($key_name, $fn($data), $ttl);
    }

    /**
     * load the data from cache, else call $generator
     */
    public function load_or_cache(string $key_name, int $ttl, callable $generator, ...$data) {
        if (($data = $this->load_data($key_name)) === null) {
            $data = $generator(...$data);
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
        //$data = "{$page['METHOD']}:{$page['HOST']}:{$page['PATH']}";
        //str_replace("/")
        //return substr($page['PATH'], -5)."/".crc32($data).".json";
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
        //$path = $this->_path . DIRECTORY_SEPARATOR . $this->request_to_name($page);
        //debug("load page [$name]");
        $path = $this->_path . $name . ".json";
        if (!is_file($path)) { return null; }
        $data = file_get_contents($path);
        return ($data !== false) ? json_decode($data, true) : null;
    }

    public function load_page_list() {
        $path = $this->_path . 'bitfire_pagelist.json';
        if (!is_file($path)) { return null; }
        $data = file_get_contents($path);
        return ($data !== false) ? json_decode($data, true) : null;
    }

    public function save_page_list($list) {
        $data = json_encode($list);
        file_put_contents($this->_path . 'bitfire_pagelist.json', $data);
    }
}
