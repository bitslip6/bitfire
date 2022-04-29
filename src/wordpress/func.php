<?php
namespace FunctionalWP;

class MenuItem {
    public $_title;
    public $_label;
    public $_fn;
    public $_icon_url;
    public $_id;
    public function __construct(string $title, string $label, callable $fn, string $icon_url, string $id = "") {
        static $id_num = 0;
        $this->_id = "functional_wp_id_$id_num";
        $this->_title = $title;
        $this->_fn = $fn;
        $this->_icon_url = $icon_url;
        $id_num++;
    }
}


class Effect {
    private $out = '';
    private $response = 0;
    private $exit = false;
    private $headers = array();
    private $cookie = '';
    private $cache = array();
    private $file_outs = array();
    private $nav = array();
    private $admin_nav = array();
    private $status = 0;

    public static function new() : Effect { return new Effect(); }

    public function nav(MenuItem $item) { $this->nav[] = $item; return $this; }
    public function admin_nav(MenuItem $item) { $this->admin_nav[] = $item; return $this; }
    // response content effect
    public function out(string $line) : Effect { $this->out .= $line; return $this; }
    // response header effect
    public function header(string $name, string $value) : Effect { $this->headers[$name] = $value; return $this; }
    // response cookie effect
    public function cookie(string $value) : Effect { $this->cookie = $value; return $this; }
    // response code effect
    public function response_code(int $code) : Effect { $this->response = $code; return $this; }
    // update cache entry effect
    public function update(\TF\CacheItem $item) : Effect { $this->cache[$item->key] = $item; return $this; }
    // exit the script effect (when run is called)
    public function exit(bool $should_exit = true) : Effect { $this->exit = $should_exit; return $this; }
    // an effect status code that can be read later
    public function status(int $status) : Effect { $this->status = $status; return $this; }
    // an effect to write a file to the filesystem
    public function file(\TF\FileMod $mod) : Effect { $this->file_outs[] = $mod; return $this; }

    // return true if the effect will exit 
    public function read_exit() : bool { return $this->exit; }
    // return the effect content
    public function read_out() : string { return $this->out; }
    // return the effect headers
    public function read_headers() : array { return $this->headers; }
    // return the effect cookie (only 1 cookie supported)
    public function read_cookie() : string { return $this->cookie; }
    // return the effect cache update
    public function read_cache() : array { return $this->cache; }
    // return the effect response code
    public function read_code() : int { return $this->response; }
    // return the effect function status code
    public function read_status() : int { return $this->status; }
    // return the effect filesystem changes
    public function read_files() : array { return $this->file_outs; }
}


function EffectRunner(Effect $effect) {
    foreach ($effect->admin_nav as $item) {
        \add_menu_page($item->title, $item->label, "Administrator", $item->_id, $item->_fn, $item->_icon_url);
    }
}

