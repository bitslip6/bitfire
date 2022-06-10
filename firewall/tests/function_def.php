<?php

function acpu_store(string $key, $value, int $ttl) : bool {
    return true;
}

function acpu_delete(string $key) : bool {
    return true;
}

function acpu_fetch(string $key) : ?string {
    return null;
}

function brotli_compress(string $data) : string {
    return $data;
}

function content_url() : string {
    return "http://localhost/wp-content";
}

function get_home_path() : string {
    return "/var/www/wordpress/wp-content";
};

function plugin_dir_url(string $path) : string {
    return __DIR__ . "/" . $path;
}

function current_user_can(string $capability) : bool {
    return true;
}

function wp_enqueue_script(string $handle, string $src) : void {
    //echo "wp_enqueue_script($handle, $src, $deps, $ver, $in_footer)";
}

function admin_url(string $path) : string {
    return "http://localhost/wp-admin/$path";
}

function plugin_dir_path(string $path) : string {
    return __DIR__ . "/" . $path;
}

function add_menu_page(string $page_title, string $menu_title, string $capability, string $menu_slug, callable $function, string $icon_url, int $position) : void {
    //echo "add_menu_page($page_title, $menu_title, $capability, $menu_slug, $function, $icon_url, $position)";
}

function add_action(string $action, callable $fn) : void {

}

function register_activation_hook(string $path, callable $fn) : void {

}

function register_deactivation_hook(string $path, callable $fn) : void {
}

function esc_attr(string $x) : string { 
    return $x;
}
function get_the_author_meta(string $name, $id) : string {
    return "";
}
function get_user_meta(int $id, string $field, bool $single) : string {
    return "";
}
function update_user_meta(int $user_id, string $name, string $value) {
}
function get_user_by(string $method, string $username) : stdClass {
    return new stdClass();
}
function get_bloginfo(string $type) : string {
    return $type;
}

namespace BitFirePRO;

use BitFire\Request;
use TF\MaybeStr;
use ThreadFin\Effect;

define("WP_CONTENT_DIR", "wp-content");
define("WP_CONTENT_URL", content_url());
define("ABSPATH", "/var/www/wordpress");

function send_pro_mfa(Request $request) {

}

function send_pro_headers(Request $request, MaybeStr $cookies, ?string $agent) : Effect { 
    return Effect::new();
}

function find_malware(array $lines) : ?array {
    return null;
}

function site_unlock() : void { }
function site_lock() : void { }
