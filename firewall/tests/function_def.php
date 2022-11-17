<?php
const XHPROF_FLAGS_CPU = 1;
const XHPROF_FLAGS_MEMORY = 2;
const XHPROF_FLAGS_NO_BUILTINS = 3;

define ("DB_USER", "");
define ("DB_PASSWORD", "");
define ("DB_NAME", "");
define ("DB_HOST", "");

function xhprof_disable() : array {
    return [];
}
function xhprof_enable(int $options) : void {
}

function igbinary_serialize(mixed $item) : string {
    return "";
}
function igbinary_unserialize(mixed $item) : string {
    return "";
}
function msgpack_pack(mixed $item) : string {
    return "";
}
function msgpack_unserialize(mixed $item) : string {
    return "";
}

function acpu_store(string $key, $value, int $ttl) : bool {
    return true;
}

function acpu_delete(string $key) : bool {
    return true;
}

function acpu_fetch(string $key) : ?string {
    return null;
}
function wp_get_inline_script_tag(string $js, array $attributes = []) : string {
    return '';
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
function wp_get_current_user() : Object{
    return new stdClass();
}
function is_user_logged_in() : bool {
    return true;
}
function wp_mail($email, $subject, $message) : bool {
    return true;
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

function add_filter($data) {
}

function wp_add_inline_script(string $handle, string $content, string $before_or_after = "after") : void {}
function login_header(string $title = 'Log In', string $message = '', $wp_error = null) : string { return $message; }
function login_footer(string $input_id = 'Log In') : string { return $input_id; }
function esc_html(string $text) : string { return $text; }
function esc_url(string $text) : string { return $text; }
function wp_login_url(string $url) : string { return $url; }



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
function get_user_meta(int $id, string $field, bool $single = false) : string {
    return "";
}
function get_userdata($user_id) : Object {
    return new stdClass(); 
}
function update_user_meta(int $user_id, string $name, string $value) {
}
function get_current_user_id() : int { return 1; }
function get_user_by(string $method, string $username) : stdClass {
    return new stdClass();
}
function get_bloginfo(string $type) : string {
    return $type;
}

namespace BitFirePRO;

use BitFire\Request;
use ThreadFin\Effect;
use ThreadFin\MaybeStr;

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
