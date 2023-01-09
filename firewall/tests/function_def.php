<?php
const XHPROF_FLAGS_CPU = 1;
const XHPROF_FLAGS_MEMORY = 2;
const XHPROF_FLAGS_NO_BUILTINS = 3;
const DISABLE_NAG_NOTICES = 99;

define ("DB_USER", "");
define ("DB_PASSWORD", "");
define ("DB_NAME", "");
define ("DB_HOST", "");
define ("WP_CONTENT_DIR", "/var/www/wordpress/wp-content");
define("ABSPATH", $_SERVER["DOCUMENT_ROOT"]);

function mt_rand(int $min, int $max) : int { return 1; }
function mt_getrandmax() : int { return 1; }

function free_disk_space(string $path): int {
    return 1024*1024;
}
function xhprof_disable() : array {
    return [];
}
function xhprof_enable(int $options) : void {
}

function get_locale() : string { return ""; }

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
function get_option(string $option_name) : string {
    return "";
}


function wp_next_scheduled( string $event_name) : int { return 0; }
function wp_schedule_event( int $time, string $interval_name, string $action_name) :void { };

function get_bloginfo(string $show) : string { return ""; }
function add_submenu_page( string $parent_slug, string $page_title, string $menu_title, string $capability, string $menu_slug, $callback = '', int $position = null ): bool { return false; }
function wp_add_dashboard_widget(string $widget_name, string $description, callable $fn) : void { };
function get_admin_url() : string { return "http://localhost/wp-admin"; }
function _wp_specialchars(string $input) : string { return htmlspecialchars($input); }
function update_user_meta(int $my_id, string $meta_name, string $meta_value): bool { return true; }
function get_user_meta(int $my_id, string $meta_name) { return ""; }
function get_userdata(int $user_id) : StdClass { return new StdClass; }
function get_user_by(string $column, string $column_value) : StdClass  { return new StdClass; }
function get_current_user_id() : int { return 1; }
function wp_register_style(string $handle, string $src, ?array $deps = [], string $ver = "1.0") { }
function wp_enqueue_scripts(string $handle, string $src, ?array $deps = [], string $ver = "1.0", bool $in_footer = false) { }
function wp_enqueue_style(string $handle, string $src, ?array $deps = [], string $ver = "1.0", bool $in_footer = false) { }
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
function esc_attr(string $text) : string { return $text; }
function esc_html(string $text) : string { return $text; }
function esc_url(string $text) : string { return $text; }
function wp_login_url(string $url) : string { return $url; }
function wp_register_script(string $name, string $file_path, ?array $deps =[], string $ver="1.0", bool $in_footer = false) { };
function register_activation_hook(string $file_name, callable $function) : void { };
function register_deactivation_hook(string $file_name, callable $function) : void { };



function site_unlock() : void { }
function site_lock() : void { }
