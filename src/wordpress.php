<?php
namespace BitFireWP;

use function \TF\partial_right AS CAPR;
require_once WAF_DIR . "src/db.php";


class Parts {
    private $_x;
    private $_names = array();
    public static function of(string $seperator, string $data) {
        $p = new Parts();
        $p->_x = explode($seperator, $data);
        return $p;
    } 

    public function name(...$names) : Parts {
        for ($i=0;$i<count($names);$i++) {
            $this->_names[$names[$i]] = $i;
        }
        return $this;
    }

    public function at(string $name) : ?string {
        if (!isset($this->_names[$name])) { return NULL; }
        $idx = $this->_names[$name];
        if ($idx > count($this->_x)) { return NULL; }
        return $this->_x[$idx];
    }
}

// concatenate all data with a concat glue
function concat_fn(string $bind_char) : callable {
    return function(...$concat) use ($bind_char) : string {
        $result = "";
        for ($i=0,$m=count($concat);$i<$m;$i++) {
            $result .= $concat[$i] . $bind_char;
        }
        return trim($result, $bind_char);
    };
}


// take a single line and return the define value, suitable for array_reduce function
function define_to_array(array $input, $define_line) : array {
    
    if (preg_match("/define\s*\(\s*['\"]([a-zA-Z_]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]/", $define_line, $matches)) {
        $input[$matches[1]] = $matches[2];
    }
    if (preg_match("/table_prefix\s*=\s*['\"]([a-z0-9A-Z_]+)/", $define_line, $matches)) {
        $input["prefix"] = $matches[1];
    }

    return $input;
}

// turn define array into credentials
function array_to_creds(?array $defines) : ?\DB\Creds {
    $creds = NULL;
    if ($defines && count($defines) > 5) {
        $creds = new \DB\Creds($defines['DB_USER']??'', $defines['DB_PASSWORD']??'', $defines['DB_HOST']??'', $defines['DB_NAME']??'', $defines['prefix']??'wp_');
    }
    return $creds;
}


// parse wp-config into db credentials
function wp_parse_credentials(string $root) : ?\DB\Creds {
    $creds = NULL;
    $defines = wp_parse_define($root);
    if (isset($defines["SECURE_AUTH_KEY"])) {
        $creds = array_to_creds($defines);
    }
    return $creds;
}

// parse out all defines from the wp-config
function wp_parse_define(string $root) : array {
    static $defines = array();
    if (count($defines) < 1) {
        $config_file = "$root/wp-config.php";
        $data = file($config_file);
        if (!empty($data)) {
            $defines = array_reduce($data, '\BitFireWP\define_to_array', array());
        }
    }
	return $defines;
}


// fetch an auth "salt" for a particular "scheme"
function wp_fetch_salt(string $root, string $scheme) : string {
	$scheme = strtoupper($scheme);
	$defines = wp_parse_define($root);
	if (!isset($defines["{$scheme}_KEY"])) { \TF\debug("auth define [$scheme] missing"); return ""; }
	return $defines["{$scheme}_KEY"] . $defines["{$scheme}_SALT"];
}

// validate an auth cookie
function wp_validate_cookie(string $cookie, string $root) : bool {
    $data = Parts::of("|", $cookie)->name("username", "exp", "token", "hmac");
    $creds = wp_parse_credentials($root);
    $db = \DB\DB::cred_connect($creds);
    $sql = $db->fetch("SELECT SUBSTRING(user_pass, 9, 4) AS pass FROM " . $creds->prefix . "users WHERE user_login = {login} LIMIT 1", array("login" => $data->at("username")));
    if ($sql->empty()) { \TF\debug("wp-auth failed to load db user data"); return false; }
    $key_src = concat_fn("|")($data->at("username"), $sql->col("pass"), $data->at("exp"), $data->at("token"));

    // first try to auth with data from the config file
    $key_list = array("auth", "secure_auth", "logged_in");
    foreach ($key_list as $name) {
        $key = hash_hmac('md5', $key_src, wp_fetch_salt($root, $name));
        $hash = hash_hmac(function_exists('hash')?'sha256':'sha1', concat_fn("|")($data->at("username"), $data->at("exp"), $data->at("token")), $key);
        if (hash_equals($hash, $data->at("hmac"))) { \TF\debug("config key wp match [%s]", $name); return true; }
    }

    // that failed, lets try the db salt and key (may need to try logged_in_key/salt also)
    $db_salt = $db->fetch("SELECT option_value FROM " . $creds->prefix . "options where option_name = 'auth_salt'");
    if (!$db_salt->empty()) {
        $db_key = $db->fetch("SELECT option_value FROM " . $creds->prefix . "options where option_name = 'auth_key'");
        if (!$db_salt->empty()) {
            $salt = $db_salt->col('option_value')();
            $key = $db_key->col('option_value')();
            $full_key = $key . $salt;
            $key = hash_hmac('md5', $key_src, $full_key);
            $hash = hash_hmac(function_exists('hash')?'sha256':'sha1', concat_fn("|")($data->at("username"), $data->at("exp"), $data->at("token")), $key);
            if (hash_equals($hash, $data->at("hmac"))) { \TF\debug("db key wp match [%s]", $name); return true; }
        }
    }

    \TF\debug("wp auth failed");
    return false;
}

// return the wp cookie value
function wp_get_login_cookie(array $cookies) : string {
    $wp = array_filter($cookies, function ($x) {
        if (strpos($x, "wordpress_") !== false) {
            if ((strpos($x, "wordpress_logged_in") === false) && (strpos($x, "wordpress_test") === false)) {
                return true;
            }
        }
        return false;
    }, ARRAY_FILTER_USE_KEY);
    if (count($wp) < 1) { return ""; }
    return array_values($wp)[0];
}


function wp_handle_admin(\BitFire\Request $request, \TF\MaybeA $cookie) {
    \TF\debug("wp_handle_admin");
    $root = \BitFire\Config::str("wp_root");
    if (empty($root)) { \TF\debug("no wp_root"); return; }
    if (strpos($request->path, "/wp-admin/") === false) { \TF\debug("no wp-admin"); return; }
    if ($request->post['action']??'' === "heartbeat") { return; }
    \TF\debug("wp admin req %s", $request->path);


    // upgrade requested, or plugin stuff happening.  unlock for 1 hour.
    if (\TF\contains($request->path, array("/plugins.php", "/upgrade.php")) || (isset($request->post['action']) && $request->post['action'] == "update-plugin")) {
        if (!file_exists(WAF_DIR . "cache/unlock")) {
            if (function_exists('\BitFire\file_site_dir')) {
                touch(WAF_DIR . "cache/unlock", time() + 120);
                \BitFire\file_site_dir($root, false);
            }
        }
    }

/*
    // site admin on wp-admin
    // allow editing htaccess and wp-config
    @chmod("$root/.htaccess", 0644);
    @chmod("$root/wp-config.php", 0644);
    register_shutdown_function(function() use ($root) {
        @chmod("$root/.htaccess", 0444);
        @chmod("$root/wp-config", 0444);
    });

    if (!isset($request->post['slug']) || !isset($request->post['action'])) { \TF\debug("slug"); return; }

    if ($request->post['action']??'' === 'update-plugin' && isset($request->post['slug'])) {
        \TF\debug("update  plugin");
        $plugin = $request->post['slug'];
        if (function_exists("\BitFire\lock_site_dir")) {
            \BitFire\lock_site_dir($request, $plugin, false);
            register_shutdown_function(function() use($request, $plugin) {
                \TF\debug("shutdown called [$plugin]");
                \BitFire\lock_site_dir($request, $plugin, true);
            });
            //die("LOCK $plugin\n");
        }
        else { \TF\debug("no lock site dir"); }
        //die("no func lock!\n");
    }
    else { \TF\debug("no slug or action"); }
    //\TF\dbg($request);
*/
}