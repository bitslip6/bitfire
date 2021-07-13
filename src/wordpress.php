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

class Concat {
    private $_binder;
    private $_data = "";

    public static function of(string $binder) {
        $c = new Concat();
        $c->_binder = $binder;
        return $c;
    }

    public function add(?string $data) {
        $this->_data .= (($data !== NULL) ? $data : '') . $this->_binder;
        return $this;
    }

    public function get() : string {
        return trim($this->_data, $this->_binder);
    }
}



// take a single line and return the define value, suitable for array_reduce function
function define_to_array(array $input, $define_line) : array {
    
    if (preg_match("/define\s*\(\s*['\"]([a-zA-Z_]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]/", $define_line, $matches)) {
        $input[$matches[1]] = $matches[2];
    }
    if (preg_match("/table_prefix\s*=\s*['\"]([a-zA-Z_]+)/", $define_line, $matches)) {
        $input["prefix"] = $matches[1];
    }

    return $input;
}

// turn define array into credentials
function array_to_creds(?array $defines) : ?\DB\Creds {
    $creds = NULL;
    if ($defines && count($defines) > 5) {
        $creds = new \DB\Creds($defines['DB_USER']??'', $defines['DB_PASSWORD']??'', $defines['DB_HOST']??'', $defines['DB_NAME']??'', $defines['predix']??'wp_');
    }
    return $creds;
}

// parse wp-config into db credentials
function wp_parse_credentials(string $root) : ?\DB\Creds {
    $config_file = "$root/wp-config.php";
    $data = file($config_file);
    $defines = array_reduce($data, '\BitFireWP\define_to_array', array());
    if (isset($defines["SECURE_AUTH_KEY"])) {
        $creds = array_to_creds($defines);
        $creds->salt_key = (is_ssl()) ? $defines["SECURE_AUTH_KEY"] . $defines["SECURE_AUTH_SALT"] : $defines["AUTH_KEY"] . $defines["AUTH_SALT"];
        \TF\debug("salt key: {$creds->salt_key}");
        return $creds;
    }
    return NULL;
}

function wp_validate_cookie(string $cookie, string $root) : bool {
    $data = Parts::of("|", $cookie)->name("username", "exp", "token", "hmac");
    $creds = wp_parse_credentials($root);
    $db = \DB\DB::cred_connect($creds);
    $sql = $db->fetch("SELECT SUBSTRING(user_pass, 8, 4) AS pass FROM " . $creds->prefix . "users WHERE user_login = {login} LIMIT 1", array("login" => $data->at("username")));
    $key_src = Concat::of("|")->add($data->at("username"))->add($sql->col("pass"))->add($data->at("exp"))->add($data->at("token"));
    $key = hash_hmac( 'md5', $key_src, $creds->salt_key);
    $hash = hash_hmac(function_exists('hash')?'sha256':'sha1', Concat::of("|")->add($data->at("username"))->add($data->at("exp"))->add($data->at("token")), $key);
    return hash_equals($hash, $data->at("hmac"));
}
