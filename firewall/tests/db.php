<?php declare(strict_types=1);
/**
 * functional MySQL database abstraction
 */

namespace ThreadFinDB;

use Exception;
use mysqli;
use mysqli_result;
use ThreadFin\MaybeA;
use ThreadFin\MaybeStr;
use const BitFire\WAF_ROOT;
use function ThreadFin\func_name;
use function ThreadFin\partial_right as BINDR;

if (!defined("DUMP_FILE")) {
    if (defined("WAF_ROOT")) {
        define("DUMP_FILE", WAF_ROOT . "cache/dump.txt");
    } else {
        define("DUMP_FILE", sys_get_temp_dir() . "/dump.txt");
    }
}

class Credentials {
    public $username;
    public $password;
    public $prefix;
    public $db_name;

    /**
     * create database credentials
     * @return Credentials
     */
    public function __construct(string $user, string $pass, string $host, string $db_name, string $pre = "") {
        $this->username = $user;
        $this->password = $pass;
        $this->prefix = $pre;
        $this->host = $host;
        $this->db_name = $db_name;
    }
}

/** 
 * used to glue key values pairs together for SQL queries
 * if data key begins with ! then the value is not quoted
 * EG: UPDATE $table set " . glue(" = ", $data, ", ") .  where_clause($where);
 */
function glue(string $join, array $data, string $append_str = "") : string {
    $result = "";
    var_export($data);
    foreach ($data as $key => $value) {
        if ($result != '') { $result .= $append_str; }
        if ($key[0] === '!') { $key = substr($key, 1); $result .= "`{$key}` $join $value"; }
        else { $result .= "`{$key}`" . $join . quote($value); }
    }
    return $result;   
}

/**
 * add SQL quoting to a string, convert ints and bool to SQL types
 * @param mixed $input 
 * @return string 
 */
function quote($input) : string {
    if (is_null($input)) { return 'null'; }
    if (is_numeric($input)) { return strval($input); }
    if (is_string($input)) { return "'".addslashes($input)."'"; }
    if (is_bool($input)) { return $input ? 1 : 0; }
    return $input;
}

/**
 * create a where clause from an array of key value pairs
 * @param array $data 
 * @return string - the generated SQL where clause
 */
function where_clause(array $data) : string { 
    $result = " WHERE ";
    foreach ($data as $key => $value) {
        if ($key[0] == '!') {
            $t = substr($key, 1);
            $result .= " `{$t}` = {$value} , ";
        } else {
            $result .= " `{$key}` = " . quote($value) . ",";
        }
    }
    $x = trim($result, ",");
    return $x;
}


class DB {
    protected $_db;
    public $_errors;
    public $logs = array();
    public $host;
    public $user;
    public $database;
    protected $_log_enabled = false;
    protected $_simulation = false;
    protected $_replay_enabled = false;
    protected $_err_filter_fn;
    protected $_replay_log = [];

    protected function __construct(?\mysqli $db) { $this->_db = $db; $this->_errors = array(); }

    public function __destruct() {
        if ($this->_db) { $this->_db->close(); }
        if (count ($this->_replay_log)) { 
            file_put_contents("replay.log", "\n".implode(";\n", $this->_replay_log).";\n", FILE_APPEND);
        }
    }


    /**
     * @param null|mysqli $mysqli 
     * @return DB a new DB object, from existing connection
     */
    public static function from(?\mysqli $mysqli) : DB { 
        return new DB($mysqli);
    }

    /**
     * @param bool $enable - enable or disable logging
     * @return DB 
     */
    public function enable_log(bool $enable) : DB {
        $this->_log_enabled = $enable;
        return $this;
    }

    /**
     * @param bool $enable - enable or disable logging
     * @return DB 
     */
    public function enable_replay(bool $enable) : DB {
        $this->_replay_enabled = $enable;
        return $this;
    }


    /**
     * @param bool $enable - enable or disable simulation (no queries, just the log)
     * @return DB 
     */
    public function enable_simulation(bool $enable) : DB {
        $this->_simulation = $enable;
        return $this;
    }


    /**
     * @param null|Credentials $cred create a new DB connection
     * @return DB 
     */
    public static function cred_connect(?Credentials $cred) : DB {
        if ($cred == NULL) { return DB::from(NULL); }
        return DB::connect($cred->host, $cred->username, $cred->password, $cred->db_name);
    }

    public static function connect(string $host, string $user, string $passwd, string $db_name) : DB {
        $db = mysqli_init();
        mysqli_options($db, MYSQLI_OPT_CONNECT_TIMEOUT, 3);
        if(mysqli_real_connect($db, $host, $user, $passwd, $db_name)) {
            $db = DB::from($db);
            $db->host = $host;
            $db->user = $user;
            $db->database = $db_name;
            return $db;
        }
        return DB::from(NULL);
    }

    /**
     * @param string $sql raw SQL to run.  be careful!
     * @return bool 
     */
    public function unsafe_raw(string $sql) : bool {
        return $this->_qb($sql);
    }

    /**
     * run SQL $sql return result as bool. errors stored tail($this->_errors)
     */
    protected function _qb(string $sql) : bool {
        $r = false;
        try {
            if ($this->_log_enabled) { $this->logs[] = $sql; }
            if (!$this->_simulation) {
                $r = mysqli_query($this->_db, $sql); 
            }
        }
        // silently swallow exceptions, will catch them in next line
        catch (Exception $e) { $r = false; }
        if ($r === false) {
            $errno = mysqli_errno($this->_db);
            $err = "[$sql] errno($errno) " . mysqli_error($this->_db);
            $this->_errors[] = $err;
        }
        return (bool)$r;
    }

    /**
     * run SQL $sql return result as bool. errors stored tail($this->_errors)
     */
    protected function _qr(string $sql, $mode = MYSQLI_ASSOC) : SQL {
        $r = NULL;
        try {
            if ($this->_log_enabled) { $this->logs[] = $sql; }
            if (!$this->_simulation) {
                $r = mysqli_query($this->_db, $sql); 
            }
        }
        // silently swallow exceptions, will catch them in next line
        catch (Exception $e) { $r = NULL; }
        if (!$r || !$r instanceof mysqli_result) {
            $errno = mysqli_errno($this->_db);
            $err = "[$sql] errno($errno) " . mysqli_error($this->_db);
            $this->_errors[] = $err;
            return SQL::from(NULL, $sql);
        }
        return SQL::from(mysqli_fetch_all($r, $mode), $sql);
    }

    /**
     * build sql replacing {name} with values from $data[name] = value
     * auto quotes values,  use {!name} to not quote
     * @return SQL - SQL result abstraction
     */
    public function fetch(string $sql, ?array $data = NULL, $mode = MYSQLI_ASSOC) : SQL {
        if ($this->_db == NULL) { return SQL::from(NULL); }

        // replace {} with named values from $data, or $this->_x
        $new_sql = preg_replace_callback("/{\w+}/", function ($x) use ($data) {
            $param = str_replace(array('{', '}'), '', $x[0]);
            if ($param[0] == "!") {
                $key = substr($param, 1);
                $result = $data[$key]??"NO_SUCH_KEY_$key";
            } else {
                $result = quote($data[$param]??"NO_SUCH_KEY_$param");
            }
            return $result;
        }, $sql);

        return $this->_qr($new_sql, $mode);
    }

    /**
     * delete entries from $table where $data matches
     * @param string $table table name
     * @param array $where key value pairs of column names and values
     * @return bool 
     */
    public function delete(string $table, array $where) : bool {
        $sql = "DELETE FROM $table " . where_clause($where);
        $success = $this->_qb($sql);
        if ($success) {
            if ($this->_replay_enabled || $this->_log_enabled) {
                $e = mysqli_affected_rows($this->_db);
            }
            if ($this->_replay_enabled && $e > 0) {
                $this->_replay_log[] = $sql;
            }
            if ($this->_log_enabled) {
                $this->logs[] = " --> effected rows: $e";
            }
        }
        return $success;
    }

    /**
     * insert $data into $table 
     * @param string $table 
     * @param array $kvp 
     * @return bool 
     */
    public function insert(string $table, array $kvp) : bool {
        $sql = "INSERT INTO $table (" . join(",", array_keys($kvp)) . 
        ") VALUES (" . join(",", array_map('\DB\quote', array_values($kvp))).")";

        $success = $this->_qb($sql);
        if ($success && $this->_replay_enabled) { $this->_replay_log[] = $sql; }
        return $success;
    }

    /**
     * return a function that will insert key value pairs into $table.  
     * keys are column names, values are data to insert.
     * @param string $table the table name
     * @param ?array $keys list of allowed key names from the passed $data
     * @return callable(array $data) insert $data into $table 
     */
    public function insert_fn(string $table, ?array $keys = null) : callable { 
        $t = $this;
        return function(array $data) use ($table, $t, $keys) : bool {
            if (!empty($keys)) {
                $data = array_filter($data, BINDR('in_array', $keys), ARRAY_FILTER_USE_KEY);
            }
            $sql = "INSERT INTO $table (" . join(",", array_keys($data)) . 
                ") VALUES (" . join(",", array_map('\DB\quote', array_values($data))) . ")";

            $success = $t->_qb($sql);
            if ($success && $this->_replay_enabled) { $t->_replay_log[] = $sql; }
            return $success;
        };
    }

    /**
     * return a function that will insert key value pairs into $table.
     * does not support {} replacement
     * @param string $table the table name
     * @param array $columns column names in (col1, col2) or (col->data) format
     * @return callable(?array $data) that takes KVP ordered in $columns order. 
     *         pass null as KVP data to run the bulk query
     */
    public function bulk_fn(string $table, array $columns) : callable { 
        $t = $this;
        $sql = "INSERT INTO $table (" . join(",", array_keys($columns)) . ") VALUES ";
        return function(?array $data = null) use (&$sql) : bool {
            if ($data !== null) {
                $sql .= join(",", array_map('\DB\quote', array_values($data))) . ")";
                return false;
            }

            $success = $this->_qb($sql);
            if ($success && $this->_replay_enabled) { $this->_replay_log[] = $sql; }
            return $success;
        };
    }



    /**
     * update $table and set $data where $where
     */
    public function update(string $table, array $data, array $where) : bool {
        $sql = "UPDATE $table set " . glue(" = ", $data, ", ") .  where_clause($where);
        return $this->_qb($sql);
    }

    /**
     * store object data into table.  data must have public members and have the 
     * same names as the table
     * @return bool true if the SQL write is successful
     */
    public function store(string $table, Object $data) : bool {
        if (!$this->_db) { return false; }
        $r = new \ReflectionClass($data);
        $props = $r->getProperties(\ReflectionProperty::IS_PUBLIC);
        $name_list = array_reduce($props, function($carry, $item) {
            return $carry . ", " . $item->getName(); 
        });
        $value_list = array_reduce($props, function($carry, $item) use ($data) {
            $name = $item->getName(); return $carry . ", " . $data->$name;
        });
        $sql = "INSERT INTO $table (" . trim($name_list, ", ") .
            ") VALUES (" . trim($value_list, ", ") . ")";
        return $this->_qb($sql);
    }

    public function close() : void {
        if ($this->_db) { mysqli_close($this->_db); $this->_db = NULL; }
        if (count($this->_errors) > 0) {
            $errors = array_filter($this->_errors, function($x) { return stripos($x, "Duplicate") != false; });
            file_put_contents("/tmp/php_db_errors.txt", print_r($errors, true), FILE_APPEND);
        }
    }
}


/**
 * SQL result abstraction
 */
class SQL {
    protected $_x;
    protected $_data = NULL;
    protected $_idx = 0;
    protected $_errors;
    protected $_sql;
    protected $_len;

    /**
     * create a new SQL result abstraction from a SQL associative result
     * @param null|array $x 
     * @param string $sql the sql that generated the result
     * @return SQL 
     */
    public static function from(?array $x, string $in_sql="") : SQL { 
        $sql = new SQL();
        $sql->_x = $x;
        $sql->_len < (is_array($x)) ? count($x) : 0;
        $sql->_sql = $in_sql;
        return $sql; 
    }
    
    /**
     * set internal dataset to value of $name at current row index 
     */
    public function set_col(string $name) : SQL {
        if (isset($this->_x[$this->_idx])) {
            $this->_data = $this->_x[$this->_idx][$name]??NULL;
        } else {
            $this->_data = NULL;
        }

        return $this;
    }

    /**
     * set internal dataset to row  at current row index 
     */
    public function set_row(?int $idx = NULL) : SQL {
        $idx = ($idx !== NULL) ? $idx : $this->_idx;
        if (isset($this->_x[$idx])) {
            $this->_data = $this->_x[$idx];
        }
        return $this;
    }

    /**
     * @return MaybeStr of column $name at current row index
     */
    public function col(string $name) : MaybeSTR {
        if (isset($this->_x[$this->_idx])) {
            return MaybeStr::of($this->_x[$this->_idx][$name]??NULL);
        } 
        return MaybeStr::of(NULL);
    }

    /**
     * @return bool true if column name has a row with at least one value of $value 
     */
    public function in_set(string $name, string $value) : bool {
        return array_reduce($this->_x, function ($carry, $item) use ($name, $value) {
            return $carry || $item[$name] == $value;
        }, false);
    }

    /**
     * @return MaybeA of result row at $idx or current row indx
     */
    public function row(?int $idx = NULL) : MaybeA {
        $idx = ($idx !== NULL) ? $idx : $this->_idx;
        if (isset($this->_x[$idx])) {
            return MaybeA::of($this->_x[$idx]);
        }
        return MaybeA::of(NULL);
    }

    /**
     * increment row index
     */
    public function next() : void {
        $this->_idx++;
    }

    /**
     * return true if data has a row at index $idx
     */
    public function has_row(int $idx = 0) : bool {
        return isset($this->_x[$idx]);
    }

    /**
     * call $fn on current $this->_data (see set_row, set_col)
     * @param bool $spread if true, call $fn(...$this->_data)
     */
    public function ondata(callable $fn, bool $spread = false) : SQL {
        if (!empty($this->_data)) {
            $this->_data = 
                ($spread) ?
                $fn(...$this->_data) :
                $fn($this->_data);
        } else {
            $this->_errors[] = "wont call " . func_name($fn) . " on data : " . var_export($this->_data, true);
        }

        return $this;
    }

    /**
     * map $fn on each row in entire result (works on raw result, no set necessary)
     */
    public function map(callable $fn) : SQL {
        if (is_array($this->_x) && !empty($this->_x)) {
            $this->_data = array_map($fn, $this->_x);
        } else {
            $this->_errors[] = "wont call " . func_name($fn) . " on data : " . var_export($this->_data, true);
        }
        return $this;
    }

    /**
     * reduce $fn($carry, $item) on each row in entire result (works on raw result, no set necessary)
     * $fn may return any type, but should be a string in 99% cases
     */
    public function reduce(callable $fn, $initial = "") {
        if (is_array($this->_x) && !empty($this->_x)) {
            return array_reduce($this->_x, $fn, $initial);
        } else {
            $this->_errors[] = "wont call " . func_name($fn) . " on data : " . var_export($this->_data, true);
        }
        return $this;
    }
    // run an a function that has external effect on current data
    public function effect(callable $fn) : SQL { 
        if (!empty($this->_data)) { $fn($this->_data); } return $this;
    }
    // set data to NULL if $fn returns false
    public function if(callable $fn) : SQL {
        if ($fn($this->_data) === false) { $this->_data = NULL; } return $this;
    }
    // set data to NULL if $fn returns true
    public function if_not(callable $fn) : SQL {
        if ($fn($this->_data) !== false) { $this->_data = NULL; } return $this;
    }
    // return true if we have an empty result set
    public function empty() : bool {
        return empty($this->_x);
    } 
    public function count() : int {
        return is_array($this->_x) ? count($this->_x) : 0;
    } 
    // get all errors
    public function errors() : array {
        return $this->_errors;
    }
    // size of result set
    public function size() : int {
        return is_array($this->_x) ? count($this->_x) : ((empty($this->_x)) ? 0 : 1);
    }
    public function data() : ?array {
        return $this->_x;
    }
    public function __toString() : string {
        return (string)$this->_data;
    }
}

