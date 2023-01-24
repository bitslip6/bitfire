<?php declare(strict_types=1);
/**
 * functional MySQL database abstraction
 */

namespace ThreadFinDB;

use Attribute;
use Exception;
use mysqli;
use mysqli_result;
use ThreadFin\MaybeA;
use ThreadFin\MaybeStr;

use function ThreadFin\dbg;
use function ThreadFin\do_for_all_key;
use function ThreadFin\func_name;
use function ThreadFin\partial_right as BINDR;
use function ThreadFin\partial as BINDL;
use function ThreadFin\trace;
use function ThreadFin\utc_time;

const DB_FETCH_NUM_ROWS = 2;
const DB_FETCH_INSERT_ID = 4;
const DB_DUPLICATE_IGNORE = 8;
const DB_DUPLICATE_ERROR = 16;
const DB_DUPLICATE_UPDATE = 32;
const DB_FETCH_SUCCESS = 1;


/**
 * The property is a primary key and will not update on duplicate
 */
#[Attribute(Attribute::TARGET_CLASS_CONSTANT|Attribute::TARGET_PROPERTY)]
class NoUpdate { public function __construct() {} }
/** 
 * the attribute will not update on duplicate if the update would null it
 */
#[Attribute(Attribute::TARGET_CLASS_CONSTANT|Attribute::TARGET_PROPERTY)]
class NotNull { public function __construct() {} }
/**
 * The property should only be updated if the value is not null and null in the DB
 */
#[Attribute(Attribute::TARGET_CLASS_CONSTANT|Attribute::TARGET_PROPERTY)]
class IfSet { public function __construct() {} }


// set the error log file if running in cli mode
if (!defined("BitFire\WAF_ROOT")) {
    define("SQL_ERROR_FILE", "/tmp/php_sql_errors.log");
} else {
    define("SQL_ERROR_FILE", false);
}


class Credentials {
    public $username;
    public $password;
    public $prefix;
    public $db_name;
    public $host;

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
        if (strlen($result) > 7) { $result .= " AND "; }
        if ($key[0] == '!') {
            $t = substr($key, 1);
            $result .= " `{$t}` = {$value} ";
        } else {
            $result .= " `{$key}` = " . quote($value);
        }
    }
    $x = trim($result, ",");
    return $x;
}


class DB {
    protected $_db;
    public $errors;
    public $logs = [];
    public $host;
    public $user;
    public $database;
    public $prefix;
    protected $_log_enabled = false;
    protected $_simulation = false;
    protected $_replay_enabled = false;
    protected $_err_filter_fn;
    protected $_replay_log = "";
    protected $_replay = [];

    /**
     * @param null|mysqli $db 
     * @return void 
     */
    protected function __construct(?\mysqli $db) {
        $this->_db = $db;
        $this->errors = array();
    }

    public function __destruct() {
        if ($this->_db) { $this->_db->close(); }
        if ($this->_replay_enabled && count($this->_replay) >= 1) { 
            file_put_contents($this->_replay_log, "\n".implode(";\n", $this->logs).";\n", FILE_APPEND);
        }
    }


    /**
     * @param null|mysqli $mysqli 
     * @return DB a new DB object, from existing connection
     */
    public static function from(?\mysqli $mysqli) : DB {
        trace("DB_FROM");
        return new DB($mysqli);
    }

    /**
     * @param bool $enable - enable or disable logging
     * @return DB 
     */
    public function enable_log(bool $enable = true) : DB {
        $this->_log_enabled = $enable;
        return $this;
    }

    /**
     * @param string $replay_file_name - the name of the replay log to record to
     * @return DB 
     */
    public function enable_replay(string $replay_file_name) : DB {
        $this->_replay_log = $replay_file_name;
        $this->_replay_enabled = true;
        return $this;
    }


    /**
     * @param bool $enable - enable or disable simulation (no queries, just the query log)
     * @return DB 
     */
    public function enable_simulation(bool $enable) : DB {
        $this->_simulation = $enable;
        $this->enable_log(true);
        return $this;
    }


    /**
     * @param null|Credentials $cred create a new DB connection
     * @return DB 
     */
    public static function cred_connect(?Credentials $cred) : DB {
        if ($cred == NULL) { return DB::from(NULL); }
        $db = DB::connect($cred->host, $cred->username, $cred->password, $cred->db_name);
        $db->prefix = $cred->prefix;
        return $db;
    }

    /**
     * @return bool - true if the database is connected
     */
    public function is_connected() : bool {
        return $this->_db != NULL;
    }

    /**
     * @todo: add support for retry.  busy network environments can cause connection failures
     * 
     * @param string $host 
     * @param string $user 
     * @param string $passwd 
     * @param string $db_name 
     * @return DB 
     */
    public static function connect(string $host, string $user, string $passwd, string $db_name) : DB {
        trace("DB_CONNECT");
        $db = mysqli_init();
        mysqli_options($db, MYSQLI_OPT_CONNECT_TIMEOUT, 3);
        if(mysqli_real_connect($db, $host, $user, $passwd, $db_name)) {
            $db = DB::from($db);
            $db->host = $host;
            $db->user = $user;
            $db->database = $db_name;
            return $db;
        } else {
            debug("failed to connect to {$host} as {$user} on {$db_name}");
        }
        return DB::from(NULL);
    }

    /**
     * @param string $sql raw SQL to run.  be careful!
     * @return bool 
     */
    public function unsafe_raw(string $sql) : bool {
        return (bool)$this->_qb($sql, DB_FETCH_SUCCESS);
    }

    /**
     * run SQL $sql return result as bool. errors stored tail($this->errors)
     */
    protected function _qb(string $sql, int $return_type = DB_FETCH_SUCCESS) : int {
        assert(!empty($this->_db), "database: {$this->database} is not connected [".gettype($this->_db)."]");
        $r = false;
        $errno = 0;
        try {
            if (!$this->_simulation) {
                $r = mysqli_query($this->_db, $sql); 
            }
        }
        // silently swallow exceptions, will catch them in next line
        catch (Exception $e) { $r = false; }
        if ($r === false) {
            $errno = mysqli_errno($this->_db);
            $err = "[$sql] errno($errno) " . mysqli_error($this->_db);
            $this->errors[] = $err;
        }
        $success = (bool)$r;
        if ($success) {
            if ($this->_replay_enabled || $this->_log_enabled) {
                $e = mysqli_affected_rows($this->_db);
                if ($this->_log_enabled) {
                    $msg = "# [$sql] errno($errno) affected rows($e)";
                    $this->logs[] = $msg;
                }
                if ($this->_replay_enabled) {
                    $this->_replay[] = $sql;
                }
            }
            if ($return_type == DB_FETCH_NUM_ROWS) {
                return intval($e);
            } else if ($return_type == DB_FETCH_INSERT_ID) {
                $id = intval(mysqli_insert_id($this->_db));
                return ($id == 0) ? -1 : $id;
            }
        }
        return ($success) ? 1 : 0;
    }

    /**
     * run SQL $sql return result as bool. errors stored tail($this->errors)
     */
    protected function _qr(string $sql, $mode = MYSQLI_ASSOC) : SQL {
        $r = false;
        $errno = 0;
        try {
            if (!$this->_simulation) {
                $r = mysqli_query($this->_db, $sql); 
            }
        }
        // silently swallow exceptions, will catch them in next line
        catch (Exception $e) { $r = false; }
        if ($r == false || !$r instanceof mysqli_result) {
            $errno = mysqli_errno($this->_db);
            $err = "[$sql] errno($errno) " . mysqli_error($this->_db);
            $this->errors[] = $err;
            return SQL::from(NULL, $sql);
        }
        else {
            if ($this->_log_enabled) {
                $e = mysqli_affected_rows($this->_db);
                // $this->logs[] = $sql;
                $msg = "# [$sql] errno($errno) selected rows($e)";
                $this->logs[] = $msg;
            }
        }

       return SQL::from(mysqli_fetch_all($r, $mode), $sql);
    }

    /**
     * build sql replacing {name} with values from $data[name] = value
     * auto quotes values,  use {!name} to not quote
     * @return SQL - SQL result abstraction
     */
    //public function fetch(string $sql, array|object $data = NULL, $mode = MYSQLI_ASSOC) : SQL {
    public function fetch(string $sql, $data = NULL, $mode = MYSQLI_ASSOC) : SQL {
        assert(!empty($this->_db), "database: {$this->database} is not connected [".gettype($this->_db)."]");

        $type = (is_array($data)) ? 'array' : ((is_object($data)) ? 'object' : 'scalar');
        // replace {} with named values from $data, or $this->_x
        $new_sql = preg_replace_callback("/{\w+}/", function ($x) use ($data, $type) {
            // strip { }
            $param = str_replace(array('{', '}'), '', $x[0]);
            // access the value of $param (by object or array)
            $data_param = ($type === 'array') ? $data[$param]??"_NO_KEY_$param" : $data->$param;
            // no quoting
            if ($param[0] === "!") {
                return $data_param;
            } 
            // replace with the value of the param
            return quote($data_param);
        }, $sql);

        return $this->_qr($new_sql, $mode);
    }

    /**
     * delete entries from $table where $data matches
     * @param string $table table name
     * @param array $where key value pairs of column names and values
     * @return bool 
     */
    public function delete(string $table, array $where) : int {
        $sql = "DELETE FROM $table " . where_clause($where);
        return $this->_qb($sql);
    }

    protected function insert_stmt(string $table, array $data, int $on_duplicate = DB_DUPLICATE_IGNORE, ?array $no_update = null, ?array $if_null = null) : string {
        
        $ignore = "";
        // ignore duplicates
        if ($on_duplicate === DB_DUPLICATE_IGNORE) {
            $ignore = "IGNORE";
        }

        $sql = "INSERT $ignore INTO `$table` (`" . join("`,`", array_keys($data)) . 
        "`) VALUES (" . join(",", array_map('\ThreadFinDB\quote', array_values($data))).")";

        // update on duplicate, exclude any PKS
        if ($on_duplicate === DB_DUPLICATE_UPDATE) {
            $update_data = array_diff_key($data, $no_update);
            // UGLY AF
            $suffix = "";
            foreach($update_data as $key => $value) {
                $q_value = quote($value);
                if (isset($if_null[$key])) {
                    $suffix .= "`$key` = IF(`$key` = '' OR `$key` IS NULL, $q_value, `$key`), ";
                } else {
                    $suffix .= "`$key` = $q_value, ";
                }
            }
            if (!empty($suffix)) {
                $sql .= " ON DUPLICATE KEY UPDATE " . substr($suffix, 0, -2);
            }
        }

        return $sql;
    }

    /**
     * insert $data into $table 
     * @param string $table 
     * @param array $kvp 
     * @param int $on_duplicate - DB_DUPLICATE_IGNORE, DB_DUPLICATE_UPDATE. 
     *   IMPORTANT! for update be sure auto incrementing PK is not in $data
     * @return bool 
     */
    public function insert(string $table, array $kvp, int $on_duplicate = DB_DUPLICATE_IGNORE) : int {
        $sql = $this->insert_stmt($table, $kvp, $on_duplicate);

        return $this->_qb($sql);
    }

    /**
     * return a function that will insert key value pairs into $table.  
     * keys are column names, values are data to insert.
     * @param string $table the table name
     * @param ?array $keys list of allowed key names from the passed $data
     * @return callable(array $data) insert $data into $table 
     */
    public function insert_fn(string $table, ?array $keys = null, $ignore_duplicate = true) : callable { 
        $t = $this;
        return function(array $data) use ($table, &$t, $keys, $ignore_duplicate) : int {
            if (!empty($keys)) {
                $data = array_filter($data, BINDR('in_array', $keys), ARRAY_FILTER_USE_KEY);
            }
            $ignore = ($ignore_duplicate) ? "IGNORE" : "";
            $sql = "INSERT $ignore INTO $table (" . join(",", array_keys($data)) . 
                ") VALUES (" . join(",", array_map('\ThreadFinDB\quote', array_values($data))) . ")";

            return $t->_qb($sql);
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
    public function bulk_fn(string $table, array $columns, bool $ignore_duplicate = true) : callable { 
        $t = $this;
        $ignore = ($ignore_duplicate) ? "IGNORE" : "";
        $sql = "INSERT $ignore INTO $table (" . join(",", array_keys($columns)) . ") VALUES ";
        return function(?array $data = null) use (&$sql) : bool {
            if ($data !== null) {
                $sql .= join(",", array_map('\ThreadFinDB\quote', array_values($data))) . ")";
                return false;
            }

            return $this->_qb($sql);
        };
    }



    /**
     * update $table and set $data where $where
     */
    public function update(string $table, array $data, array $where) : int {
        // unset all where keys in data. this makes no sense when where is a PK
        //do_for_all_key($where, function ($x) use (&$data) { unset($data[$x]); });
        do_for_all_key($where, function ($x) use (&$data) { unset($data[$x]); });

        $sql = "UPDATE $table set " . glue(" = ", $data, ", ") .  where_clause($where);
        return $this->_qb($sql);
    }

    /**
     * store object data into table.  data must have public members and have the 
     * same names as the table
     * @return bool true if the SQL write is successful
     */
    public function store(string $table, Object $data, int $on_duplicate = DB_DUPLICATE_IGNORE) : int {
        assert(is_resource($this->_db), "database not connected");

        // TODO: this should be it's own object to array function with tests
        $r = new \ReflectionClass($data);
        $props = $r->getProperties(\ReflectionProperty::IS_PUBLIC);
        $no_updates = [];
        $if_null = [];
        // turn the object into an array, update PKS for update list
        $kvp = array_reduce($props, function($kvp, $item) use ($data, $on_duplicate, &$no_updates, &$if_null) {
            $name = $item->name;
            $attrs = $item->getAttributes();

            foreach ($attrs as $attr) {
                $attribute = $attr->getName();
                switch($attribute) {
                    case "ThreadFinDB\NoUpdate":
                        $no_updates[$name] = true;
                        break;
                    case "ThreadFinDB\NotNull":
                        if (!isset($data->$name) || empty($data->$name)) {
                            return $kvp;
                        }
                        break;
                    case "ThreadFinDB\IfNull":
                        $if_null[$name] = true;
                }
            }

            if (isset($data->$name)) {
                $kvp[$name] = $data->$name;
            }
            return $kvp;
        }, []);

        $sql = $this->insert_stmt($table, $kvp, $on_duplicate, $no_updates, $if_null);
        return $this->_qb($sql, DB_FETCH_INSERT_ID);
    }

    public function close() : void {
        if ($this->_db) { mysqli_close($this->_db); $this->_db = NULL; }
        if (SQL_ERROR_FILE) {
            if (count($this->errors) > 0) {
                $errors = array_filter($this->errors, function($x) { return stripos($x, "Duplicate") != false; });
                file_put_contents(SQL_ERROR_FILE, print_r($errors, true), FILE_APPEND);
            }
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
    public function map(callable $fn) : array {
        if (is_array($this->_x) && !empty($this->_x)) {
            return array_map($fn, $this->_x);
        } else {
            $this->_errors[] = "wont call " . func_name($fn) . " on data : " . var_export($this->_data, true);
        }
        return [];
    }

    /**
     * reduce $fn($carry, $item) on each row in entire result (works on raw result, no set necessary)
     * $fn may return any type, but should be a string in 99% cases
     * @return mixed return type of $fn, false if rows (_x) is empty
     */
    public function reduce(callable $fn, $initial = "") {
        if (is_array($this->_x) && !empty($this->_x)) {
            return array_reduce($this->_x, $fn, $initial);
        } else {
            $this->_errors[] = "wont call " . func_name($fn) . " on data : " . var_export($this->_data, true);
        }
        return false;
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


/**
 * database backup checkpoint offset
 * @package ThreadFinDB
 */
class Offset {
    public $table;
    public $limit_sz = 0;
    public $offset = 0;
    const TABLE_COMPLETE = -1;

    public function __construct(string $table, int $limit_sz = 300) {
        $this->limit_sz = $limit_sz;
        $this->table = $table;
    }

    /**
     * update a table saved offset
     * @param string $table 
     * @param int $offset 
     * @param int $limit 
     * @return void 
     */
    public function set_check_point(int $offset) {
        $this->offset = $offset;
    }

    /**
     * @param string $table 
     * @return bool true if the table is completely dumped, false if not or incomplete
     */
    public function is_table_complete() : bool {
        return $this->offset == Offset::TABLE_COMPLETE;
    }
}

/**
 * function suitable for database dumping to gz compressed output file
 * this is equal to calling stream_output_fn($data, $stream, "gzwrite")
 * @param string $data 
 * @param mixed $stream 
 * @return int -1 on error, else total byte length written to stream across all writes
 */
function gz_output_fn(?string $data, $stream) : int {
    return stream_output_fn($data, $stream, "gzwrite");
}

/**
 * function suitable for database dumping to gz compressed output file
 * @param string $data 
 * @param mixed $stream 
 * @return int -1 on error, else total byte length written to stream across all writes
 */
function stream_output_fn(?string $data, $stream, $fn = "fwrite") : int {
    assert(is_resource($stream), "stream must be a resource");
    static $total_bytes = 0;

    if ($data && strlen($data) > 0) {
        $bytes = $fn($stream, $data);
        if (!$bytes) {
            return -1;
        }
        $total_bytes += $bytes;
    }
    return $total_bytes;
}


/**
 * dump a single SQL table 100 rows at a time
 * @param DB $db 
 * @param string $db_dump_file 
 * @param mixed $row 
 * @return int number of uncompressed bytes written
 */
function dump_table(DB $db, callable $write_fn, array $row) : ?Offset {
    $idx = 0;
    $limit = 300;
    $db_name = $db->database;
    $table = $row["Tables_in_$db_name"];
    $offset = new Offset($table);

    // find number of rows
    $num_rows = intval($db->fetch("SELECT count(*) as count FROM $table")->col("count")());
    // the create statement
    $create = $db->fetch("SHOW CREATE TABLE $table");
    // table header line
    $write_fn("# Export of $table\n# $num_rows rows in $table\n");
    // drop table if it exists
    $write_fn("DROP TABLE IF EXISTS `$table`;\n");
    // add create statement
    $write_fn($create->col("Create Table")() . ";\n\n");

    // insert $limit rows at a time
    while($idx < $num_rows) {
        $limit = min($limit, $num_rows - $idx);
        $rows = $db->fetch("SELECT * FROM $table LIMIT $limit OFFSET $idx", NULL, MYSQLI_NUM);
        // create the output string
        $result = $rows->reduce(function(string $carry, array $row) {
            return $carry . "(" . implode(",", array_map('\ThreadFinDB\quote', $row)) . "),\n";
        }, "INSERT IGNORE INTO $table VALUES");
        // write to the output stream
        $bytes_written = $write_fn(substr($result, 0, -2) . ";\n\n");
        if ($bytes_written < 0 || $bytes_written > 1048576*20) {
            return $offset;
        }

        // increment the offset by the limit
        $idx += $limit;
        $offset->set_check_point($idx);

        // let the database rest a second
        usleep(100000);
    }
    $offset->set_check_point(Offset::TABLE_COMPLETE);

    return $offset;
}

/**
 * dump all database tables to the function $write_fn
 * @param Credentials $cred Access credentials to the database
 * @param string $db_name the name of the database (eg, wordpress)
 * @param callable $write_fn a function that takes a string and 
 *      writes it to the output stream (fwrite, gzwrite, etc)
 * @return array of Offset objects. one for each table in $db_name
 */
function dump_database(Credentials $cred, callable $write_fn, int $max_bytes = 1024*1024*50) : array {
    $db_name = $cred->db_name;
    $header = "# Database export of ($db_name) began at UTC: " 
            . date(DATE_RFC3339) . "\n# UTC tv: " . utc_time() . "\n\n";
    $init_sql = "SET NAMES 'utf8'\n";

    $db = DB::cred_connect($cred);
    $db->unsafe_raw($init_sql);
    $tables = $db->fetch("SHOW TABLES");
    $write_fn($header . $init_sql);

    $t = BINDL('\ThreadFinDB\dump_table', $db, $write_fn);
    $data = $tables->map($t);
    //$data = $tables->data();
    return (!$data || empty($data) || !is_array($data)) ? [] : $data;
}
