<?php declare(strict_types=1);

namespace DB;

class Creds {
    public $username;
    public $password;
    public $prefix;
    public $db_name;

    public function __construct(string $user, string $pass, string $host, string $db_name, string $pre = "") {
        $this->username = $user;
        $this->password = $pass;
        $this->prefix = $pre;
        $this->host = $host;
        $this->db_name = $db_name;
    }
}

function glue(string $join, array $data, string $append_str = "") : string {
    $result = "";
    foreach ($data as $key => $value) {
        if ($result != '') { $result .= $append_str; }
        if ($key[0] === '!') { $key = substr($key, 1); $result .= "`{$key}` $join $value"; }
        else { $result .= "`{$key}`" . $join . quote($value); }
    }
    return $result;   
}

function quote($input) : ?string {
    if (is_numeric($input)) { return strval($input); }
    if (is_string($input)) { return "'".addslashes($input)."'"; }
    return $input;
}

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

    protected function __construct(?\mysqli $db) { $this->_db = $db; $this->_errors = array(); }

    public static function from(?\mysqli $mysqli) : DB { 
        return new DB($mysqli);
    }

    public static function cred_connect(?Creds $creds) : DB {
        if ($creds == NULL) { return DB::from(NULL); }
        return DB::connect($creds->host, $creds->username, $creds->password, $creds->db_name);
    }

    public static function connect(string $host, string $user, string $passwd, string $db_name) : DB {
        $db = mysqli_init();
        mysqli_options($db, MYSQLI_OPT_CONNECT_TIMEOUT, 3);
        if(mysqli_real_connect($db, $host, $user, $passwd, $db_name)) {
            return DB::from($db);
        }
        return DB::from(NULL);
    }


    /**
     * build sql replacing {name} with values from $data[name] = value
     */
    public function fetch(string $sql, ?array $data = NULL) : SQL {
        if ($this->_db == NULL) { return SQL::from(NULL); }

        // replace {} with named values from $data, or $this->_x
        $new_sql = preg_replace_callback("/{\w+}/", function ($x) use ($data) {
            $param = str_replace(array('{', '}'), '', $x[0]);
            $result = quote($data[$param]);
            return $result;
        }, $sql);

        //echo "SQL [$new_sql]\n";
        $result = mysqli_query($this->_db, $new_sql);
        if ($result !== false) {
            return SQL::from(mysqli_fetch_all($result, MYSQLI_ASSOC), $sql);
        }
        return SQL::from(NULL, $sql);
    }

    public function insert(string $table, array $kvp) {
        $sql = "INSERT INTO $table (" . join(",", array_keys($kvp)) . ") VALUES (" . join(",", array_map('\DB\quote', array_values($kvp))) . ")";
        //echo "SQL [$sql]\n";
        $r = mysqli_query($this->_db, $sql); 
        if (!$r) $this->_errors[] = "[$sql] " . mysqli_error($this->_db);
        return (bool) $r;
    }

    public function insert_fn(string $table) : callable { 
        $db = $this->_db;
        return function(array $data) use ($table, $db) {
            $sql = "INSERT INTO $table (" . join(",", array_keys($data)) . ") VALUES (" . join(",", array_map('\DB\quote', array_values($data))) . ")";
            //echo "SQL [$sql]\n";
            $r = mysqli_query($db, $sql); 
            if (!$r) $this->_errors[] = "[$sql] " . mysqli_error($this->_db);
            return (bool) $r;
        };
    }

    public function update(string $table, array $data, array $where) {
        $sql = "UPDATE $table set " . glue(" = ", $data, ", ") .  where_clause($where);
        //echo "SQL [$sql]\n";
        $r = mysqli_query($this->_db, $sql); 
        if (!$r) $this->_errors[] = "[$sql] " . mysqli_error($this->_db);
        return (bool) $r;
    }

    /**
     * store data into table.  data must have public members and have the same names as the table
     */
    public function store(string $table, Object $data) : bool {
        if (!$this->_db) { return false; }
        $r = new \ReflectionClass($data);
        $props = $r->getProperties(\ReflectionProperty::IS_PUBLIC);
        $name_list = array_reduce($props, function($carry, $item) { return $carry . ", " . $item->getName(); });
        $value_list = array_reduce($props, function($carry, $item) use ($data) { $name = $item->getName(); return $carry . ", " . $data->$name; });
        $sql = "INSERT INTO $table (" . trim($name_list, ", ") . ") VALUES (" . trim($value_list, ", ") . ")";
        $r = mysqli_query($this->_db, $sql); 
        if (!$r) $this->_errors[] = mysqli_error($this->_db);
        return (bool) $r;
    }

    public function close() : void {
        if ($this->_db) { mysqli_close($this->_db); }
    }
}

class SQL {
    protected $_x;
    protected $_data = NULL;
    protected $_idx = 0;
    protected $_errors;
    protected $_sql;
    protected $_len;

    public static function from(?array $x, string $sql_stmt="") : SQL { $sql = new SQL(); $sql->_x = $x; $sql->_len < (is_array($x)) ? count($x) : 0; $sql->_sql = $sql_stmt; return $sql; }
    
    /**
     * set internal dataset to value of $name at current row index 
     */
    public function setcol(string $name) : SQL {
        if (isset($this->_x[$this->_idx])) {
            $this->_data = $this->_x[$this->_idx][$name]??NULL;
        } else { $this->_data = NULL; }

        return $this;
    }

    /**
     * set internal dataset to row  at current row index 
     */
    public function setrow(?int $idx = NULL) : SQL {
        $idx = ($idx !== NULL) ? $idx : $this->_idx;
        if (isset($this->_x[$idx])) {
            $this->_data = $this->_x[$idx];
        }
        return $this;
    }

    public function col(string $name) : \TF\MaybeSTR {
        if (isset($this->_x[$this->_idx])) {
            return \TF\MaybeStr::of($this->_x[$this->_idx][$name]??NULL);
        } 
        return \TF\MaybeStr::of(NULL);
    }

    /**
     * return true if column name has a row with at least one value of $value 
     */
    public function in_set(string $name, string $value) : bool {
        return array_reduce($this->_x, function ($carry, $item) use ($name, $value) {
            return $carry || $item[$name] == $value;
        }, false);
    }

    public function row(?int $idx = NULL) : \TF\MaybeA {
        $idx = ($idx !== NULL) ? $idx : $this->_idx;
        if (isset($this->_x[$idx])) {
            return \TF\MaybeA::of($this->_x[$idx]);
        }
        return \TF\MaybeA::of(NULL);
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
     * call $fn on current $this->_data (see setrow, setcol)
     */
    public function ondata(callable $fn, bool $spread = false) : SQL {
        if (!empty($this->_data)) {
            $this->_data = 
                ($spread) ?
                $fn(...$this->_data) :
                $fn($this->_data);
        } else {
            $this->_errors[] = \TF\func_name($fn) . " : " . var_export($this->_data, true);
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
            $this->_errors[] = \TF\func_name($fn) . " : " . var_export($this->_x, true);
        }
        return $this;
    }


    // run an effect on current data
    public function effect(callable $fn) : SQL { if (!empty($this->_data)) { $fn($this->_data); } return $this; }

    // set data to NULL if $fn returns false
    public function if(callable $fn) : SQL { if ($fn($this->_data) === false) { $this->_data = NULL; } return $this; }
    // set data to NULL if $fn returns true
    public function ifnot(callable $fn) : SQL { if ($fn($this->_data) !== false) { $this->_data = NULL; } return $this; }
    // return true if we have an empty result set
    public function empty() : bool { return empty($this->_x); } 
    public function count() : int { return is_array($this->_x) ? count($this->_x) : 0; } 
    // get all errors
    public function errors() : array { return $this->_errors; }
    // size of result set
    public function size() : int { return is_array($this->_x) ? count($this->_x) : ((empty($this->_x)) ? 0 : 1); }
    public function data() : ?array { return $this->_x; }
    public function __toString() : string { return (string)$this->_data; }
}


// class to support string concat for bulk inserts
class StringBuffer {
    private $_root = '';
    private $_buffer = '';
    private $_ctr = 0;

    public function __construct(string $root) {
        $this->_root = $root;
    }

    public function append(string $buffer) : int {
        $this->_buffer .= $buffer;
        return ++$this->_ctr;
    }

    public function get() : string {
        return $this->_root . $this->_buffer;
    }

    public function len() : int {
        return $this->_ctr;
    }

    public function if_len(int $min_len, callable $fn) {
        if ($this->_ctr >= $min_len) { $fn ($this->get()); $this->_ctr = 0; $this->_buffer = ''; }
    }
}


