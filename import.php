<?php
die("import");

class bitfirehash {
    public $path;
    public $crc_path;
    public $crc_content;
    public $md5;
    public $type;
    public $svn_ver;
}

function hash_file_simple(string $filename) : bitfirehash {
    $c = file_get_contents($filename);
    $i = pathinfo($filename);
    $hash = new bitfirehash();
    $hash->path = $filename;
    $hash->crc_path = crc32($filename);
    $hash->md5 = md5($c);
    $hash->crc_content = crc32($c);
    $hash->type = $i['extension'];
    $hash->svn_ver = 1;

    return $hash;
}

function hash_to_insert(bitfirehash $hash) : string {
    return "INSERT INTO hash (path, type, svn_ver, md5, crc_path, crc_contents) VALUES ('{$hash->path}', '{$hash->type}', {$hash->svn_ver}, '{$hash->crc_path}', '{$hash->crc_content}'";
}

$handle = mysqli_init();
mysqli_options($handle, MYSQLI_OPT_CONNECT_TIMEOUT, 1);
$success = mysqli_real_connect($handle, 'localhost', 'root', 'password', 'bitfire');

$hash = hash_file_simple("import.php");
$sql = hash_to_insert($hash);
echo "[$sql]\n";

mysqli_query($handle, $sql);
