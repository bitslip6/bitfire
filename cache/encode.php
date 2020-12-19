<?php


function foo_test_pack() : string {
    $f = bin2hex('convert_uudecode');
    echo "hex\n";
    $f2 = unpack('n*', 'uuencode');
    echo "\n";
    print_r($f2);
    $fn = pack('H*', $f);
    echo "F3: [$fn]\n";
    //print_r($f3);
    
    $packed = do_encode($data);
    echo "packed [$packed]\n";
    $m0 = microtime(true);
    //echo "FN! [$fn] packed [$fn_packed]\n";
    $fn_packed = do_decode($packed);
    $fn = pack('H*', $fn_packed);
    for ($i=0;$i<60;$i++) {
        //$unpacked = do_decode($packed);
        $unpacked = $fn($encoded);
    }
    $m1 = microtime(true);
    echo "unpacked [$unpacked] ".($m1-$m0) . "\n";
    return json_encode($packed);
}

function do_encode() : string {
    
    $f = bin2hex('convert_uudecode');
    mt_srand(time());
    $num = mt_rand(0, 120);
    $fname = sprintf("%02x", $num);
    for ($i=0;$i<strlen($f);$i+=2) {
        $str = substr($f, $i, 2);
        $r = hexdec($str);
        $r += $num;
        $fname .= dechex($r);
    }
    return "$fname";
}

function do_decode($s) : string {
    $num = hexdec(substr($s, 0, 2));
    $r = "";
    for ($i=2;$i<strlen($s);$i+=2) {
        $r .= dechex(hexdec(substr($s, $i, 2))-$num);
    }
    return $r;
}


$lines = file($argv[1]);
/*
function recache2($z, array $lines) {
    $a = array();
    $builder = "";
    for ($i=1,$m=count($lines);$i<$m;$i++) {
        if (strlen($lines[$i]) > 2) {
            $builder .= $z($lines[$i]);
        } else { 
            $a[] = trim($builder);
            $builder = "";
        }
    }
    return $a;
}

include_once "../util.php";

$m0 = microtime(true);
$z = BitSlip\recache($lines);
$m1 = microtime(true);
echo "time: " . ($m1 - $m0) . "\n";
print_r($z);
*/
echo do_encode() . "\n"; for ($i=0,$m=count($lines);$i<$m;$i++) {
    $line = $lines[$i];
    $r = ($i%2==1) ? dechex(trim($line))."\n" : convert_uuencode($line);
    //$r = ($i%2!=1) ? $line : convert_uuencode($line);
    if (strlen($r)>3) { echo $r; }
}
