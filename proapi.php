<?php
namespace BitFire;


function lock_site(\BitFire\Request $request) {
    $root = $_SERVER['DOCUMENT_ROOT'];
    system("find $root -type d | xargs chmod 555");
    system("find $root -type f | xargs chmod 444");
    echo "{result:'locked'}\n";
}

function unlock_site(\BitFire\Request $request) {
    $root = $_SERVER['DOCUMENT_ROOT'];
    system("find $root -type d | xargs chmod 755");
    system("find $root -type f | xargs chmod 644");
    echo "{result:'unlocked'}\n";
}

function find_malware(\BitFire\Request $request) {
    $cmd = "find {$_SERVER['DOCUMENT_ROOT']} -type f -name '*.php' | xargs grep -l 'chr(60).chr(115).chr(99)'";// | xargs ls -l";
    //$cmd = "find {$_SERVER['DOCUMENT_ROOT']} -type f -name '*.php' | xargs grep -l '2080825FKHOBK' | xargs ls -l";
    echo "[$cmd]\n";
    exec($cmd, $files, $num);
    if (count($files) < 1) { echo "no malware found\n"; return; }
    if (!isset($_GET['force'])) { print_r($files); return; }

    foreach ($files as $item) {
        //echo " - [$item]\n";
        $foo = preg_split("/\s+/", $item);
        if (count($foo) < 8) { continue; }
        $size = $foo[4];
        $name = $foo[8];

        if (!\TF\ends_with($name, 'php')) {
            continue;
        }
        echo " # [$name] ($size)\n";

        
        if ($size == 2026) {
            echo "remove [$name]\n";
            unlink($name);
        } else if ($size > 0 && strlen($name) > 3) {
            echo "repair: {$name}\n";
            $content = file_get_contents($name);
            if (stristr($content, "silence is golden") !== false) {
                file_put_contents($name, "<?php\n// Silence is golden.\n", LOCK_EX);
            } else {
                $orig_size = strlen($content);
                //$newcontent = preg_replace('/echo[\n\s]*chr(60)\s*\.\s*chr(115)\s*\.\s*chr(99)\s*\.\s*chr.*;/m', '', $content);
                $newcontent = preg_replace('/var\s*_0x1c9a.*smalller\(\);/m', '', $content);
                    // '/echo[\n\s]*chr(60)\s*\.\s*chr(115)\s*\.\s*chr(99)\s*\.\s*chr.*;/m', '', $content);
                $new_size = strlen($newcontent);
                if ($new_size > 1 && $new_size < $orig_size) {
                    file_put_contents($name, $newcontent, LOCK_EX);
                    echo "remove <script> injection: [$name] \n";
                } else {
                    echo "error fixing script [$orig_size] ($new_size)\n";
                    //echo "$newcontent\n\n";
                }
            }
        }
    }
}

