<?php
/**
 * Copy this file to your webserver and open the page in your web browser.
 * This script will attempt to download and install the latest version of
 * BitFire and configure your server.
 *
 * BitFire can be run on any webserver that processes PHP >7.0
 *
 * NOTE: If using WordPress, please install via the WordPress plugin installer
 */


const MISS_GZ=2;const WITH_ZLIB=4;const FAILED=6;const OPEN_FAIL=8;const MKDIR_FAIL=10;const WRITE_FAIL=12;const CHMOD_FAIL=14;const READ_FAIL=16;const CHK_FAIL=18;const HTTP_FAIL=20;const PHP_VER=22;const SHMOP=24;const APCU=26;const SHM=28;const SUCCESS=30;const ROOT_WRITE=32;const COOKIE=34;const NO_CACHE=36;const INSTALL=38;const ADDED=40;const UNIN=42;const ADDEDINI=44;const ADDEDINDEX=46;
const UNIN_FAIL=80;const COOKIE_FAIL=82;const ADDED_FAIL=84;const REMOVE_SUCCESS=90;const REMOVE_FAIL=91; const GZBLOCKSZ=512;
const FILE_RW2=0664;
class Err { private static $_e = array(); public $title; public $msg; public static function new($t, ...$args) { 
    $e = new Err(); $e->title = lang($t); $e->msg = lang($t+1); error($e, ...$args); self::$_e[] = $e;
} public static function get(){return self::$_e; } }

$GLOBALS['lang'] = array("en" => 
    array(
MISS_GZ => "missing gzopen",
MISS_GZ+1 => "The PHP environment does not support gzopen.  Unable to extract BitFire release.  Please recompile with --with-zlib",
FAILED => "BitFire Install Failed",
FAILED+1 => "A problem was found with your PHP environment, please check the error and visit the support center.",
INSTALL => "BitFire Installed",
INSTALL+1 => "BitFire is already installed",
OPEN_FAIL => "Unable to open file", 
OPEN_FAIL+1 => "Error ocurred opening file [%s]", 
MKDIR_FAIL => "Unable to mkdir", 
MKDIR_FAIL+1 => "Unable to create the directory [%s]", 
WRITE_FAIL => "Unable to write file", 
WRITE_FAIL+1 => "Error ocurred writing to file [%s]", 
CHMOD_FAIL => "Permission set error", 
CHMOD_FAIL+1 => "Unable to set the permissions on file [%s]",
READ_FAIL => "Unable to read archive", 
READ_FAIL+1 => "Unable to read archive, read %d of 512 bytes", 
CHK_FAIL => "Checksum fail",
CHK_FAIL+1 => "Archive Checksum error.  expected %d, but found %d.",
HTTP_FAIL => "No HTTP Support",
HTTP_FAIL+1 => "BitFire requires allow_url_fopen or cURL support",
PHP_VER => "PHP 7.0+",
PHP_VER+1 => "BitFire requires PHP 7.0 or greater",
COOKIE => "\$_COOKIE",
COOKIE+1 => "cookie support found.",
SHMOP => "SHMOP",
SHMOP+1 => "SHMOP support found.",
APCU => "APCU",
APCU+1 => "APCU support found.  Server cache available.",
SHM => "SHM",
SHM+1 => "SHM support found.  Server cache available.",
SUCCESS => "SUCCESS",
SUCCESS+1 => "BitFire installed successfully.  Please visit <a style='color:#506690' target='_blank' id='link' data-href='/bitfire/startup.php' href='/bitfire/startup.php' title='Launch BitFire Dashboard'>BitFire Dashboard</a>",
UNIN => "SUCCESS",
UNIN+1 => "BitFire un-installed successfully.  Bitfire startup removed from .htaccess, user.ini and index.php. /bitfire directory removed.",
ROOT_WRITE => "Permission error",
ROOT_WRITE+1 => "%s must be writeable to use this install script",
COOKIE_FAIL => "no cookie support",
COOKIE_FAIL+1 => "Cookie support required for browser verification",
NO_CACHE => "no cache support",
NO_CACHE+1 => "Server cache recommended for fastest operation",
ADDED => "Startup",
ADDED+1 => "BitFire has been added to .htaccess",
ADDEDINI => "Startup",
ADDEDINI+1 => "BitFire has been added to user.ini",
ADDEDINDEX => "Startup",
ADDEDINDEX+1 => "BitFire has been added to the top of /index.php",
ADDED_FAIL => "Startup",
ADDED_FAIL+1 => "Unable to add startup to .htaccess, .user.ini or index.php",
UNIN_FAIL => "ERROR",
UNIN_FAIL+1 => "BitFire un-installed successfully.  Bitfire startup removed from .htaccess, user.ini and index.php.  You are no longer protected",
REMOVE_SUCCESS => "File Restored",
REMOVE_SUCCESS+1 => "BitFire startup has been removed from %s",
REMOVE_FAIL => "Error Restoring File",
REMOVE_FAIL+1 => "BitFire startup unable to removed from %s"
));

$GLOBALS['page2'] = <<<EOT
<!DOCTYPE html> <html lang="en"> <head>
    <!-- Simple HttpErrorPages | MIT License | https://github.com/HttpErrorPages -->
    <meta charset="utf-8" /><meta http-equiv="X-UA-Compatible" content="IE=edge" /><meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="icon" type="image/png" href="https://bitfire.co/assets/favicon/favicon.ico">
    <title>%s</title>
    <style type="text/css">/*! normalize.css v5.0.0 | MIT License | github.com/necolas/normalize.css */a[disabled]{pointer-events:none;}span.desc{text-shadow:none;color:#555;}span.title{color:#FFF;display:inline-block;text-align:left;width:250px;white-space:nowrap;text-overflow:ellipsis;}html{font-family:sans-serif;line-height:1.15;-ms-text-size-adjust:100%%;-webkit-text-size-adjust:100%%}body{margin:0}article,aside,footer,header,nav,section{display:block}h1{font-size:2em;margin:.67em 0}figcaption,figure,main{display:block}figure{margin:1em 40px}hr{box-sizing:content-box;height:0;overflow:visible}pre{font-family:monospace,monospace;font-size:1em}a{background-color:transparent;-webkit-text-decoration-skip:objects}a:active,a:hover{outline-width:0}abbr[title]{border-bottom:none;text-decoration:underline;text-decoration:underline;color:#335EEA}b,strong{font-weight:inherit}b,strong{font-weight:bolder}code,kbd,samp{font-family:monospace,monospace;font-size:1em}dfn{font-style:italic}mark{background-color:#ff0;color:#000}small{font-size:80%%}sub,sup{font-size:75%%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}audio,video{display:inline-block}audio:not([controls]){display:none;height:0}img{border-style:none}svg:not(:root){overflow:hidden}button,input,optgroup,select,textarea{font-family:sans-serif;font-size:100%%;line-height:1.15;margin:0}button,input{overflow:visible}button,select{text-transform:none}[type=reset],[type=submit],button,html [type=button]{-webkit-appearance:button}[type=button]::-moz-focus-inner,[type=reset]::-moz-focus-inner,[type=submit]::-moz-focus-inner,button::-moz-focus-inner{border-style:none;padding:0}[type=button]:-moz-focusring,[type=reset]:-moz-focusring,[type=submit]:-moz-focusring,button:-moz-focusring{outline:1px dotted ButtonText}fieldset{border:1px solid silver;margin:0 2px;padding:.35em .625em .75em}legend{box-sizing:border-box;color:inherit;display:table;max-width:100%%;padding:0;white-space:normal}progress{display:inline-block;vertical-align:baseline}textarea{overflow:auto}[type=checkbox],[type=radio]{box-sizing:border-box;padding:0}[type=number]::-webkit-inner-spin-button,[type=number]::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:textfield;outline-offset:-2px}[type=search]::-webkit-search-cancel-button,[type=search]::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{-webkit-appearance:button;font:inherit}details,menu{display:block}summary{display:list-item}canvas{display:inline-block}template{display:none}[hidden]{display:none}/*! Simple HttpErrorPages | MIT X11 License | https://github.com/AndiDittrich/HttpErrorPages */body,html{width:100%%;height:100%%;}body.error{background-color:#21232a;}body.success{background-color:rgba(66,186,150,0.75);}body{color:#fff;text-align:center;text-shadow:0 2px 4px rgba(0,0,0,.5);padding:0;min-height:100%%;-webkit-box-shadow:inset 0 0 100px rgba(0,0,0,.8);box-shadow:inset 0 0 100px rgba(0,0,0,.8);display:table;font-family:"Open Sans",Arial,sans-serif}h1{font-family:inherit;font-weight:500;line-height:1.1;color:inherit;font-size:36px}h1 small{font-size:68%%;font-weight:400;line-height:1;color:#777}a{text-decoration:none;color:#fff;font-size:inherit;border-bottom:solid 1px #707070}.lead{color:#EEE;font-size:21px;line-height:1.4;text-shadow:none;}.cover{display:table-cell;vertical-align:middle;padding:0 20px}footer{position:fxed;width:100%%;height:40px;left:0;bottom:0;color:#a0a0a0;font-size:14px}li{list-style:none;display:flex;flex-direction:row;align-items:center;}li span{padding-left:20px;}</style>
    <script> function copy_text(elm) { const text = elm.innerText; alert(text+" copied to clipboard"); const textarea = document.createElement('textarea'); textarea.value = text; textarea.setAttribute('readonly', ''); textarea.style.position = 'absolute'; textarea.style.left = '-9999px'; document.body.appendChild(textarea); textarea.select(); try { var successful = document.execCommand('copy'); this.copied = true; } catch(err) { this.copied = false; } textarea.remove(); }
    </script>
</head>
<body class="%s"> <div class="cover"><h1>%s</h1><p class="lead">%s</p><ul style="width:600px;text-align:center;margin:20px auto;">%s</ul><div class="btn"><a style="position:relative;top:30px;" href="https://bitfire.co/support-center" title="">BitFire Support</a></div><br><div class="btn"><a style="position:relative;top:30px;color:#777;" 
EOT;
$GLOBALS['page2'] .= 'href="'.$_SERVER['PHP_SELF'].'?uninstall=1" title="">Uninstall Bitfire</a></div></div>  </body> </html>';

$GLOBALS['item'] = <<<EOT
<li><img src="https://bitfire.co/assets/favicon/%s.svg" width="24px" alt="%s" /> <span class='title'> %s </span>&nbsp;- <span class='desc'>%s</span></li>
EOT;
$GLOBALS['list'] = '';
$GLOBALS['txt'] = false;


register_shutdown_function(function () {
    $e = error_get_last();
    if ($e) {
        echo "<br><br>\n\n<h3>last error</h3><pre>\n";
        print_r($e);
        echo "</pre>\n";
    }
});


// report any errors so we can fix them
function onerr($errno, $errstr, $errfile, $errline, $context = NULL) : bool {
    if ($errline == 274) { $GLOBALS['txt'] = true; return false; }
    $data = array("errno" => $errno, "errstr" => $errstr, "errfile" => $errfile, "errline" => $errline);
    Err::new(FAILED, "$errfile:$errline [$errno] $errstr"); // fin(FAILED); 
    $data['info'] = $_SERVER;
    http("POST", "https://bitfire.co/err.php?line={$errline}&errno={$errno}&msg=".urlencode($errstr), base64_encode(json_encode($data)));
    return false;
}
function removeDirectory($path) {
    $files = array_merge(glob($path . '/*'), glob($path."/.*"));
    foreach ($files as $file) { 
        $n = basename($file);
        if ($n == "." || $n == "..") { continue; }
        is_dir($file) ? removeDirectory($file) : @unlink($file); }
    @rmdir($path);
    return;
}

function file_recurse(string $dirname, callable $fn, string $regex_filter = NULL, array $result = array(), $max_results = 20000) : array {
    $maxfiles = 20000;
    $result_count = count($result);

    if ($dh = \opendir($dirname)) {
        while(($file = \readdir($dh)) !== false && $maxfiles-- > 0 && $result_count < $max_results) {
            $path = $dirname . '/' . $file;
            if (!$file || $file === '.' || $file === '..') {
                continue;
            }
            if (($regex_filter != NULL && preg_match($regex_filter, $path)) || $regex_filter == NULL) {
                $x = $fn($path);
                if (!empty($x)) { $result[] = $x; $result_count++; }
            }
            if (is_dir($path) && !is_link($path)) {
                if (!preg_match("#\/uploads\/?$#", $path)) {
                    $result = file_recurse($path, $fn, $regex_filter, $result, $max_results);
                    $result_count = count($result);
                }
            }
        }
        \closedir($dh);
    }

    return $result;
}

function file_replace(string $filename, string $find, string $replace, int $mode = 0) : void {
    // preg swap src,dst
    $data = file_get_contents($filename);
    if ($find[0] == "/") {
        $fixed = preg_replace($find, $replace, $data);
    } else {
        $fixed = str_replace($find, $replace, $data);
    }
    if (strlen($fixed) > 5000) {
        file_put_contents($filename, $fixed);
    } else {
        Err::new(FAILED, "unable to file replace $filename [$find] [$replace]");
    }
}




// setup function
function init() {
    error_clear_last();
    set_error_handler("onerr");
    $root = $_SERVER['DOCUMENT_ROOT'];

    if (PHP_VERSION_ID < 70000) { Err::new(PHP_VER); }
    if (!function_exists('gzopen')) { Err::new(MISS_GZ); }
    if (!ini_get("allow_url_fopen") && !function_exists('curl_init')) { Err::new(HTTP_FAIL); }
    if (isset($_GET['uninstall']) || isset($_GET['?uninstall'])) { uninstall(); }
    if (defined("\BitFire\WAF_ROOT")) { Err::new(INSTALL); }
    if (!is_writeable($root)) { Err::new(ROOT_WRITE, $root); }
    if (!empty(Err::get())) { die(fin(FAILED)); }

    if (file_exists("bitfire")) { 
        debug("bitfire", "remove directory");
        removeDirectory("bitfire");
    }
}

// get translation
function lang($msg, $uc = false) {
    $l = "en";
    if (isset($GLOBALS['lang'][$l]) && (isset($GLOBALS['lang'][$l][$msg]))) {
        $m = $GLOBALS['lang'][$l][$msg];
        return ($uc) ? ucwords($m) : $m;
    }
    return $msg;
}

// error functions
function format_error() {
    $e = error_get_last();
    error_clear_last();
    return (empty($e)) ? "" : "errno: {$e['type']}  line: {$e['line']} , {$e['message']}";
}
function error(Err $e, ...$args) {
    $err = format_error();
    if (!empty($err)) {
        $GLOBALS['list'] .= sprintf($GLOBALS['item'], "gear", "gear", 'php error', $err);
    }

    if (!empty($args) && strpos($e->msg, '%') !== false) {
        $GLOBALS['list'] .= sprintf($GLOBALS['item'], "error", "error", $e->title, sprintf($e->msg, ...$args));
    } else {
        $GLOBALS['list'] .= sprintf($GLOBALS['item'], "error", "error", $e->title, $e->msg);
    }
    return false;
}
function debug($msg, ...$args) {
    $GLOBALS['list'] .= (is_int($msg)) ? 
        sprintf($GLOBALS['item'], "gear", "gear", lang($msg), ucfirst(lang($msg+1)), ...$args) :
        sprintf($GLOBALS['item'], "gear", "gear", ucwords($msg), ucfirst($args[0]??''));

}

// test passes
function okay($msg, ...$args) {
    $GLOBALS['list'] .= sprintf($GLOBALS['item'], "okay", "okay", lang($msg, ...$args));
}

// build the final output
function fin($title, $success = "error", ...$args) {
    $t = lang($title, true);
    $m = (empty($args)) ? lang($title+1) : sprintf(lang($title+1), ...$args);
    $m .= ($success == "success") ? "<br><br><img width='128' src='https://bitfire.co/assets/check-mark.png'><br>" : "";
    /*
    if ($GLOBALS['WAIT']??false) {
        $m .= '<div>Please wait 5:00 minutes for PHP ini cache to expire before loading...</div><h1 style="margin: 10px auto 10px auto" id="timer" data-sec="'.$GLOBALS['WAIT'].'">00:00</h1><script type="text/javascript">let x=document.getElementById("link");x.title="Please wait for countdown timer before launching Dashboard.";x.href="";x.setAttribute("disabled","disabled");function cl(x){console.log(x);}function cntdwn() {let e=document.getElementById("timer");let ds=parseInt(e.getAttribute("data-sec"));e.setAttribute("data-sec", ds-1);let min=Math.floor(ds/60);let sec=ds-(min*60);if(ds>=0){e.innerText = min + ":" + String(sec).padStart(2,"0");window.setTimeout(cntdwn, 1000);}else{let x=document.getElementById("link");x.title="Launch BitFire Dashboard";x.href=x.getAttribute("data-href");x.removeAttribute("disabled");}}cntdwn();</script>';
    }
    */
    printf($GLOBALS['page2'], $t, $success, $t, $m, $GLOBALS['list']);
}

// PHP GZIPPED TAR IMPL
class TarHeader {
    public $filename;
    public $size;
    public $perm;
    public $checksum;
    public $type;
}

// uncompress
function tar_read_file($fh, TarHeader $header) {
    $result = "";
    $ctr = 0;
    while ($header->size > 0 && $ctr++ < 20000) { // max 10Mb
        $tmp = gzread($fh, GZBLOCKSZ);
        $len = strlen($tmp);
        if ($len != GZBLOCKSZ) { Err::new(READ_FAIL, "1:$len"); die(fin(FAILED)); }
        $result .= substr($tmp, 0, min($header->size, GZBLOCKSZ));
        $header->size -= strlen($tmp);
    }
    return $result;
}

// extract tar archive into destination directory
function tar_extract(string $file, string $destination = "") {
    $input = gzopen($file, 'rb');
    if ($input == false) { Err::new(OPEN_FAIL, $file); die(fin(FAILED)); }

    $num_files = 0;
    while(($header = tar_read_header($input, $destination))) {
        if ($header->type == 5) {
            if (!file_exists($header->filename)) {
                if (!mkdir($header->filename, 0775, true)) {
                    Err::new(MKDIR_FAIL, $header->filename); die(fin(FAILED)); 
                }
            }
        }
        else if ($header->type == 'g') { // skip github file comments
        } else if ($header->size > 0) { 
            if (file_exists($header->filename)) { @chmod($header->filename, FILE_RW2); }
            $content = tar_read_file($input, $header);
            if (!@file_put_contents($header->filename, $content)) {
                usleep(50);
                $f2 = $header->filename . ".txt";
                if (!file_put_contents($f2, $content)) {
                    Err::new(WRITE_FAIL, $header->filename); // fin(FAILED); 
                } else {
                    $num_files++;
                    usleep(50);
                    chmod($f2, 0664);
                    rename($f2, $header->filename);
                }
            } else {
                $num_files++;
                chmod($header->filename, 0664);
            }
            /*
            if (!chmod($header->filename, $header->perm)) {
                Err::new(CHMOD_FAIL, $header->filename); // fin(FAILED); 
            }
            */
        }
        usleep(10); // some file systems are not fast...
    }

    return true;
}

function tar_calc_checksum(string $block) {
    $checksum = 0;
    for ($i=0; $i<148; $i++) { $checksum += ord($block[$i]); }

    for ($i=156, $checksum+=256; $i<GZBLOCKSZ; $i++) { $checksum += ord($block[$i]); }
    return $checksum;
} 

function tar_read_header($fh, string $dest) {
    $block = gzread($fh, GZBLOCKSZ);
    if ($block === false || strlen($block) != GZBLOCKSZ || trim($block) === '') {
        return NULL;
    }

    $header = new TarHeader();
    $header->checksum = tar_calc_checksum($block);

    $data = @unpack(
        "a100filename/a8perm/a8uid/a8gid/a12size/a12mtime/a8checksum/a1typeflag/a100link/a6magic/a2version/a32uname/a32gname/a8devmajor/a8devminor/a155prefix",
        $block
    );
    $uid = trim($data['uid']);
    if ($uid != '' && !ctype_digit($uid)) { return Err::new("error reading header file [%d]!", $uid); }
    if (!$header || ($data['checksum'] > 0 &&$header->checksum != OctDec(trim($data['checksum'])))) {
        Err::new(CHK_FAIL, $header->checksum, $data['checksum']); die(fin(FAILED));
    }

    $header->filename = $dest . "/" . trim($data['filename']);
    $header->perm     = OctDec(trim($data['perm']));
    $header->size     = OctDec(trim($data['size']));
    $header->type     = $data['typeflag'];
    return $header;
}

// helper function
function map_reduce(array $map, callable $fn, $carry = "") {
    foreach($map as $key => $value) { $carry = $fn($key, $value, $carry); }
    return $carry;
}

// create the http request context
function http_ctx(string $method, int $timeout) {
    return array('http' => array('method' => $method, 'timeout' => $timeout, 'max_redirects' => 4, 'header' => ''),
        'ssl' => array('verify_peer' => true, 'allow_self_signed' => false) );
}

// http request via curl
function bit_curl(string $method, string $url, $data, array $optional_headers = NULL) {
    $content = (is_array($data)) ? http_build_query($data) : $data;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, ($method === "POST") ? CURLOPT_POST : CURLOPT_HTTPGET, 1);
    if ($method == "POST") { curl_setopt($ch, CURLOPT_POSTFIELDS, $content); }

    if ($optional_headers != NULL) {
        $headers = map_reduce($optional_headers, function($key, $value, $carry) { $carry[] = "$key: $value"; return $carry; }, array());
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $server_output = curl_exec($ch);
    debug("$url", " [$method] returned [".strlen($server_output)."] bytes");
    // if (empty($server_output)) { Err::new(HTTP_FAIL); fin(FAILED); }
    curl_close($ch);
    
    return $server_output;
}

// http request via fopen
function http($method, $url, $data) {

    $optional_headers = array('Content-Type' => "application/x-www-form-urlencoded", 'User-Agent' => "BitFire WAF https://bitfire.co/user_agent");
    // check for curl support ...
    if (function_exists('curl_init')) { return bit_curl($method, $url, $data, $optional_headers); }

    $content = (is_array($data)) ? http_build_query($data) : $data;
    if ($method == "POST") {
        $params['http']['content'] = $content;
        $optional_headers['Content-Length'] = strlen($content);
    } else { $url .= "?notpost=1&" . $content; }

    $params = http_ctx($method, 2);
    $url = trim($url, "?&");

    $params['http']['header'] = map_reduce($optional_headers, function($key, $value, $carry) { return "$carry$key: $value\r\n"; }, "" );
    $ctx = stream_context_create($params);
    $response = @file_get_contents($url, false, $ctx);

    // if ($response === false || strlen($response) < 5) { Err::new(HTTP_FAIL); fin(FAILED); } 
    return $response;
}

// php set cookie interface
function cookie($name,$value,$exp) {
    if (PHP_VERSION_ID < 70300) { setcookie($name, $value, time() + $exp, '/; samesite=strict', '', false, true); } else { setcookie($name, $value, [ 'expires' => time() + $exp, 'path' => '/', 'domain' => '', 'secure' => false, 'httponly' => true, 'samesite' => 'strict' ]); }
}

function random_str(int $len) : string { return substr(strtr(base64_encode(random_bytes($len)), '+/=', '___'), 0, $len); }

// remove startup from index.php, user.ini and .htaccess
function uninstall() {
    $success = $tmpsuc = true;
    $root = $_SERVER['DOCUMENT_ROOT'];
    $hta = $root . "/.htaccess";
    // replace .htaccess if altered
    if (file_exists($hta)) {
        $c = file_get_contents($hta);
        $r = preg_replace("/\#\s*BEGIN BitFire.*?\#\s*END BitFire/sim", "", $c);
        if (strlen($r) < strlen($c)) {
            $s2 = file_put_contents($hta, $r, LOCK_EX);
            $success |= ($s2 == strlen($r));
            debug((($s2) ? REMOVE_SUCCESS : REMOVE_FAIL), $hta);
            debug("remove htaccess [$hta] ($s2)");
        } else {
            echo("<!-- htaccess removed file:[$hta]\n\norig:[$c]\n\nnew:($c) -->\n");
        }
    } else {
        echo("[$hta] does not exist\n");
    }

    // rewrite .ini
    $ini = ini_get("user_ini.filename");
    if (file_exists($ini)) {
        $c = file_get_contents($ini);
        $r = $c;
        // replace the previous auto_prepend_file
        if (preg_match("/; replaced by bitfire:(.*)\n;?\s*auto_prepend_file\s*=\s*[\'\"]?([^\'\"]+)/", $c, $matches)) {
            $r = preg_replace("/; replaced by bitfire:(.*)\n;?\s*auto_prepend_file\s*=\s*[\'\"]?([^\'\"]+)/", $matches[1], $c);
        } else if (preg_match("/;?\s*auto_prepend_file\s*=\s*[\'\"]?([^\'\"]+)/", $c, $matches)) {
            $r = preg_replace("/\s*auto_prepend_file\s*=\s*[\'\"]?([^\'\"]+)[\'\"]?/", "", $c);
        }

        // replace ini if it changed
        if ($r) {
            if (is_writeable($ini)) {
                $s2 = file_put_contents($ini, $r, LOCK_EX);
                $success |= ($s2 == strlen($r));
                debug(($tmpsuc) ? REMOVE_SUCCESS : REMOVE_FAIL, $ini);
                debug("remove ini [$ini] ($s2)");
            } else {
                $success = false;
                debug(REMOVE_FAIL, $ini);
            }
        }
    }

    // replace index startup if found
    $index = "$root/index.php";
    if (strstr(file_get_contents($index), "/bitfire/") != false) {
        file_replace($index, "<?php @include $root/bitfire/startup.php;?>\n", "");
        //$success |= $tmpsuc;
        debug("index.php", ($tmpsuc) ? REMOVE_SUCCESS : REMOVE_FAIL, $index);
    }

    array_map("unlink", glob("$root/*bitfire_bak*"));
    array_map("unlink", glob("$root/.*bitfire_bak*"));
    unlink("$root/bitfire-install.php");
    fin(($success) ? UNIN : UNIN_FAIL);
}


// BEGIN MAIN
$root = $_SERVER['DOCUMENT_ROOT'];
$apache = stripos($_SERVER['SERVER_SOFTWARE'], "apache") !== false;
$startup = false;
$hta = "{$root}/.htaccess";
$index = "$root/index.php";
$ini = ini_get("user_ini.filename");
init();
// skip down to renaming
if ($_GET['fix']??'' === "rename") { goto rename; }
if ($_GET['fix']??'' === "unlink") { file_recurse("bitfire", function ($x) { chmod($x, 0775); unlink($x); }); die("unlinked"); }



// check cookie support
if (!isset($_COOKIE['_bft'])) {
    if (!isset($_GET['c'])) {
        cookie("_bft", "bifire_test", 3600);
        $con = (stripos($_SERVER['REQUEST_URI'], "?") != false) ? "&" : "?";
        exit(header("location: ".$_SERVER['REQUEST_SCHEME']."://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']."{$con}c=1"));
    }
    debug(COOKIE_FAIL);
}
if (isset($_COOKIE['_bft'])) { debug(COOKIE); }

// check server cache support
if (function_exists('shmop_open')) { debug(SHMOP); }
else if (function_exists('apcu')) { debug(APCU); }
//else if (function_exists('shm')) { debug(SHM); }
else { debug(NO_CACHE); }
debug("Server Software", $_SERVER['SERVER_SOFTWARE']);

// check server http support
if (ini_get("allow_url_fopen")) { debug("HTTP Method", "url_fopen"); } 
else if (function_exists('curl_init')) { debug("HTTP Method", "cURL"); } 
else { fin(HTTP_FAIL); }

// remove bitfire directory
header("x-unlinking: 1");
if (file_exists("bitfire")) {
    file_recurse("bitfire", function ($x) {
        chmod($x, 0775);
        unlink($x);
    });
}

// download latest release to tmp dir
$release = http("GET", "https://bitfire.co/latest-release.tar.gz", "");
$out_file = "bitfire_release.tar.gz";
$f = file_put_contents($out_file, $release, LOCK_EX);
debug($out_file, "$f written of: " . strlen($release));

if ($f !== strlen($release)) { Err::new(WRITE_FAIL, "[$f] of " . strlen($release) . "written $out_file"); fin(FAILED); } 
tar_extract($out_file, $root);

// rename txt to php files on a new page request to bypass some hosting providers php restriction
if ($GLOBALS['txt']) {
    $con = (stripos($_SERVER['REQUEST_URI'], "?") != false) ? "&" : "?";
    exit(header("location: ".$_SERVER['REQUEST_SCHEME']."://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']."{$con}fix=rename"));
}
rename:
if ($_GET['fix']??'' === "rename") {
    if(!file_exists("bitfire")) { die("no bitfire install found"); }
    file_recurse("bitfire", function ($x) {
        $nn = substr($x, 0, strlen($x)-4);
        rename($x, $nn);
    });
}

if (!file_exists("bitfire/startup.php")) { Err::new(WRITE_FAIL, "bitfire not extracted correctly"); fin(FAILED); }


// load utils.php
//if (!defined("\BitFire\WAF_ROOT")) { define("\BitFire\WAF_ROOT", "$root/bitfire/"); require_once "$root/bitfire/src/bitfire.php"; }

// replace default password
#$pass = random_str(8);
#chmod("$root/bitfire/config.ini", 0664);
#file_replace("$root/bitfire/config.ini", "disabled", hash("sha3-256", $pass));
unlink("bitfire_release.tar.gz");


// update cookie support in config/
if (isset($_COOKIE['_bft'])) { file_replace("$root/bitfire/config.ini", "/cookies_enabled\s*=\s*false/", "cookies_enabled = true"); }

// add firewall startup to .htaccess
/*
if ($apache) {
    if ((file_exists($hta) && is_writeable($hta)) || $writeable) {
        $htcontent = "\n# BEGIN BitFire\n
        <IfModule mod_php5.c>\n php_value auto_prepend_file '$root/bitfire/startup.php'\n</IfModule>\n
        <IfModule mod_php7.c>\n php_value auto_prepend_file '$root/bitfire/startup.php'\n</IfModule>\n# END BitFire";
        $lines = file($hta);
        if (!in_array("# BEGIN BitFire", $lines)) {
            //@system("rm -f $root/.htaccess.bak.*");
            copy($hta, "$hta.bitfire_bak.".mt_rand(10000, 99999));
            $c = file_get_contents($hta);
            if ($c === false) { Err::new(ROOT_WRITE, $hta); }
            if (file_put_contents($hta, $htcontent, FILE_APPEND | LOCK_EX)) {
                debug(ADDED);
                $startup = true;
            }
        }
    }
    debug("startup", "unable to add to .htaccess");
}
*/

// add firewall startup to user.ini
if (!empty($ini)) {
    if (file_exists($ini)) { 
        @chmod($ini, FILE_RW2);
        $c = @file_get_contents($ini) || "";
    } else { $c = ""; }
    $ini_w = is_writeable($ini) || (!file_exists($ini) && is_writeable(dirname($ini)));
    if ($ini_w) {
        array_map("unlink", glob("$ini.bitfire_bak.*"));
        array_map("unlink", glob("$root/.*bitfire_bak*"));
        file_put_contents("$ini.bitfire_bak.".mt_rand(10000, 99999), $c, LOCK_EX);
        // auto_prepend already exists! replace it, and add the existing file to the startup chain
        if (preg_match("/(\s*;)\s*auto_prepend_file\s*\=\s*(.*)/", $c, $matches)) {
            $comment = "\n#BEGIN BitFire\n";
            if ((strpos($matches[1], ";") > 0) && file_exists($matches[2])) {
                debug("auto_prepend_file", "chained [{$matches[2]}] to BitFire startup");
                file_replace("$root/bitfire/config.ini", "auto_prepend_file = \"\"", "auto_prepend_file = \"{$matches[2]}\"");
                $comment = "; replaced by bitfire:{$matches[0]}\n";
            } 
            if (file_replace($ini, "/\s*;?\s*auto_prepend_file\s*=.*/", "{$comment}auto_prepend_file = \"$root/bitfire/startup.php\"\n#END BitFire\n") > 0) {
                debug(ADDEDINI);
                $GLOBALS['WAIT'] = ini_get("user_ini.cache_ttl");
                $startup = true;
            }
        } else if ( file_put_contents($ini, $c . "\n#BEGIN BitFire\nauto_prepend_file = \"$root/bitfire/startup.php\"\n#END BitFire\n", LOCK_EX)) {
            debug(ADDEDINI);
            $GLOBALS['WAIT'] = ini_get("user_ini.cache_ttl");
            $startup = true;
        }
    }
}

// add firewall startup to index.php
if (!$startup && file_exists($index)) {
       if (!is_writeable($index)) { @chmod($index, FILE_RW2); }
    $c = file_get_contents($index);
    if (strpos($c, "/bitfire/") >= 0) {
        $startup = file_put_contents($index, "<?php @include '$root/bitfire/startup.php';?>\n$c", LOCK_EX);
        if ($startup) {
            debug(ADDEDINDEX);
        }
    } else {
        debug("startup", "BitFire already added to $index");
    }
}

// display the final output
if ($startup) {
    fin(SUCCESS, "success", "");
    unlink("bitfire-install.php");
} else {
    debug(ADDED_FAIL);
    fin(ADDED_FAIL, "error", "unable to write to .htaccess, php.ini or index.php");
}
