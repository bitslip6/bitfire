<?php

use ThreadFin\Effect;
use ThreadFin\FileData;
use const BitFire\WAF_SRC;

const ACCESS = "portugal";
const APACHE = "RewriteEngine On\nRewriteRule ^((?!recovery.php).+)$ /recovery.php [L,QSA]\n";
const PHPINI = "auto_prepend_file = '" . __FILE__ . "';\n";
const MAINTENANCE = "CjwhRE9DVFlQRSBodG1sPgo8aHRtbCBsYW5nPSJlbiI+CjxoZWFkPgo8dGl0bGU+aG9tZWR0ZWNoLnNob3AgLSBNYWludGVuYW5jZTwvdGl0bGU+CjxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KPG1ldGEgaHR0cC1lcXVpdj0iWC1VQS1Db21wYXRpYmxlIiBjb250ZW50PSJJRT1lZGdlIj4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xIj4KPG1ldGEgbmFtZT0icm9ib3RzIiBjb250ZW50PSJub2luZGV4LCBmb2xsb3ciPgo8c3R5bGU+CmJvZHkgeyBmb250LWZhbWlseTogJ0xhdG8nLCBzYW5zLXNlcmlmOyB9Cip7LXdlYmtpdC1ib3gtc2l6aW5nOmJvcmRlci1ib3g7Ym94LXNpemluZzpib3JkZXItYm94fQpib2R5e3BhZGRpbmc6MDttYXJnaW46MH0KI2Jsb2Nre3Bvc2l0aW9uOnJlbGF0aXZlO2hlaWdodDoxMDB2aH0KI2Jsb2NrIC5ibG9jay1iZ3twb3NpdGlvbjphYnNvbHV0ZTt3aWR0aDoxMDAlO2hlaWdodDoxMDAlO2JhY2tncm91bmQtc2l6ZTpjb3Zlcn0KI2Jsb2NrIC5ibG9jay1iZzphZnRlcntjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRlO3dpZHRoOjEwMCU7aGVpZ2h0OjEwMCU7YmFja2dyb3VuZC1jb2xvcjpyZ2JhKDAsMCwwLC4yNSl9CiNibG9jayAuYmxvY2t7cG9zaXRpb246YWJzb2x1dGU7bGVmdDo1MCU7dG9wOjUwJTstd2Via2l0LXRyYW5zZm9ybTp0cmFuc2xhdGUoLTUwJSwtNTAlKTstbXMtdHJhbnNmb3JtOnRyYW5zbGF0ZSgtNTAlLC01MCUpO3RyYW5zZm9ybTp0cmFuc2xhdGUoLTUwJSwtNTAlKX0KI2Jsb2NrIC5ibG9jazphZnRlcntjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRlO2xlZnQ6NTAlO3RvcDo1MCU7LXdlYmtpdC10cmFuc2Zvcm06dHJhbnNsYXRlKC01MCUsLTUwJSk7LW1zLXRyYW5zZm9ybTp0cmFuc2xhdGUoLTUwJSwtNTAlKTt0cmFuc2Zvcm06dHJhbnNsYXRlKC01MCUsLTUwJSk7d2lkdGg6MTAwJTtoZWlnaHQ6NjAwcHg7YmFja2dyb3VuZC1jb2xvcjpyZ2JhKDI1NSwyNTUsMjU1LC43KTstd2Via2l0LWJveC1zaGFkb3c6MCAwIDAgMzBweCByZ2JhKDI1NSwyNTUsMjU1LC43KSBpbnNldDtib3gtc2hhZG93OjAgMCAwIDMwcHggcmdiYSgyNTUsMjU1LDI1NSwuNykgaW5zZXQ7ei1pbmRleDotMX0KLmJsb2Nre21heC13aWR0aDo2MDBweDt3aWR0aDoxMDAlO3RleHQtYWxpZ246Y2VudGVyO3BhZGRpbmc6MzBweDtsaW5lLWhlaWdodDoxLjR9Ci5ibG9jayAuYmxvY2stZXJye3Bvc2l0aW9uOnJlbGF0aXZlO2hlaWdodDoxNjBweH0KLmJsb2NrIC5ibG9jay1lcnIgaDF7Zm9udC1mYW1pbHk6cGFzc2lvbiBvbmUsc2Fucy1zZXJpZjtwb3NpdGlvbjphYnNvbHV0ZTtsZWZ0OjUwJTt0b3A6NDAlOy13ZWJraXQtdHJhbnNmb3JtOnRyYW5zbGF0ZSgtNTAlLC01MCUpOy1tcy10cmFuc2Zvcm06dHJhbnNsYXRlKC01MCUsLTUwJSk7dHJhbnNmb3JtOnRyYW5zbGF0ZSgtNTAlLC01MCUpO2ZvbnQtc2l6ZTo2MHB4O21hcmdpbjowO2NvbG9yOiMyMjIyMjU7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlfQouYmxvY2sgaDJ7Zm9udC1mYW1pbHk6bXVsaSxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToyNnB4O2ZvbnQtd2VpZ2h0OjQwMDt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7Y29sb3I6IzIyMjIyNTttYXJnaW4tdG9wOjI2cHg7bWFyZ2luLWJvdHRvbToyMHB4fQouYmxvY2stc2VhcmNoe3Bvc2l0aW9uOnJlbGF0aXZlO3BhZGRpbmctcmlnaHQ6MTIwcHg7bWF4LXdpZHRoOjQyMHB4O3dpZHRoOjEwMCU7bWFyZ2luOjMwcHggYXV0byAyMHB4fQouYmxvY2stc2VhcmNoIGlucHV0e2ZvbnQtZmFtaWx5Om11bGksc2Fucy1zZXJpZjt3aWR0aDoxMDAlO2hlaWdodDo0MHB4O3BhZGRpbmc6M3B4IDE1cHg7Y29sb3I6I2ZmZjtmb250LXdlaWdodDo0MDA7Zm9udC1zaXplOjE4cHg7YmFja2dyb3VuZDojMjIyMjI1O2JvcmRlcjpub25lfQpidXR0b24jcmV2aWV3e2ZvbnQtZmFtaWx5Om11bGksc2Fucy1zZXJpZjt3aWR0aDoxODBweDtoZWlnaHQ6NTBweDt0ZXh0LWFsaWduOmNlbnRlcjtib3JkZXI6bm9uZTtiYWNrZ3JvdW5kOiNmMDA4YzQ7Y3Vyc29yOnBvaW50ZXI7cGFkZGluZzowO2NvbG9yOiNmZmY7Zm9udC13ZWlnaHQ6NDAwO2ZvbnQtc2l6ZToxNnB4O3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZX0KYnV0dG9uI2hvbWV7Zm9udC1mYW1pbHk6bXVsaSxzYW5zLXNlcmlmO3dpZHRoOjIyMHB4O2hlaWdodDo1MHB4O3RleHQtYWxpZ246Y2VudGVyO2JvcmRlcjpub25lO2JhY2tncm91bmQ6IzIyMztjdXJzb3I6cG9pbnRlcjtwYWRkaW5nOjA7Y29sb3I6I2ZmZjtmb250LXdlaWdodDo0MDA7Zm9udC1zaXplOjE2cHg7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlfQouYmxvY2sgYXtmb250LWZhbWlseTptdWxpLHNhbnMtc2VyaWY7ZGlzcGxheTppbmxpbmUtYmxvY2s7Zm9udC13ZWlnaHQ6NDAwO3RleHQtZGVjb3JhdGlvbjpub25lO2JhY2tncm91bmQtY29sb3I6dHJhbnNwYXJlbnQ7Y29sb3I6IzIyMjIyNTt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7Zm9udC1zaXplOjE0cHh9Ci5ibG9jay1zb2NpYWx7bWFyZ2luLWJvdHRvbToxNXB4fQouYmxvY2stc29jaWFsPmF7ZGlzcGxheTppbmxpbmUtYmxvY2s7aGVpZ2h0OjQwcHg7bGluZS1oZWlnaHQ6NDBweDt3aWR0aDo0MHB4O2ZvbnQtc2l6ZToxNHB4O2NvbG9yOiNmZmY7YmFja2dyb3VuZC1jb2xvcjojMjIyMjI1O21hcmdpbjozcHg7LXdlYmtpdC10cmFuc2l0aW9uOi4ycyBhbGw7dHJhbnNpdGlvbjouMnMgYWxsfQouYmxvY2sgaDJ7Zm9udC1zaXplOjMycHh9Ci5ub3J7Zm9udC13ZWlnaHQ6bm9ybWFsO2ZvbnQtc2l6ZToyNHB4O30KI2F0dHJpYnV0ZXtwb3NpdGlvbjogZml4ZWQ7IGJvdHRvbTogMDsgbGVmdDogMDsgd2lkdGg6IDEwMCU7IGJhY2tncm91bmQ6ICMwMDA7IGNvbG9yOiAjZmZmOyBwYWRkaW5nOiAxMHB4OyB0ZXh0LWFsaWduOiBjZW50ZXI7IGZvbnQtc2l6ZTogMTRweDt9CiNhdHRyaWJ1dGUgc3BhbntwYWRkaW5nOiAwIDEwMHB4O30KI3RoZS1iZ3tiYWNrZ3JvdW5kLWltYWdlOiBVUkwoJ2h0dHBzOi8vaW1hZ2VzLnBleGVscy5jb20vcGhvdG9zLzExNTQ1MTAvcGV4ZWxzLXBob3RvLTExNTQ1MTAuanBlZz9hdXRvPWNvbXByZXNzJmNzPXRpbnlzcmdiJnc9MTI2MCZoPTc1MCZkcHI9MicpO30KQG1lZGlhIG9ubHkgc2NyZWVuIGFuZCAobWF4LXdpZHRoOjQ4MHB4KXsKICAgIC5ibG9jayAuYmxvY2stZXJye2hlaWdodDoxNDZweH0KICAgIC5ibG9jayAuYmxvY2stZXJyIGgxe2ZvbnQtc2l6ZToxNDZweH0KICAgIDwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CjxkaXYgY2xhc3M9ImhpZGRlbiIgaWQ9InJvb3QiPgo8ZGl2IGNsYXNzPSJoaWRkZW4iIGlkPSJibG9jayI+PGRpdiBpZD0idGhlLWJnIiBjbGFzcz0iYmxvY2stYmciPjwvZGl2PiA8ZGl2IGNsYXNzPSJibG9jayI+IDxkaXYgY2xhc3M9ImJsb2NrLWVyciI+IDxoMT5NYWludGVuYW5jZTwvaDE+IDwvZGl2Pgo8aDI+U2l0ZSBpcyBvZmZsaW5lPC9oMj4KPHAgY2xhc3M9Im5vciI+VGhpcyBzaXRlIGlzIHByb3RlY3RlZCBieSBCaXRGaXJlIFJBU1AuIDxicj4KVGhlIHNpdGUgaXMgY3VycmVudGx5IG9mZmxpbmUgYW5kIHVuZGVyZ29pbmcgbWFpbnRlbmFuY2UuIFdlIHdpbGwgYmUgYmFjayBzaG9ydGx5Lgo8L3A+Cgo8L2Rpdj4gPC9kaXY+CjxkaXYgaWQ9ImF0dHJpYnV0ZSI+PHA+CjxzcGFuPiBQb3dlcmVkIGJ5OiA8YSBocmVmPSJodHRwczovL2JpdGZpcmUuY28iIHJlbD0ibm9mb2xsb3cgc3BvbnNvcmVkIiB0YXJnZXQ9Il9ibGFuayIgc3R5bGU9ImNvbG9yOiAjZmZmOyI+Qml0RmlyZTwvYT48L3NwYW4+CjxzcGFuPiBQaG90byBieTogPGEgaHJlZj0iaHR0cHM6Ly93d3cucGV4ZWxzLmNvbS9Aam9zaHNvcmVuc29uLyIgcmVsPSJub2ZvbGxvdyB1Z2MiIHRhcmdldD0iX2JsYW5rIiBzdHlsZT0iY29sb3I6ICNmZmY7Ij5Aam9zaHNvcmVuc29uPC9hPiA8L3NwYW4+CjwvcD48L2Rpdj4KPC9kaXY+CjwvYm9keT4KPC9odG1sPg==";
if ($_GET['access'] !== ACCESS) {
    $html = base64_decode(MAINTENANCE);
    $content = str_replace("__TITLE__", $_SERVER['SERVER_NAME'] . " - Maintenance", $html);
    http_response_code(503);
    die($content);
}

/**
 * yield all matching files in a directory recursively
 */
function file_recurse(string $dirname, string $include_regex_filter = NULL, string $exclude_regex_filter = NULL, $max_files = 20000, bool $recurse = true) : \Generator {
    echo "check [$dirname]\n";
    if (!is_dir($dirname)) { return; }

    if ($dh = \opendir($dirname)) {
        while(($file = \readdir($dh)) !== false && $max_files-- > 0) {
            if (!$file || $file === '.' || $file === '..') {
                continue;
            }
            $path = $dirname . '/' . $file;
            // check if the path matches the regex filter
            echo "($include_regex_filter) [$path]\n";

            if (($include_regex_filter != NULL && preg_match($include_regex_filter, $path)) || $include_regex_filter == NULL) {
                // skip if it matches the exclude filter
                if ($exclude_regex_filter != NULL && preg_match($exclude_regex_filter, $path)) {
                    continue;
                }
                yield $path;
            }
            // recurse if it is a directory, don't follow symlinks ...
            if (is_dir($path) && !is_link($path)) {
                yield from file_recurse($path, $include_regex_filter, $exclude_regex_filter, $max_files);
			}
        }
        \closedir($dh);
    }
}


/*
$archive = [];
foreach (file_recurse(__DIR__, "/\.user\.ini/") as $file) {
    $archive[] = $file;
}
foreach (file_recurse(__DIR__, "/\.htaccess/") as $file) {
    $archive[] = $file;
}
*/
echo "<pre>HIT 1\n";

foreach (file_recurse(__DIR__ . DIRECTORY_SEPARATOR . "wp-content", "/\/plugins\/[a-zA-Z0-9_-]+$/") as $file) {
    echo "[$file]\n";
}

print_r($archive);


