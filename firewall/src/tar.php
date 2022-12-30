<?php
/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 */

namespace ThreadFin;

class TarHeader {
    public $filename;
    public $size;
    public $perm;
    public $checksum;
    public $type;
}

function tar_read_file($fh, TarHeader $header) : string {
    $result = "";
    $ctr = 0;
    while ($header->size > 0 && $ctr++ < 20000) {
        $tmp = gzread($fh, 512);
        $len = strlen($tmp);
        if ($len != 512) { debug("only read %d bytes / 512", $len); }
        $result .= substr($tmp, 0, min($header->size, 512));
        $header->size -= strlen($tmp);
    }
    return $result;
}

/**
 * extract tar archive into destination directory
 */
function tar_extract(string $file, string $destination = "") : ?bool {
    $input = gzopen($file, 'rb');
    if ($input == false) { return debugF("unable to open [%s]", $file); }

    while(($header = tar_read_header($input, $destination))) {
        if ($header->type == 5) {
            if (!file_exists($header->filename)) {
                if (!mkdir($header->filename, 0755, true)) {
                    return debugF("error mkdir [%s]", $header->filename);
                }
            }
        }
        // skip github file comments
        else if ($header->type == 'g') { 
        } else if ($header->size > 0) { 
            if (!file_put_contents($header->filename, tar_read_file($input, $header), LOCK_EX)) {
                return debugF("error writing [%s]", $header->filename);
            }
            if (!chmod($header->filename, $header->perm)) {
                return debugF("error setting permission [%s]", $header->filename);
            }
        }
    }
    return true;
}

/**
 * calculate a checksum for a header block
 */
function tar_calc_checksum(string $block) : int {
    $checksum = 0;
    for ($i=0; $i<148; $i++) { $checksum += ord($block[$i]); }

    for ($i=156, $checksum+=256; $i<512; $i++) { $checksum += ord($block[$i]); }
    return $checksum;
} 

/**
 * parse a tar header
 */
function tar_read_header($fh, string $dest) : ?TarHeader {
    $block = gzread($fh, 512);
    if ($block === false || strlen($block) != 512 || trim($block) === '') {
        return debugN("unable to read header block, end of archive");
    }

    $header = new TarHeader();
    $header->checksum = tar_calc_checksum($block);

    $data = @unpack(
        "a100filename/a8perm/a8uid/a8gid/a12size/a12mtime/a8checksum/a1typeflag/a100link/a6magic/a2version/a32uname/a32gname/a8devmajor/a8devminor/a155prefix",
        $block
    );
    $uid = trim($data['uid']);
    if ($uid != '' && !ctype_digit($uid)) { return debug("error reading header file [%d]!", $uid); }
    if (!$header || ($data['checksum'] > 0 && $header->checksum != OctDec(trim($data['checksum'])))) {
        return debugN("calc checksum failed (%s) [%d] / [%d]", $header->filename, $header->checksum, $data['checksum']);
    }

    $header->filename = $dest . "/" . trim($data['filename']);
    $header->perm     = OctDec(trim($data['perm']));
    $header->size     = OctDec(trim($data['size']));
    $header->type     = $data['typeflag'];
    return $header;
}
