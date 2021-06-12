<?php
namespace TF;

class TarHeader {
    public $filename;
    public $size;
    public $perm;
    public $checksum;
    public $type;
}

/**
 * extract tar archive into destination directory
 */
function tar_extract(string $file, string $destination = "") : ?bool {
    $input = gzopen($file, 'rb');
    if ($input == false) { return \TF\debug("unable to open [%s]", $file); }

    while(($header = tar_read_header($input, $destination))) {
        if ((bool) $header->type) {
            @mkdir($header->filename, 0755, true);
        } else { 
            $output = @fopen($header->filename, "wb");
            if (!$output) { return \TF\debug("unable to open [%s]", $header->filename); }

            while ($header->size > 0) {
                $tmp = gzread($input, 512);
                $len = strlen($tmp);
                if ($len != fwrite($output, $tmp)) { return \TF\debug("unable to write %d bytes [%s]", $len, $header->filename); }
                $header->size -= $len;
            }
            fclose($output);
            @chmod($header->filename, $header->perm);
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
function tar_read_header($fh) : ?TarHeader {
    $block = gzread($fh, 512);
    if ($block === false || strlen($block) != 512 || trim($block) === '') {
        return \TF\debug("unable to read header block");
    }

    $header = new TarHeader();
    $header->checksum = tar_calc_checksum($block);

    $data = @unpack(
        "a100filename/a8perm/a8uid/a8gid/a12size/a12mtime/a8checksum/a1typeflag/a100link/a6magic/a2version/a32uname/a32gname/a8devmajor/a8devminor/a155prefix",
        $block
    );
    if (!$header || $header->checksum != OctDec(trim($data['checksum']))) {
        return \TF\debug("calc checksum failed [%d] / [%d]", $header->checksum, $data['checksum']);
    }

    $header->filename = trim($data['filename']);
    $header->perm     = OctDec(trim($data['perm']));
    $header->size     = OctDec(trim($data['size']));
    $header->type     = $data['typeflag'];
    return $header;
}
