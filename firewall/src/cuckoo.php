<?php

/**
 * BitFire PHP based Firewall.
 * Author: BitFire (BitSlip6 company)
 * Distributed under the AGPL license: https://www.gnu.org/licenses/agpl-3.0.en.html
 * Please report issues to: https://github.com/bitslip6/bitfire/issues
 * 
 * all functions are called via api_call() from bitfire.php and all authentication 
 * is done there before calling any of these methods.
 */

namespace ThreadFin;

use const ThreadFin\CUCKOO_LOW as ThreadFinCUCKOO_LOW;

use function BitFireSvr\update_ini_value;
use function ThreadFin\cuckoo_write as ThreadFinCuckoo_write;

const CUCKOO_SLOT_SIZE_BYTES = 19;
const CUCKOO_EXP_SIZE_BYTES = 6;
const CUCKOO_MAX_SIZE = 32768;
const CUCKOO_UNPACK = "Loffset/Lhash1/Lhash2/Lexpires/nlen/Cflags";
const CUCKOO_PACK = "LLLLnC";

const CUCKOO_READ_EXPIRED = false;
const CUCKOO_PRIMARY = 1;
const CUCKOO_ALT = 2;
const CUCKOO_LOCK = 4;
const CUCKOO_EMPTY = 8;
const CUCKOO_FULL = 16;
const CUCKOO_LOW = 32;
const CUCKOO_HIGH = 64;
const CUCKOO_PERM = 128;

const CUCKOO_PERM_MASK = 0 | CUCKOO_PERM | CUCKOO_HIGH | CUCKOO_LOW;
const CUCKOO_NOT_MASK = 0 | CUCKOO_PRIMARY | CUCKOO_ALT | CUCKOO_LOCK | CUCKOO_EMPTY | CUCKOO_FULL;
const CUCKOO_POSITIONS = [CUCKOO_PRIMARY, CUCKOO_ALT];

// ghetto FP reduce, we use as repeat
function reduce(int $num, callable $f, $x)
{
    while ($num-- > 0) {
        $x = $f($x);
    }
    return $x;
}

// ghetto FP loop until max times or callable returns true
function until(int $max, callable $f): bool
{
    $r = false;
    while ($r === false && $max > 0) {
        $r = $f($max--);
    }
    return $r;
}

// ghetto FP search
function search(array $items, callable $f)
{
    for ($i = 0, $m = count($items); $i < $m; $i++) {
        $r = $f($items[$i], $i);
        if ($r !== null) {
            return $r;
        }
    }
    return null;
}

// naive power of 2
function power_of_2(int $n): bool
{
    if ($n === 0) {
        return false;
    }
    while ($n !== 1) {
        if ($n % 2 !== 0) {
            return false;
        }
        $n = $n / 2;
    }
    return true;
}

/**
 * find a key's 2 locations 
 */
function cuckoo_key(string $key): array
{
    return array(crc32($key), crc32("alt-$key-alt"));
}

/**
 * todo this needs to read in chunks of 64 4 byte ints at the expired list location
 * and search for the first free memory chunk...
 * the memory should look for a random slot in the chunk of available memory
 */
function cuckoo_find_free_mem($ctx, $size): array
{
    // can't attempt to store values beyond the max size
    if ($size > CUCKOO_MAX_SIZE) {
        debug("cache entry too large %d of max %d", $size, CUCKOO_MAX_SIZE);
        return [null, null];
    }

    // calculate a reasonable block-size
    $block_size = intval(ceil($size / $ctx['chunk_size']) * $ctx['chunk_size']);

    // debug("shmop: block_size [$block_size]\n");
    // lock memory
    if (cuckoo_lock_for_write($ctx, $block_size)) {
        // find a location to allocate at the end of the stack, if full, defrag and return end of stack
        //debug("find free: {$ctx['free_mem']} + {$block_size} >= {$ctx['mem_end']}");

        $ptr = ($ctx['free'] + $block_size >= $ctx['mem_end']) ? cuckoo_mem_defrag($ctx) : $ctx['free'];
        // CONTINUE: add mem-defrag
        //$ptr = ($ctx['free'] + $block_size >= $ctx['mem_end']) ? null : $ctx['free'];

        //debug("allocate PTR: [$ptr]");
        // if we have a location (not full and defrag successful), update pointer location
        if ($ptr !== null) {
            shmop_write($ctx['rid'], pack("nnL", $ctx['slots'], $ctx['chunk_size'], $ptr + $block_size), $ctx['mem_end']);
            cuckoo::update_free($ptr + $block_size);
        }

        // unlock memory, really, this should never fail...
        until(10, function () use ($ctx) {
            return set_lock($ctx, 0);
        });
        //var_dump($until_result);

        return [$ptr, $block_size];
    } else {
        debug("failed to lock memory\n");
    }

    return [null, null];
}

function get_lock($ctx): int
{
    $data = unpack("Ltxid/Lexp", shmop_read($ctx['rid'], $ctx['mem_end'] + 8, 8));
    return ($data['exp'] < $ctx['now']) ? 0 : $data['txid'];
}

function set_lock($ctx, $value): bool
{
    shmop_write($ctx['rid'], pack("LL", $value, $ctx['now']), $ctx['mem_end'] + 8);
    return (get_lock($ctx) === $value);
}

function cuckoo_lock_for_write(array $ctx, $block_size): bool
{
    return until(5, function ($idx) use ($ctx) {

        $lock = get_lock($ctx);
        // unlocked
        if ($lock === 0) {
            return set_lock($ctx, $ctx['txid']);
        }
        if ($lock === $ctx['txid']) {
            return true;
        }
        // we don't own the lock, wait and try again
        usleep(mt_rand(50, 700));
        return false;
    });
}

// does NOTHING!
function cuckoo_mem_defrag(&$ctx): int
{
    $final = null;
    debug("DEFRAG");


    //$slot_num = $key_hash % $ctx['slots'];
    //$slot_loc = $slot_num * CUCKOO_SLOT_SIZE_BYTES;

    //$header = unpack("L3long/nlen/Cflags", shmop_read($ctx['rid'], 
    //$header = unpack("Loffset/Lhash/Lexpires/nlen/Cflags", shmop_read($ctx['rid'], $slot_loc, CUCKOO_SLOT_SIZE_BYTES));
    //$header = unpack(CUCKOO_UNPACK, shmop_read($ctx['rid'], $slot_loc, CUCKOO_SLOT_SIZE_BYTES));
    //$header['slot_num'] = $slot_num;



    $to_keep = array();
    for ($i = 0; $i < $ctx['slots']; $i++) {
        $header = unpack(CUCKOO_UNPACK, shmop_read($ctx['rid'], $i * CUCKOO_SLOT_SIZE_BYTES, CUCKOO_SLOT_SIZE_BYTES));
        $header['slot_num'] = $i;
        # keep this entry...
        if ($header['expires'] > $ctx['now']) {
            $to_keep[] = [$header, shmop_read($ctx['rid'], $header['offset'], $header['len'])];
        }
        # clear the header entry for this mem location
        else {
            $header_block = pack(CUCKOO_PACK, 0, 0, 0, 0, 0, 0 | CUCKOO_EMPTY);
            @shmop_write($ctx['rid'], $header_block, $i * CUCKOO_SLOT_SIZE_BYTES);
        }
    }

    debug("to keep: " . count($to_keep) . " / " . $ctx['slots']);

    $mem_offset = 0;

    foreach ($to_keep as $header_data) {
        usleep(10000);
        $header = $header_data[0];
        $block = $header_data[1];
        $len = strlen($block);
        $mem_offset += $len;

        // update the header pointer
        //debug("hdr offset: @{$header['slot']} off:{$header['offset']} / {$header['len']} -> ");
        $header['offset'] = $ctx['mem_start'] + $mem_offset;
        $header['len'] = $len;
        if (($header['offset'] + $header['len']) > $ctx['mem_end']) {
            debug("ERROR: header offset[%d] + len[%d] > mem_end[%d], dropping entry", $header['offset'], $header['len'], $ctx['mem_end']);
            continue;
        }
        //debug("{$header['offset']} / {$header['len']}\n");

        // write data block to new location
        $wrote = @shmop_write($ctx['rid'], $block, $ctx['mem_start'] + $mem_offset);
        //debug("defrag [%d/%d] [%s...%s]", $wrote, $len, substr($block, 0, 48), substr($block, -32));
        cuckoo_write_header($ctx, $header);
    }

    cuckoo::update_free($ctx['mem_start'] + $mem_offset);

    return $ctx['mem_start'] + $mem_offset;

    /*
    reduce(intval(ceil($ctx['slots'] / 64)), function($x) use ($ctx, &$final) {
        $read_len = (CUCKOO_EXP_SIZE_BYTES * 64);
        $start_byte = $x * $read_len;

        $bytes = shmop_read($ctx['rid'], $start_byte, $read_len);
        for($i=0;$i<64;$i++) {
            //$header = unpack("Loffset/Lhash/Lexpires/nlen/Cflags", $bytes, $i * CUCKOO_EXP_SIZE_BYTES);
            $header = unpack(CUCKOO_UNPACK, $bytes, $i * CUCKOO_EXP_SIZE_BYTES);
            if ($header['expires'] > $ctx['now']) {
                $final .= shmop_read($ctx['rid'], $start_byte, $read_len); 
            }
            $bytes = shmop_read($ctx['rid'], $start_byte, $read_len);
        }

        return $x+1;
    }, 0);
    */
}


/**
 * write $item to $key and expires in ttl_sec
 * will overwrite existing keys with a lower priority
 */
function cuckoo_write(array &$ctx, string $key, int $ttl_sec, array $item, int $priority = CUCKOO_LOW): bool
{
    if (!$ctx['rid']) {
        return debugF("ctx rid is false");
    }

    $header = cuckoo_find_header_for_write($ctx, $key, $priority);
    if ($header === null) {
        return debugF("unable to find header [%s] pri: [%d]", $key, $priority);
    }

    // we have a header we can write cache data to...
    if (function_exists('\igbinary_serialize')) {
        $data = \igbinary_serialize($item);
    } else if (function_exists('\msgpack_pack')) {
        $data = \msgpack_pack($item);
    } else {
        $data = serialize($item);
    }
    $size = strlen($data);

    // debug("shmop: $size:[$data]\n");
    // we can't store this much data in the cache...
    if ($size > CUCKOO_MAX_SIZE) {
        return debugF("cache write failed key [%s] size [%d]", $key, $size);
    }

    $mem = ($header['len'] < $size) ? cuckoo_find_free_mem($ctx, $size) : [$header['offset'], $header['len']];
    if ($mem[0] === null) {
        return debugF("unable to find [%d] free bytes in cache key [%s]", $size, $key);
    }
    if ($size > $mem[1]) {
        return debugF("write allocate memory key [%s] size [%d], allocation %d", $key, $size, $mem[1]);
    }

    // clear permissions...
    $header['flags'] = $priority; //set_flag_priority($header['flags'], CUCKOO_LOW) | CUCKOO_FULL;
    $header['offset'] = $mem[0];
    $header['len'] = $size;
    $header['expires'] = $ctx['now'] + $ttl_sec;

    //debug("writing key [$key] to mem: {$mem[0]} / {$mem[1]}");
    //debug("%s", print_r($header, true));
    cuckoo::update_free($ctx['free'] + intval($mem[1]));

    //debug("write [%d] [%s...%s]", $size, substr($data, 0, 48), substr($data, -32));

    // write success
    if (cuckoo_write_header($ctx, $header)) {
        if (shmop_write($ctx['rid'], $data, $mem[0]) === $size) {
            trace("shmW+ [$size:{$mem[0]}:$key]");
            // debug("wrote {$ctx['rid']} %d bytes @%d [%s]", $size, $mem[0], print_r($header, true));
            // debug(print_r($data, true));
            return true;
        }
        trace("shm W+ [fail]");
    }
    return debugF("unable to write header key: [%s] [%d] bytes", $key, $size);
}

/**
 * return an array with the unpacked header at cache location $key_hash
 * impure
 */
function cuckoo_read_header(array $ctx, int $key_hash): ?array
{
    $slot_num = $key_hash % $ctx['slots'];
    $slot_loc = $slot_num * CUCKOO_SLOT_SIZE_BYTES;

    //$header = unpack("L3long/nlen/Cflags", shmop_read($ctx['rid'], 
    //$header = unpack("Loffset/Lhash/Lexpires/nlen/Cflags", shmop_read($ctx['rid'], $slot_loc, CUCKOO_SLOT_SIZE_BYTES));
    $header = unpack(CUCKOO_UNPACK, shmop_read($ctx['rid'], $slot_loc, CUCKOO_SLOT_SIZE_BYTES));
    $header['slot_num'] = $slot_num;
    // debug("read header @%d off[%d] len[%d]", $slot_num, $header['offset'], $header['len']);

    // return the filtering function
    return $header;
}

/**
 * return true if the header was written successfully
 * long1 - memory offset, long2 - hash_key, long3 - expires time
 * len - length of data, open - true/false if the slot is open
 * impure
 */
function cuckoo_write_header(array $ctx, array $header): bool
{
    $header['flags'] |= CUCKOO_FULL;
    // debug("write header @%d   off[%d]  len[%d]", $header['slot_num'], $header['offset'], $header['len']);
    return shmop_write(
        $ctx['rid'],
        pack(CUCKOO_PACK, $header['offset'], $header['hash1'], $header['hash2'], $header['expires'], $header['len'], $header['flags']),
        $header['slot_num'] * CUCKOO_SLOT_SIZE_BYTES
    ) === CUCKOO_SLOT_SIZE_BYTES;
}


/**
 * find a header for reading
 * impure
 */
function cuckoo_find_header_for_read(array $ctx, string $key): ?array
{
    $key_hashes = cuckoo_key($key);

    // read location 1 and 2.  return if either hashes do not match
    $header = cuckoo_read_header($ctx, $key_hashes[0]);
    if ($header['hash1'] !== $key_hashes[0] || $header['hash2'] !== $key_hashes[1]) {
        $header = cuckoo_read_header($ctx, $key_hashes[1]);
        if ($header['hash1'] !== $key_hashes[0] || $header['hash2'] !== $key_hashes[1]) {
            // cache entry is missing, don't log it
            if ($header['hash1'] == 0) {
                return null;
            }
            // cache entry is miss-matched, log it
            return debugN("cache keys miss-match [%s] 1:%d/%d, 2:%d/%d", $key, $key_hashes[0], $header['hash1'], $key_hashes[1], $header['hash2']);
        }
    }

    // return the header if not expired
    if ($header['expires'] > $ctx['now']) {
        return $header;
    } else {
        return debugN("cache entry expired [%s] %d/%d", $key, $header['expires'], $ctx['now']);
    }
}

// clear position flags and keep any other flags, then set the position
// pure
function set_flag_position(int $flag, int $flag_position): int
{
    return ($flag & CUCKOO_PERM_MASK) | $flag_position;
}

// clear position flags and keep any other flags, then set the position
function set_flag_priority(int $flag, int $flag_priority): int
{
    return ($flag & CUCKOO_NOT_MASK) | $flag_priority;
}


/**
 * find a header for reading
 */
function cuckoo_find_header_for_write(array $ctx, string $key, int $priority): ?array
{
    $key_hashes = cuckoo_key($key);

    // read location 1 and 2.  return if either hashes do not match
    $header = cuckoo_read_header($ctx, $key_hashes[0]);
    $header['hash1'] = $key_hashes[0];
    $header['hash2'] = $key_hashes[1];
    $header['flags'] = 0 | $priority;

    // if hash key matches, or key is expired, or priority is PERM, or 
    if (
        ($header['hash1'] === $key_hashes[0] && $header['hash2'] === $key_hashes[1]) ||
        ($header['expires'] < $ctx['now']) ||
        ($priority === CUCKOO_PERM) ||
        ($priority > CUCKOO_LOW && !($header['flags'] & CUCKOO_HIGH))
    ) {
        $header['slot_num'] = $key_hashes[0] % $ctx['slots'];
        $header['slot'] = 1;
        return $header;
    }

    $header = cuckoo_read_header($ctx, $key_hashes[1]);
    // if hash key matches, or key is expired, or priority is PERM, or 
    if (
        ($header['hash1'] === $key_hashes[0] && $header['hash2'] === $key_hashes[1]) ||
        ($header['expires'] < $ctx['now']) ||
        ($priority === CUCKOO_PERM) ||
        ($priority > CUCKOO_LOW && !($header['flags'] & CUCKOO_HIGH))
    ) {
        $header['slot_num'] = $key_hashes[1] % $ctx['slots'];
        $header['slot'] = 2;
        return $header;
    }


    return null;

    $key_hashes = cuckoo_key($key);

    return search($key_hashes, function (int $hash, int $index) use ($ctx, $priority) {
        return cuckoo_read_header($ctx, $hash, function ($header) use ($hash, $priority, $index, $ctx) {
            // key matches, or is expired, or the priority is lower
            if (
                $header['hash'] === $hash || $header['expires'] < $ctx['now'] ||
                ($header['flags'] & CUCKOO_PERM_MASK) < $priority
            ) {
                // set the correct hash position (primary, alt) flag
                $header['flags'] = 0 | CUCKOO_POSITIONS[$index];
                $header['hash'] = $hash;
                return $header;
            }
            return null;
        });
    });
}

/**
 * read a previously stored cache key
 */
function cuckoo_read_or_set(array $ctx, string $key, int $ttl, callable $fn, int $priority = CUCKOO_LOW)
{
    if (!$ctx['rid']) {
        return debugF("cache rid is null");
    }
    $header = cuckoo_find_header_for_read($ctx, $key);

    return ($header !== null)
        ? function () use ($ctx, $header) {
            return (shmop_read(
                $ctx['rid'],
                $header['offset'],
                $header['len']
            ));
        }
        : function () use ($ctx, $key, $ttl, $fn, $priority) {
            $data = $fn();
            cuckoo_write($ctx, $key, $ttl, $data, $priority);
            return $data;
        };
}

function cuckoo_read(array $ctx, string $key)
{
    if (!$ctx['rid']) {
        return debugN("cache rid is null");
    }
    $header = cuckoo_find_header_for_read($ctx, $key);
    $data = "x";

    if ($header !== null && $header['len'] > 0) {
        $data = shmop_read($ctx['rid'], $header['offset'], $header['len']);

        // we have a header we can write cache data to...
        if (function_exists('\igbinary_serialize')) {
            $x = @\igbinary_unserialize($data);
        } else if (function_exists('\msgpack_pack')) {
            $x = @\msgpack_unserialize($data);
        } else {
            $x = unserialize($data);
        }
        // unable to read the cache data, clear the slot!
        if ($x == false && $header['len'] > 0) {
            trace("ERR:{$key}");
            $header['expires'] = $ctx['now'] - 3600;
            $header['len'] = 0;
            $header['hash1'] = 0;
            $header['hash2'] = 0;
            $header['flags'] = CUCKOO_LOW;
            cuckoo_write_header($ctx, $header);
        }

        if (is_array($x)) {
            $n = count($x);
            if ($n == 2) {
                return $x;
            }
        }
    }

    $x = "E";
    if ($header == null) {
        $x = "N";
    } else if ($header['len'] < 1) {
        $x = "0";
    } else (debug("read cache error [%s] len: %d, (%s)", $key, strlen($data), $data));
    cuckoo_write($ctx, $key, 0, [$key, ""], CUCKOO_LOW);
    return null;
}


/**
 * memory is laid out like:
 * [LRU_HASH_ENTRY],[LRU_HASH_ENTRY]..X.items,[MEM_EXP],[MEM_EXP]..X.items,[MEM],[MEM]..X.items
 * LRU_HASH_ENTRY - hash_key,expires_ts,size,full|empty
 * MEM_EXP - expires_ts
 * MEM - chunk X chunk size bytes
 */
function cuckoo_init_memory(array $ctx, int $items, int $chunk_size): void
{
    // some rules about our cache
    assert($items <= 100000, "max 100K items in cache");
    assert($chunk_size <= 16384, "max base chunk_size 16K");
    assert(power_of_2($chunk_size));
    debug("init memory");


    // initial expired memory block (5 bytes)
    //$exp_full_block = pack("Ln", time() + 60, 0);
    //$exp_empty_block = pack("Ln", 1, 0);
    //$exp_block = pack("Ln", time() + 60, 0);

    // initial slot header (15 bytes)
    $header_block = pack(CUCKOO_PACK, 0, 0, 0, 0, 0, 0 | CUCKOO_EMPTY);

    reduce($items, function ($x) use ($header_block, $ctx) {

        (@shmop_write($ctx['rid'], $header_block, $x * CUCKOO_SLOT_SIZE_BYTES) !== false);
        $block = pack("Ln", (mt_rand(1, 50) == 2) ? 1 : time() + 60, $x);
        (@shmop_write($ctx['rid'], $block,    $ctx['mem_start'] + ($x * CUCKOO_EXP_SIZE_BYTES)) !== false);
        return $x + 1;
    }, 0);

    // mark memory as initialized
    shmop_write($ctx['rid'], pack("nnLLL", $items, $chunk_size, $ctx['mem_start'], 0, 0), $ctx['mem_end']);
}

/**
 * helper function to open shared memory
 */
function cuckoo_open_mem(int $size_in_bytes, $token, bool $reduced = false)
{
    // debug("shmop_open token: $token bytes: $size_in_bytes");
    $GLOBALS['bf_err_skip'] = true;
    $id = @shmop_open($token, 'c', 0666, $size_in_bytes);

    // unable to attach/created memory segment, recreate it...
    if ($id === false) {
        debug("shmop_open fail, retry");
        $e = error_get_last();
        if (!empty($e) && stripos("to allocate", $e['message']) !== false && $size_in_bytes > 162000) {
            return cuckoo_open_mem($size_in_bytes - 128000, $token, true);
        }
        if (!empty($e) && stripos("ermission denied", $e['message']) !== false) {
            $token = 0x818283ad;
        }

        // connect failed, we probably have an old mem segment that is not large enough
        $id = @shmop_open($token, 'w', 0, 0);
        if ($id) {
            @shmop_delete($id);
        }
        $GLOBALS['bf_err_skip'] = false;
        $id = @shmop_open($token, 'c', 0666, $size_in_bytes);
        if ($id === false) {
            debug("shmop: unable to allocate %d shared memory token:[%s]", $size_in_bytes, dechex($token));
        }
    } else if ($reduced) {
        debug("NOTICE: reduced cache size to %d bytes", $size_in_bytes);
        update_ini_value("cache_size", $size_in_bytes)->run();
    }
    $GLOBALS['bf_err_skip'] = false;
    return $id;
}

/**
 * connect to the existing shared memory or initialize new shared memory
 * @param int $items = 4096
 * @param int $chunk_size = 1024
 * @param int $mem = 1114112
 * @param bool $force_init = false
 * @param string $key = the shmem "key" = 'a'
 */
function cuckoo_connect(int $items = 4096, int $chunk_size = 2048, int $mem = 1114112, bool $force_init = false): array
{
    $token = \BitFire\Config::int("cache_token", 1234560);
    $entry_end = $items * CUCKOO_SLOT_SIZE_BYTES;
    $mem_end = $entry_end + $mem;

    $rid = cuckoo_open_mem($mem_end + 16, $token);
    $ctx = array(
        'rid' => $rid,
        'txid' => mt_rand(1, 2147483647),
        "mem_start" => $entry_end,
        "mem_end" => $entry_end + $mem,
        "slots" => $items,
        "now" => time(),
        "chunk_size" => $chunk_size
    );


    if ($rid) {
        // initialized memory writes num items and chunk size to last initialized byte
        $mem = unpack("nitems/nsize/Lfree/Llockid/Llockexp", shmop_read($ctx['rid'], ($ctx['mem_end']), 16));

        // memory needs initialization...
        if ($force_init || $mem['items'] !== $items || $mem['size'] !== $chunk_size) {
            cuckoo_init_memory($ctx, $items, $chunk_size);
            $ctx['free'] = $ctx['mem_start'];
        } else {
            $ctx['free'] = $mem['free'];
        }
        $ctx['free_mem'] = $ctx['mem_end'] - $mem['free'];
    }

    return $ctx;
}

class cuckoo
{
    private static $ctx;

    public static function update_free(int $free_pos)
    {
        self::$ctx['free'] = $free_pos;
        self::$ctx['free_mem'] = self::$ctx['mem_end'] - $free_pos;
        trace("FM:" . self::$ctx['free_mem']);
    }

    // TODO: determine 
    public function __construct()
    {
        self::$ctx = cuckoo_connect(20000, 128, 20000 * 128, false);
    }

    public static function read($key)
    {
        return cuckoo_read(self::$ctx, $key);
    }

    public static function read_or_set(string $key, int $ttl, callable $fn, int $priority = CUCKOO_LOW)
    {
        return cuckoo_read_or_set(self::$ctx, $key, $ttl, $fn, $priority);
    }

    public static function write(string $key, int $ttl, array $storage, int $priority = CUCKOO_LOW)
    {
        return cuckoo_write(self::$ctx, $key, $ttl, $storage, $priority);
    }

    public static function clear()
    {
        cuckoo_init_memory(self::$ctx, 20000, 128);
    }

    public static function delete()
    {
        shmop_delete(self::$ctx['rid']);
    }

    public static function defrag()
    {
        cuckoo_mem_defrag(self::$ctx);
    }
}
