<?php


/*
function cache_unique() : string {
    return take_nth($_SERVER['HTTP_ACCEPT_LANGUAGE']??'', ',', 0) . '-' . $_SERVER['SERVER_NAME']??'default';
}
*/



// chain after inspect() call in startup.php
//      ->doifnot(array($bitfire, 'cache_behind'));
//    const CACHE_PAGE = \BitFire\WAF_ROOT . "cache/root";

// TODO: move this to "pure function"
    // display the cache behind page
    // FIX: replace fail reasons here!
    /*
    function cache_behind() {
        // don't cache internal requests... (infinate loop)
        if (isset($_GET[BITFIRE_INPUT])) { return; }

        // if the request is to the homepage with no parameters, it is possible to cache
        $tracking_cookie = Config::str(CONFIG_USER_TRACK_COOKIE, '_bitf');
        $site_cookies = array_filter(array_keys($_COOKIE), function($name) use ($tracking_cookie) { return stripos($name, $tracking_cookie) === false; });

        if (Config::int(CONFIG_MAX_CACHE_AGE, 0) > 0 &&
            $this->_request->path === '/' && 
            $this->_request->method === "GET" &&
            count($_GET) === 0 && 
            count($site_cookies) === 0) {
                // update the cache after this request
                register_shutdown_function([$this, 'update_cache_behind']);
                $page = \BitFire\WAF_ROOT . 'cache/root:' . cache_unique();
                // we have a cached page that is not too old
                if ($this->cached_page_is_valid($page)) {
                    header("x-cached: 1");
                    // add a js challenge if the request is not to a bot
                    if (Config::enabled(CONFIG_REQUIRE_BROWSER) && $this->bot_filter != null && $this->bot_filter->browser->bot == false) {
                        \BitFireBot\send_browser_verification($this->bot_filter->ip_data, Config::str(CONFIG_ENCRYPT_KEY))->run();
                    }
                    // serve the static page!
                    echo file_get_contents($page);
                    echo "<!-- cache -->\n";
                    exit();
                }
        }
    }
    */



    /**
     * test if BitFire::CACHE_PAGE is a valid cached page (exists and is not stale)
     */
    /*
    function cached_page_is_valid(string $page) {
        $stat_data = @stat($page);
        $exp_time = $stat_data['ctime'] + Config::int(CONFIG_MAX_CACHE_AGE);
        //echo "<!-- [$page]\n" . time() . "\n$exp_time\n"; print_r($stat_data); echo "-->\n";
        $cache_valid = ($stat_data != false && $exp_time > time());
        $h = "x-cache-valid: false";
        if ($cache_valid) { $h = "x-cache-valid: true"; }
        header($h);
        //return false;
        return $cache_valid;
    }
    */

    /**
     * TODO: MOVE TO CACHE.php
     */
    // update the cache behind page
    /*
    static function update_cache_behind() {
        if (strlen($_SERVER['SERVER_NAME']??'') < 1) { return; }
        $secret = Config::str(CONFIG_SECRET, 'bitfiresekret');
        $scheme = ($server['HTTP_X_FORWARDED_PROTO']??$server['REQUEST_SCHEME']??'http');
        $u = "{$scheme}://" . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'] . "?" . BITFIRE_INPUT . "=$secret";
        $d = http("GET", $u, "");
        file_put_contents(\BitFire\WAF_ROOT . '/cache/root:'. cache_unique(), $d);
    }
    */

