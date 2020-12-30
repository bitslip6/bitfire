<?php

define ("GDTC", "Generic Attack Detected");
define ("TDNE", "temp dir does not exit");
define ("TDNW", "The Temporary directory is valid and writable with 128 MB diskspace available");
define ("APFI", "The auto_prepend_file ini setting is clear");
define ("CME",  "A valid cache mechanism (apc, shm, filesystem) is not available");

const ERR_HONEYPOT = "A bot requested a strictly forbidden url";
const ERR_METHOD = "An invalid HTTP method was used"; 
const ERR_INVALID_DOMAIN = "A bot requested a page but did not know the domain name";
const ERR_RR_TOO_HIGH = "An IP address flooded the server with requests";
const ERR_SQL_INJECT = "SQL Injection found";

const FATAL_NO_CONFIG = "must call Config::set() first";
const FATAL_MISSING_CONFIG = "Config is missing required parameter";
