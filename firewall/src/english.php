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

const TDNE = "temp dir does not exit";
const ERR_SQL_INJECT = "SQL Injection found";
const FATAL_NO_CONFIG = "must call Config::set() first";
const FATAL_MISSING_CONFIG = "Config is missing required parameter";


const FEATURE_CLASS = array(0 => 'require_full_browser', 10000 => 'xss_block', 11000 => 'web_block', 12000 => 'web_block', 13000 => 'web_block', 14000 => 'sql_block', 15000 => 'web_block', 16000 => 'web_block', 17000 => 'web_block', 18000 => 'spam_filter_enabled', 20000 => 'require_full_browser', 21000 => 'file_block', 22000 => 'web_block', 23000 => 'check_domain', 24000 => 'whitelist_enable', 25000 => 'blacklist_enable', 26000 => 'rate_limit', 29000 => 'rasp_filesystem', 50000 => '');
const MESSAGE_CLASS = array(0 => 'unknown', 10000 => 'Cross Site Scripting', 11000 => 'General Web Blocking', 12000 => 'Remote Code Execution', 13000 => 'Format String Vulnerability', 14000 => 'SQL Injection', 15000 => 'Local File Include', 16000 => 'Web Shell Access', 17000 => 'Dot Dot Attack', 18000 => 'SPAM', 20000 => 'Browser Impersonation', 21000 => 'PHP Script Upload', 22000 => 'General Web Blocking', 23000 => 'Invalid Domain', 24000 => 'Invalid Bot', 25000 => 'Blacklist Bot', 26000 => 'Rate Limit IP', 27000 => 'Spoofed Browser', 29000 => 'File Write Protection', 30000 => 'XSS account takeover', 31000 => 'Unknown Bot', 32000 => 'Database Spam', 50000 => '');