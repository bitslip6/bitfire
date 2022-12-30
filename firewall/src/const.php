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

namespace BitFire;

const STATUS_SERVER_STATE_FAIL = -1;


const RESTRICTED_FILES = ["wp-config", ".."];
const FEATURE_CLASS = array(0 => 'require_full_browser', 10000 => 'xss_block', 11000 => 'web_filter_enabled', 12000 => 'web_filter_enabled', 13000 => 'web_filter_enabled', 14000 => 'sql_block', 15000 => 'web_filter_enabled', 16000 => 'web_filter_enabled', 17000 => 'web_filter_enabled', 18000 => 'spam_filter_enabled', 20000 => 'require_full_browser', 21000 => 'file_block', 22000 => 'check_domain', 23000 => 'check_domain', 24000 => 'whitelist_enable', 25000 => 'blacklist_enable', 26000 => 'rate_limit', 27000 => 'require_full_browser', 29000 => 'rasp_filesystem', 30000 => 'rasp_js', 31000 => 'whitelist_enable', 32000 => 'rasp_db', 33000 => 'rasp_network', 50000 => 'web_filter_enabled');
const FEATURE_NAMES = array(0 => 'unknown', 10000 => 'Cross Site Scripting', 11000 => 'Generic Web Filtering', 12000 => 'Generic Web Filtering', 13000 => 'Generic Web Filtering', 14000 => 'SQL Injection', 15000 => 'Generic Web Filtering', 16000 => 'Generic Web Filtering', 17000 => 'Generic Web Filtering', 18000 => 'Spam Content', 20000 => 'JavaScript Required', 21000 => 'File Upload', 22000 => 'Domain Name Verify', 23000 => 'Domain Verify', 24000 => 'Invalid Robot Network', 25000 => 'Malicious Robot', 26000 => 'Rate Limit Exceeded', 27000 => 'JavaScript Required', 29000 => 'PHP File Lock', 30000 => 'Strict CMS Requests', 31000 => 'Invalid Robot Network', 32000 => 'Unauthorized User Edit', 50000 => 'Generic Web Filtering');
const CODE_CLASS = array(0 => 'robot.svg', 10000 => 'xss.svg', 11000 => 'xxe.svg', 12000 => 'bacteria.svg', 13000 => 'fire.svg', 14000 => 'sql.svg', 15000 => 'file.svg', 16000 => 'php.svg', 17000 => 'fire.svg', 21000 => 'php.svg', 22000 => 'robot.svg', 23000 => 'robot.svg', 24000 => 'robot.svg', 25000 => 'badbot.svg', 26000 => 'speed.svg', 27000 => 'robot.svg', 29000 => 'php.svg', 30000 => 'xss.svg', 31000 => 'badbot.svg', 32000 => 'sql.svg', 50000 => 'rule.svg');

const BITFIRE_API_FN = array('\\BitFire\\dump_hashes', '\\BitFire\\allow', '\\BitFire\\send_mfa', '\\BitFire\\delete', '\\BitFire\\repair', '\\BitFire\\diff','\\BitFire\\SETTINGS', '\\BitFire\\MALWARESCAN', '\\BitFire\\set_pass', '\\BitFire\\clear_cache', '\\BitFire\\upgrade', '\\BitFire\\hash_diffs', '\\BitFire\\DASHBOARD', '\\BitFire\\download', '\\BitFire\\rem_api_exception', '\\BitFire\\add_api_exception', '\\BitFire\\unlock_site', '\\BitFire\\lock_site', '\\BitFire\\get_block_types', '\\BitFire\\backup_database', '\\BitFire\\add_list_elm','\\BitFire\\clean_post', '\\BitFire\\scan_malware', '\\BitFire\\remove_list_elm', '\\BitFire\\toggle_config_value', '\\BitFire\\get_valid_data', '\\BitFire\\get_ip_data', '\\BitFire\\get_hr_data', '\\BitFire\\dump_hash_dir','\\BitFire\\install', '\\BitFire\\uninstall', '\\BitFire\\download', '\\BitFire\\malware_files');
const BITFIRE_METRICS_INIT = array('challenge' => 0, 'broken' => 0, 'invalid' => 0, 'valid' => 0, 10000 => 0, 11000 => 0, 12000 => 0, 13000 => 0, 14000 => 0, 15000 => 0, 16000 => 0, 17000 => 0, 18000 => 0, 19000 => 0, 20000 => 0, 21000 => 0, 22000 => 0, 23000 => 0, 24000 => 0, 25000 => 0, 26000 => 0, 29000 => 0, 70000 => 0);
const BITFIRE_VER = 999;
const BITFIRE_SYM_VER = "9.9.9";
const APP = "https://bitfire.co/";

const BITFIRE_INTERNAL_PARAM = 'BITFIRE_NONCE';
const BITFIRE_COMMAND = "BITFIRE_API";

const BITFIRE_MAX_HASH_COUNT = 20;
const BITFIRE_MAX_AUDIT = 20;
const BITFIRE_MAX_PAGES = 200;
const WAF_MIN_HIT = 25;
const WAF_MIN_PERCENT = 10;

const CONFIG_COOKIES='cookies_enabled';
const CONFIG_REPORT_FILE='report_file';
const CONFIG_BLOCK_FILE='block_file';
const CONFIG_DASHBOARD_PATH='dashboard_path';
const CONFIG_WHITELIST_ENABLE='whitelist_enable';
const CONFIG_BLACKLIST_ENABLE='blacklist_enable';
const CONFIG_REQUIRE_BROWSER = 'require_full_browser';
const CONFIG_USER_TRACK_COOKIE = 'browser_cookie';
const CONFIG_MAX_CACHE_AGE = 'max_cache_age';
const CONFIG_ENCRYPT_KEY = 'encryption_key';
const CONFIG_SECRET = 'secret';
const CONFIG_VALID_DOMAIN_LIST = 'valid_domains';
const CONFIG_ENABLED = 'bitfire_enabled';
const CONFIG_WEB_FILTER_ENABLED = 'web_filter_enabled';
const CONFIG_SECURITY_HEADERS = 'security_headers_enabled';
const CONFIG_XSS_FILTER="xss_block";
const CONFIG_SQL_FILTER="sql_block";
const CONFIG_FILE_FILTER="file_block";
const CONFIG_SPAM_FILTER="spam_filter_enabled";
const CONFIG_CACHE_TYPE = 'cache_type';
const CONFIG_LOG_FILE = 'log_file';
const CONFIG_RR_1M = 'rr_1m';
const CONFIG_RR_5M = 'rr_5m';
const CONFIG_PROFANITY = 'profanity_filter';
const CONFIG_CHECK_DOMAIN = 'check_domain';

const CONFIG_MFA_PATH = 'mfa_login_paths';
const CONFIG_MFA_NUMBER = 'mfa_phone_number';

const BITFIRE_INPUT = '_bitfire';

const THROTTLE_LOCK_TIME = 600;
const THROTTLE_LOCK_FILE = ".bitfire.lock";

const FAIL_NOT = 0;

const PROFANITY = "anal|anus|arse|ass|asss|bastard|bitch|cock|cocksuck|coon|crap|cunt|cyberfuck|damn|dick|douche|fag|faggot|fuck|fuck\s+you|fuckhole|god damn|gook|homoerotic|hore|lesbian|mother|fucker|motherfuck|motherfucker|negro|nigger|penis|penisfucker|piss|porn|pussy|retard|sex|shit|slut|son\s+of\s\s+a\s+bitch|tits|viagra|whore";


const FAIL_HONEYPOT=50001;
const FAIL_PHP_UNIT=50004;
const FAIL_WP_ENUM=50003;
const FAIL_THRIVE_KRAKEN=50005;
const FAIL_EVT_CAL=50006;
const FAIL_METHOD=50002;
const FAIL_INVALID_DOMAIN=23001;
const FAIL_RR_TOO_HIGH=26001;

const FAIL_HOST_TOO_LONG=22001;
const FAIL_HOST_IS_IP=22002;

const FAIL_FAKE_WHITELIST=24001;
const FAIL_MISS_WHITELIST=24002;
const FAIL_FAKE_BROWSER=27000;
const FAIL_IS_BLACKLIST=25001;
const FAIL_FILE_BLOCK=29001;
const FAIL_HTTP_BLOCK=33001;
const FAIL_CMS_REFERER=30001;

const BLOCK_LONG=3;
const BLOCK_MEDIUM=2;
const BLOCK_SHORT=1;
const BLOCK_NONE=0;
const BLOCK_WARN=-1;

const IPDATA_RR_1M='rr_1m';
const IPDATA_RR_5M='rr_5m';

const CONFIG_HONEYPOT='honeypot_url';
const CONFIG_METHODS='allowed_methods';
const CONFIG_WHITELIST='botwhitelist';
const CONFIG_RATE_LIMIT_ACTION='rate_limit_action';
const CONFIG_MFA_PAGES='mfa_pages';
const CONFIG_BLACKLIST='blacklist';


const AGENT_OS = 'os';
const AGENT_BROWSER = 'browser';
const AGENT_BOT = 'bot';
const AGENT_WHITELIST = 'whitelist';
const AGENT_BLACKLIST = 'blacklist';

const FAIL_DURATION = array(FAIL_HONEYPOT => BLOCK_LONG, FAIL_METHOD => BLOCK_SHORT);

const STATUS_FAIL = -1;
const STATUS_OK = 0;
const STATUS_ENOENT = 2;
const STATUS_EACCES = 13;
const STATUS_EEXIST = 17;
const STATUS_ECOM = 70;

// if we are installed in a web-accessible location, make files un-readable
if (strstr( __FILE__, $_SERVER["DOCUMENT_ROOT"]) !== false) {
    define('FILE_W', 0222);
    define('FILE_R', 0444);
}
else {
    define('FILE_W', 0664);
    define('FILE_R', 0664);
}
const FILE_RW = 0664;
const FILE_EX = 0775;

