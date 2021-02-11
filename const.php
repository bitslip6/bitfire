<?php
namespace BitFire;

const FEATURE_CLASS = array(0 => 'require_full_browser', 10000 => 'xss_block', 11000 => 'web_block', 12000 => 'web_block', 13000 => 'web_block', 14000 => 'sql_block', 15000 => 'web_block', 16000 => 'web_block', 17000 => 'web_block', 18000 => 'spam_filter_enabled', 20000 => 'require_full_browser', 21000 => 'file_block', 22000 => 'web_block', 23000 => 'check_domain', 24000 => 'whitelist_enable', 25000 => 'blacklist_enable', 26000 => 'rate_limit', 50000 => '');

const BITFIRE_API_FN = array('\\BitFire\\get_block_types', '\\BitFire\\get_valid_data', '\\BitFire\\get_ip_data', '\\BitFire\\get_hr_data', '\\BitFire\\make_code');
const BITFIRE_METRICS_INIT = array('challenge' => 0, 'valid' => 0, 10000 => 0, 11000 => 0, 12000 => 0, 13000 => 0, 14000 => 0, 15000 => 0, 16000 => 0, 17000 => 0, 18000 => 0, 19000 => 0, 20000 => 0, 21000 => 0, 22000 => 0, 23000 => 0, 24000 => 0, 25000 => 0, 26000 => 0, 70000 => 0);
const BITFIRE_VER = 123;
const BITFIRE_DOMAIN = "http://api.bitslip6.com";
const BITFIRE_INTERNAL_PARAM = '_bitfire_p';
const BITFIRE_COMMAND = "BITFIRE_API";

const BITFIRE_MAX_HASH_COUNT = 20;
const BITFIRE_MAX_AUDIT = 20;
const BITFIRE_MAX_PAGES = 200;
const WAF_MIN_HIT = 25;
const WAF_MIN_PERCENT = 10;

const CONFIG_REPORT_FILE='report_file';
const CONFIG_BLOCK_FILE='block_file';
const CONFIG_DASHBOARD_PATH='dashboard_path';
const CONFIG_WHITELIST_ENABLE='whitelist_enable';
const CONFIG_BLACKLIST_ENABLE='blacklist_enable';
const CONFIG_REQUIRE_BROWSER = 'require_full_browser';
const CONFIG_USER_TRACK_COOKIE = 'browser_cookie';
const CONFIG_MAX_CACHE_AGE = 'max_cache_age';
const CONFIG_USER_TRACK_PARAM = 'bitfire_param';
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

const BITFIRE_INPUT = '_bitfire';

const THROTTLE_LOCK_TIME = 600;
const THROTTLE_LOCK_FILE = ".bitfire.lock";

const FAIL_NOT = 0;

const PROFANITY = "anal|anus|arse|ass|asss|bastard|bitch|cock|cocksuck|coon|crap|cunt|cyberfuck|damn|dick|douche|fag|faggot|fuck|fuck\s+you|fuckhole|god damn|gook|homoerotic|hore|lesbian|mother|fucker|motherfuck|motherfucker|negro|nigger|penis|penisfucker|piss|porn|pussy|retard|sex|shit|slut|son\s+of\s+a\s+bitch|tits|viagra|whore";


const FAIL_HONEYPOT=50001;
const FAIL_PHPUNIT=50004;
const FAIL_WP_ENUM=50003;
const FAIL_METHOD=50002;
const FAIL_INVALID_DOMAIN=23001;
const FAIL_RR_TOO_HIGH=26001;

const FAIL_HOST_TOO_LONG=22001;

const FAIL_FAKE_WHITELIST=24001;
const FAIL_MISS_WHITELIST=24002;
const FAIL_IS_BLACKLIST=25001;

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
