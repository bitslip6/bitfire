=== BitFire ===
Contributors: BitSlip6, LLC
Donate link: http://bitfire.co/pricing
Tags: security, firewall, waf, malware scanner, anti-virus, antivirus, secure, virus
Requires at least: 4.0.1
Tested up to: 6.0.2
Stable tag: __VERSION__
License: AGPLv3 or later
License URI: https://www.gnu.org/licenses/agpl-3.0.en.html



== Description ==

Only patented WordPress Firewall locks your php files from malware. Complete protection from bots. Recover hacked sites. 100 MFA, SQLi, XSS, CSRF, LFI firewall  

Website security that works. Don't just scan for malware. Stop it from ever infecting your site.

BitFire integrates your website and server operating system to make website hacks, redirect attacks and account takeover impossible.

Don't just scan for attacks after they happen; actively prevent them.

There are many Web Firewalls available. Only BitFire has 100% Free bot Blocking, Site Restore, File Locking, Redirect Protection, and a money-back guarantee for PRO customers.

BitFire brings new security capabilities to your website you won't find anywhere else.
In addition to the standard Protection offered by similar solutions, BitFire has 4 unique features that, when activated, make your site impervious to attack.

* File Protection - Write Lock your files to prevent any attack from modifying your plugins or core files.
* Bot Protection - 99% of hacks are automated. BitFire blocks all automated requests and only allows approved search engines and tools.
* Redirect Protection - Prevent redirect attacks by enforcing only content from approved sites with dynamic Content Security Policy.
* Multi-Factor Authentication - Prevent account takeover with multi-factor authentication. Receive notification of all login attempts.


* Up to 50x faster than the competition
* More 0-day protections than anyone
* Full guaranteed Protection in less than 2 milliseconds.

Protect yourself from 0-day threats with security processes, not just known signatures.


== Installation ==

* Install this plugin via WordPress plugin installer.
* In your Plugin Dashboard, click "Activate Plugin."
* Click on "BitFire Admin" from wp-admin.

== Frequently Asked Questions ==

= Can BitFire block bots and automated attacks? =
BitFire's primary feature is bot blocking which is 100% functional in the free version. 99% of WordPress attacks are from automated tools scanning every domain and IP address for known vulnerabilities. BitFire verifies human web browsers with a JavaScript challenge similar to Cloudflare but over 50 times faster (1/10 second VS 6 seconds). BitFire also includes a list of over 80 search engines and SEO tools that are network verified to ensure only valid bot traffic reaches your site.

= Do I have to buy it? =
BitFire includes a complete standard firewall, malware scanning, and unbreakable bot blocking for free. Additional features, including File Write Locking, Redirect Protection, Automated Malware Recovery, and Multi-Factor Authentication, require paid PRO or PREMIUM versions. https://bitfire.co/pricing

= How does Redirection Protection work? =
Our unique software keeps track of every 3rd party domain your web page uses (Facebook, Google, JavaScript APIS, themes, etc.). After several weeks of learning, CSP security headers are sent to visitors instructing their browsers to only use or redirect to your approved domain list.

= Does BitFire prevent Cross-Site Scripting (XSS)? =
BitFire includes outstanding XSS protection, including HTTP headers and content filtering for persistent, reflected, and DOM-based XSS attacks.

= Does BitFire block SQL Injection attacks (SQLi)? =
Yes. BitFire has advanced SQL parsing similar to MySQL syntax parsing and can understand SQL queries regardless of encoding, injected comments, and other evasion techniques.

= Why shouldn't I use WordFence? =
If you use WordFence, you should only use the paid version. WordFence has a team monitoring emerging WordPress vulnerabilities and writing custom rules to block specific exploits. They are very good at it and run a great blog on their work. Paying customers receive these virtual patches as soon as they are available. Free customers receive the patches 30 days later. If your website is vulnerable, it is almost guaranteed to be hacked before the patch is available to free customers. Don't leave your site at risk.

= Why is BitFire better than WordFence? =
"Better" can be subjective. Our generic attack detection is on-par, if not better. WordFence does not have browser or bot network authentication and can not block many automated attacks. BitFire is the only WordPress plugin offing operating system integrated file-locking and browser enforced redirect protection.
We are also definitely FASTER. WordFence typically doubles page load time, adding 100-200ms to every request on typical dedicated T3 small/medium AWS servers, more for shared environments. BitFire runs under 5ms on similar AWS hardware and near 10ms on shared environments.

We believe BitFire is the only plugin that can effectively protect WordPress sites - and is the only one with a 100% money-back guarantee for paid customers (up to 12 months effective).



== Privacy / Monitoring / Data Collection ==

1. Privacy.  We take privacy very seriously.  BitFire inspects all traffic going to the webserver and takes care to filter out any potentially sensative information by replacing it with *****.  This can include information like passwords, credit card numbers, etc.  The config.ini file includes a list of common sensative field names under the "filtered_logging" section.  These fields are immediately filtered and can not be included in any logging or error reporting. You can add additional fields to filter in the config file by adding a line "filtered_logging[field_name] = true" and replacing "field_name" with the name of the desired parameter to filter.

2. BitFire includes error monitoring.  While we strive to make BitFire as robust as possible, sometimes unforeseen things happen.  BitFire includes error handler which monitors it's operation.  In the event an error is detected _only_ in the BitFire software; including during install, an alert can be sent to BitFire's developer team.  The development team monitors these errors in real time and includes fixes for any detected errors in each new release.   This feature includes sending basic server info in the error report to help diagnose the problem.  You may opt in/out on the setting page.

3. Plugin usage.  You can help the development team improve the functionaly by opting in to use the usage monitioring.  This adds an embed for google analytics to send some very basic usage information to help the development team understand which features are used by customers and how often. Default off.

4. Updates.  Four times a day BitFire will request the latest signatures from the BitFire signature API.  These signatures are sent over SSL(TLS) and encrypted specifically for each client site.

5. Malware scanning.  When bitfire scans your website for malware it creates signatures for every file on your site.  It then compares these signatures against a database of over 10 million WordPress signatures to ensure your file integrity.  To do this, BitFire will send the signature values (hashes) of every file to the bitfire malware api. In addition to this, any found differences are compared with the official WordPress code hosted at wordpress.org.  When malware is detected it's signature added to BitFire's growing malware database for improved detection.

6. PRO / PREMIUM.  The PRO version of BitFire is limited to 10,000 page views per day.  If you are using the PRO version and you regularly exceed this usage, a notice will be sent to you and BitFire requesting a license upgrade.  This data includes aproximate daily usage per domain.




== Screenshots ==

1. Malware detection and repair. Scan thousands of files in seconds. 
`/assets/malware-1.png` 

2. BitFire integrated plugin settings. 
`/assets/settings-1.png`

== Changelog ==

= 2.0.1 =
 * Implemented setup wizards and online help functions.
 * Added auto-learning exceptions for new installs to prevent possibility of false-positives..
 * Workflow and usability improvements

= 1.9.7 =
 * fixed an issue that could cause false positive when non administrators 
 were editing posts.  This check has been expanded to authors as well.
 * fixed an issue that was causing extra padding in config.ini files
 * added support for auto-discovering bots to whitelist
 * reduced the maximum size of saved blocked data

= 1.9.6 =
 * fix for WordPress source code path resolution
 * use CMS default script inclusion system for admin pages

= 1.9.5 =
 * added initial support templates for custom CMS
 * refactored escaping on MFA page

= 1.9.4 =
 * fixed an issue which could allow admin requests to be rate limited
 * refactored malware scanner to support custom CMS

= 1.9.3 =
 * added suport for redirect url on MFA login page
 * fixed issue with MFA login submission
 * added support for Content Security Policy WordPress integration
 * Wordpress MFA login support complete
 * PHP file write blocks are now logged in the dashboard

= 1.9.2 =
 * improved support for alternate content management systems
 * removed direct $_SERVER, $_GET, $_POST access and replace with filter_input
 * fixed issue that could cause malware download to fail with expired access token

= 1.9.1 =
 * improved install logging
 * additional tests for instaliation procedure

= 1.9.0 =
 * added SQL auditing feature.  Currently this is an advanced toggle only available
   by editing the config.ini.  Planned features: SQL Injection Detection, CC data 
   access, replay log for DB restores
 * namespaced all defines to prevent any possible name collisions
 * added WordPress plugin and theme enumeration blocking
 * refactored several echo lines to remove dead code and xss encode on the same line
 * added fix for a bug in php >=8.0 <= 8.1 where splat operator on variables containing :
   would be incorrectly interpreted by PHP 8.0 as a named operator.
 * added support for cloudflare real connecting IP 
 * plguins not regsitered at wordpress.org are now rolled into a single malware line

= 1.8.9 =
 * upgraded bootstrap and chart.js to latest stable releases
 * refactored all API methods to be pure and testable
 * refactored malware detection to allow detecting malware on non-WordPress installs
 * updated all WordPress path resolutions
 * added code to ensure config.ini is not web readable even when .htaccess is disabled
 * INI settings: reset realpath.cache_size to system size when used with openbase_dir
 * special handling of DOCUMENT_ROOT for WordPress
 * improvements to installing always on protection on Nginx systems
 * make config.ini unreadable even on systems that do not support .htaccess

= 1.8.6 =
 * added additional WordPress abstractions as requested by WordPress team
 * upgraded bootstrap css files
 * abstracted wordpress plugin with pure implementations and additional unit tests

= 1.8.5 =
 * refactored several functions with pure implemtations and added unit tests
 * refactored views to use new templating system
 * refactored wordpress integration to use standard plugin architecture
 * moved all dashboard javascript, image, css files into the distribution
 * removed dead code
 * removed a warning for php 8.1

= 1.8.3 =
* Added support to enable always-on from settings page
* Added support for WordPress Engine
* Fixed bug where rotating encryption keys would prevent new signatures from downloading for up to a day

= 1.8.0 =
* Improved support for PHP 8.0
* improved settings page
* improved malware scanner
* additional whitelist SEO bots
* improved auto-detection of server support

= 1.7.3 =
* First public release of BitFire WordPress security plugin

== Upgrade Notice ==

= 1.8.3 =
No incompatibilities



