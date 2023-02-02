=== BitFire Security - RASP Firewall & Malware Cleaner ===
Contributors: BitSlip6, LLC
Donate link: http://bitfire.co/pricing
Tags: security, firewall, malware scanner, waf, rasp, anti-virus, antivirus, secure, virus, hacked, authentication, backups
Requires at least: 4.0.1
Tested up to: 6.1.1
Stable tag: 3.6.5
Requires PHP: 7.1
License: AGPLv3 or later
License URI: https://www.gnu.org/licenses/agpl-3.0.en.html

Best RASP firewall for WordPress. Stop malware, redirects, back-doors and account takeover. 100% bot blocking, backups, malware cleaner.

== Description ==

### DON'T JUST SCAN FOR MALWARE. PREVENT IT INFECTING YOUR SITE. ###

Protect yourself from 0-day threats with security processes, not just signatures.

*Infected with malware?*
BitFire malware scanner has one of the highest malware detection rates in the industry.
Most malware scans take less than 60 seconds. See the data:
**[WordPress Malware Detection Rates vs WordFence](https://medium.com/@cory_67329/wordpress-malware-removal-product-comparison-top-5-4d53c60c65eb#707a)

*Complete Bot protection*
Automated scanning tools make up 99.99% of all WordPress hacks.
BitFire is the only WordPress security plugin that tracks every bot on your website.
We compare each bot visit against a list of 600 known good bots and only allow them if their IP address is valid. 
This prevents hackers from impersonating good bots like GoogleBot and bypassing your security.
See every bot accessing your site and approve or deny it.

*Integrated human verification*
BitFire integrates a free human verification system that validates your visitors are real humans.
Using integrated JavaScript, humans can only access your website after answering a JavaScript challenge.
This works similar to cloudflair human verification but is much faster, usually < 100 milliseconds.

Human verification is important to block hackers since many automated hacking tools impersonate
web browsers. BitFire stops all of these from accessing your website.

*Runtime Application Self Protection*
BitFire is the only RASP firewall for WordPress.
*[How RASP works from checkpoint](https://www.checkpoint.com/cyber-hub/cloud-security/what-is-runtime-application-self-protection-rasp/)
Integrated directly with WordPress and your webserver, bitfire stops malware before it can infect your site.

*RASP File Protection*
File-Protection runs anytime a PHP file is attempted to be modified on your server.
BitFire intercepts the write and verifies that a valid site administrator is modifying the file and not a hacker.
This prevents any malware from infecting your site  even if the firewall missed it.

*RASP Database Protection*
Database-Protection monitors SQL queriers to your WordPress database.
Anytime data is attempted to be modified BitFire inspects the tables being updated.
If the query is attempting to create a new user or update permissions to administrator level,
BitFire will block the query unless the user is logged in as an administrator.

This defeats any attempt by hackers to install backdoor accounts onto your server.

*RASP Network Protection*
Last, BitFire RASP intercepts all network requests from your webserver to the Internet.
BitFire blocks all Server Side Request Forgery attempts, stops all Time Of Use, Time of Check attacks (TOUTOC) and prevents your server from talking to a malware command and control servers.


#### Comparison with WordFence ####
WordFence is the most popular choice for WordPress security.  How does BitFire compare to the market leader?  **[WordFence VS BitFire](https://bitfire.co/EN/wordfence-vs-bitfire)**

== Screenshots ==

1. BitFire shows detailed graphs about the type of attacks your website is defending.
2. Bot Control page allows instant authenitcation of over 600 known bots.
3. Detailed malware scanner contains over 20 million data-points and scans 10,000 PHP files per minute.
4. View detailed block and alerting information about each request, add blocking exceptions with a single click.
5. Database malware scanner with backup and restore points can identify malware comments and posts from over 2.5 million domains.
6. Plugin monitoring alerts you within the hour when new plugin vulnerabilities effecting your site are released so you can stay on top of important security updates.
7. Simple on/off configuration with granular rules can be set to alert to test new rules before actually blocking.



#### Core Features ####
* **[Runtime Application Self-Protection](https://en.wikipedia.org/wiki/Runtime_application_self-protection)** prevents the most severe vulnerabilities from being exploited. (PHP file modification, Admin account creation, Redirects, etc).
* **Bot Blocking** stops 99.99% of attacks. Transparent CAPTCHA and Network verification prevent vulnerability scanners from accessing any part of your site.
* **Malware Scanner** Scan your website for existing malware at over 10,000 files per minute and access our offline database with over 10 million data-points.
* **Plugin vulnerability monitoring**. Hourly checked over a dozen vulnerability databases against your installed plugins to notify you if any of your themes or plugins have known vulnerabilities.
* **Free Off-site Database Backups**. Because plugins can be re-installed, but your content can not.
* **WAF firewall**. Of course we have all of the Firewall features you know and expect from any security product including protecting from **XSS**, **SQLi**, **LFI/RFI**, **XXE**, **SSRF**, **CSRF**, **Directory Traversal**, **Insecure Deserialization**, **OS Command Injection**, **PHP File Upload** and many more.
* **Simple configuration** on/off security settings makes setup easy.
* **SMS based multi-factor authentication** secures your accounts without the need of installing any new software.
* **Monitor** every block and alert in realtime from your dashboard.
 
### Runtime Application Self Protection ###
BitFire is the first [RASP][1] security solution available for WordPress. Previously only available with $50,000 security installs from companies like [Imperva][2] (NYSE: IMPV) and [Signal Sciences][3] (NYSE: FSLY), RASP systems monitor your application's actions adding additional security checks along the way.
[1]: https://techbeacon.com/security/what-runtime-application-self-protection-rasp "RASP from TechBeacon"
[2]: https://www.imperva.com/products/runtime-application-self-protection-rasp/ "Imperva RASP'
[3]: https://www.signalsciences.com/products/rasp-runtime-application-self-protection/ "RASP from Signal Sciences"


BitFire monitors all important system actions on your site like writing files, editing wordpress users, credential and privilege changes, network connections, and checking access controls. When any of these functions happen (or don't happen the case of access controls), BitFire runs checks like the following:

* **Adding a new administrator account?** BitFire checks that the current user has the administrator privilege before allowing the account creation.
* **Making a network connection?** BitFire checks the remote system against a list of over 2.5 million malware domains before allowing the connection.
* **Adding or editing a file?** BitFire inspects the filename and content to ensure that it does not edit a PHP file or inject backdoor code. 
* **Redirecting the visitor to another website?** First check the malware domain list before sending the redirect.
* **Is a plugin eval() dynamic PHP Code?** Inspect the code being passed to eval() and block malicious code before executing it.

These features protect vulnerable plugins and themes from the most common and severe vulnerabilities. They are only available with integration of the Operating System and WordPress core actions. Traditional WAFs only look at the request and either  pass it to WordPress or block it. They have no idea what WordPress did after they allowed the request. That's what makes RASP systems unique.

### High Performance (< 1ms per request) ###

Our unique approach to security allows us to run 50-100x faster than our most popular competitors. Because our RASP checks never happen during normal website operation you get blazing fast performance. BitFire only runs RASP checks when security sensitive operations happen (such as adding a new user account, editing a file, activating a plugin, etc). This means that most traffic does not ever need to be inspected for these types of attacks so your website stays just as performant after adding RASP as before. 

### Complete Bot Blocking Tops Hackers Fast ###

**99.99% of web attacks are completely automated** and run en-mass. These scanners are equipped to scan for and exploit 1 or more known security vulnerabilities. They then scan the entire Internet looking for vulnerable systems to compromise. 

BitFire stops these automated attacks completely in 2 ways. Each web client has a unique identifier called a "user-agent". Chrome, Safari, Edge and Firefox all have unique user-agents that tell websites who they are. Hackers often use these user-agents to hide their malicious scanners as normal web traffic. BitFire stops these attacks by sending a transparent JavaScript challenge to anyone that claims to be a web browser that only real browsers can solve. The challenge takes less than 100 milliseconds to complete (one network round trip + 2ms) and only happens on the first page load for a browser. Normal humans then browse the site as usual and malicious scanners are stopped before they they can even access the homepage.

The second type of user-agents are what are called "robots". These are often helpful robots like GoogleBot, Bing, AHrefs, SEOMoz and many others which index your website making it searchable or providing additional services. Hackers will often disguise their scanners as helpful bots like GoogleBot to avoid security systems. BitFire stops these malicious attacks by verifying the host network of the bot. For example, bots claiming to be GoogleBot are only allowed to access the site without JavaScript challenges if the source network is the Google campus. We have over 100 helpful web crawlers and scanners in our default approved database of robots so your site allows the good robots while keeping out the bad.


### Scan for malware in seconds ###

<img src="https://bitfire.co/assets/malware_strip.jpg" alt="malware header image">

We believe so strongly that BitFire will prevent any malware infecting your site, we didn't build a malware scanner for years. Only after several infected sites not running BitFire found us and asked for help did we decide to build a malware scanner for clients who might be infected before installing BitFire.  

BitFire **scans PHP files at a rate over 10,000 per minute**. Most websites complete a full malware scan in under 45 seconds. We use a 3 step process to achieve the fastest malware scans possible.

1. A combination of intelligent file hashing and offline malware databases identify potentially modified or injected files.
2. Candidate files are then scanned for dangerous, dynamic or malicious functions or actions.
3. Remaining files are then feed through character frequency analysis, and deep learning to remove common programmer design patterns and other false positives.

**What is reported is a highly accurate list of found malware with a false positive rate of 1 in 10,000**.

### WHY HAVEN'T I HEARD OF YOU BEFORE? ###

The BitFire firewall was started as a custom security solution in 2018 for a
small group of WordPress sites by Cory Marsh. Bringing his 20 years of 
enterprise security knowledge and software architecture experience to create the first RASP for WordPress. We had a vision of bringing real enterprise 
grade security solutions to the millions of websites running WordPress. After 
almost 4 years of development and countless late nights we are finally ready 
to offer the highest quality security product available to the WordPress 
community at large. We receiving initial funding in late 2022 we are now officially launching!



== Installation ==

* Install this plugin via WordPress plugin installer.
* In your Plugin Dashboard, click "Activate Plugin."
* Open the BitFire Settings from your WordPress admin dashboard.  Complete the setup wizard.
* Run a malware scan from the BitFire malware menu and verify your site files are 100% clean.
* Run a database malware scan to ensure your content does not have any links to over 2.5 million malware sites.
* Monitor your firewall blocking on the BitFire Dashboard page

== Frequently Asked Questions ==

= If other security plugins live up to their hype, why do they scan my site for malware daily? =
That's an excellent question. The majority of popular security plugins create custom signatures for each WordPress plugin vulnerability as they are publicly disclosed. With over 10,000 known WordPress security vulnerabilities and less than 200 signatures, they miss blocking a lot of hacks. They are also unable to block the most common security flaws (access control errors) for anything they do not have a pre-built signature for. To make the situation more difficult, they delay these rules by up to a month for non-paying customers.

= Can BitFire block bots and automated attacks? =
BitFire's primary feature is bot blocking which is 100% functional in the free version. 99% of WordPress attacks are from automated tools scanning every domain and IP address for known vulnerabilities. BitFire verifies human web browsers with a JavaScript challenge similar to Cloudflare but over 50 times faster (1/10 second VS 6 seconds). BitFire also includes a list of over 80 search engines and SEO tools that are network verified to ensure only valid bot traffic reaches your site.

= Do I have to buy it? =
BitFire includes a complete standard firewall, malware scanning, vulnerability detection offsite database backup and unbreakable bot blocking for free. Our patented RASP technology and SMS based 2FA is only available to our paying PRO and PREMIUM clients.  https://bitfire.co/pricing


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
We are also definitely FASTER. WordFence typically doubles page load time, adding 100-200ms to every request on typical dedicated T4 small/medium AWS servers, more for shared environments. BitFire runs under 5ms on similar AWS hardware and near 10ms on shared environments.

We believe BitFire is the only plugin that can effectively protect WordPress sites - and is the only one with a 100% money-back guarantee for paid customers (up to 12 months effective).



== Privacy / Monitoring / Data Collection ==

1. Privacy.  We take privacy very seriously. BitFire inspects all traffic going to the webserver and takes care to filter out any potentially sensitive information by replacing it with ***redacted***. The config.ini file includes a list of common sensitive field names under the "filtered_logging" section. You can add additional fields to filter in the config file by adding a line "filtered_logging[field_name] = true" and replacing "field_name" with the name of the desired parameter to filter.

2. BitFire includes an error handler which monitors it's operation. In the event an error is detected _only_ in the BitFire software; including during install, an alert can be sent to BitFire's developer team. The development team monitors these errors in real time and includes fixes for any detected errors in each new release.

3. Updates. Four times a day BitFire will request the latest signatures from the BitFire signature API. These signatures are sent over SSL(TLS) and encrypted specifically for each client site. In addition bitFire also sends a list of installed plugins and version numbers to compare against recently posted security vulnerabilities.




== Changelog ==

= 3.7.1 =
 * reduce malware false positives
 * added detection for image include malware
 * improved machine learning dataset
 * added __wakeup() handlers for all classes with magic methods to prevent inclusion in POP chain
 * improved bot listing formatting to support longer data formats
 * better handling of some server temporary failures (filesystem, network, etc)

= 3.6.4 =
 * improved malware detection
 * improved support for some smaller hosting providers
 * improved bot authentication during learning

= 3.6.3 =
 * various PHP warning fixes

= 3.6.2 =
 * Improve support for WordPress installs in path sub directory
 * Performance improvement for user capability check
 * Small warning fixes for PHP 8.1

= 3.6.1 =
 * New bot control management page
 * Improved settings and RASP configuration
 * Improved upgrade process to keep all config data between upgrades, re-installs
 * New hidden (secret) file support for nginx without modifying file permissions
   (configuration data is now stored in a random hashed directory)
 * Small bug fixes on malware scanning for files in root directory
 * Improved support for PHP 7.2

= 3.5.3 =
 * Added over 600 known bots with network identification
 * Improved malware scanning support for unknown files
 * Added additional scan locations
 * Added JavaScript malware scanning

= 3.0.8 =
 * Database Malware Scanner Support
 * Offsite database backups
 * Fixes for some apache server installs
 * Support for malware scanning plugins off the WordPress repository
 * Added support and small fixes for PHP 8.1
 * Improved malicious file upload scanning
 * Improved basic settings and advanced settings page

= 3.0.6 =
 * Added a pretty error page for browsers that do not support JavaScript when JavaScript verification is enabled.

= 3.0.4 =
 * Minor bug fixes for corner cases

= 3.0.1 =
 * Added database malware scanning support for over 2.5 million domains


= 2.3.5 =
 * improved configuration wizard and css styles

= 2.3.4 =
 * Malware Scanner Support 
 * Fixed a bug in browser verification on mobile safari.

= 2.3.3 = 
 * Added CSS styles to the blocking page

= 2.1.2 =
 * Added plugin vulnerability notifications.  These will check over 3500 active CVE advisories 
 for any known security issues in your plugins or themes
 * Improved upgrade process which could forget some settings on upgrade
 * Fixed a possible rare false positive on base64 encoded data
 * Improved learning mode to find more false positives 
 * Fixed a warning on PHP 8.x with undefined variable for alerts from IPs with no associated country 
 (localhost)
 * Fixed a bug which incorrectly reported the currently viewed alert page number range on the dashboard screen

= 2.1.0 =
 * Several bug fixes
 * Improvements to malware scanning, added additional files to scan list
 * Fixed bug adding additional allowed domains on settings page 

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
 * added support for redirect url on MFA login page
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
 * additional tests for installation procedure

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
 * plugins not registered at wordpress.org are now rolled into a single malware line

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
 * refactored several functions with pure implementations and added unit tests
 * refactored views to use new template system
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

= 3.0.8 =
No incompatibilities





