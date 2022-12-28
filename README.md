
<!-- SHIELDS 
[![Discord Chat](https://img.shields.io/discord/793172132191928341)](https://discord.gg/VZ3C3bFK) 
-->
[![License](https://img.shields.io/badge/license-AGPL%203.0-blue)](https://www.gnu.org/licenses/agpl-3.0.en.html)
[![Issues](https://img.shields.io/github/issues/bitslip6/bitfire)](https://github.com/bitslip6/bitfire) 
[![Maintainability](https://api.codeclimate.com/v1/badges/0a9a35bf6e0378820811/maintainability)](https://codeclimate.com/github/bitslip6/bitfire/maintainability)
[![PHP Ver](https://img.shields.io/badge/php->=7.1-blue)](https://php)
[![Slack Chat](https://img.shields.io/badge/slack-3%20online-blue)](https://join.slack.com/t/bitslip6/shared_invite/zt-l7gxmgc3-9T0QFNP6GN4IFPOVtZGJrQ)
 
<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://bitfire.co/">
    <img src="firewall/views/bitslip.png" alt="Logo" width="80" height="80">
  <h2 align="center">BitFire RASP Firewall for PHP</h2> </a>


  <p align="center">
enterprise class security for everyone
    <br />
    <a href="https://bitfire.co/bitfire-install"><strong>BitFire Install Guide »</strong></a>
    <br />
    <br /><!--
    <a href="https://github.com/othneildrew/Best-README-Template">View Demo</a>
    ·
    -->
    <a href="https://github.com/bitslip6/bitfire/issues">Report Bug</a>
    ·
    <a href="https://github.com/bitslip6/bitfire/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About BitFire</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## Runtime Application Self Protection firewall for PHP

<p align="center">
<a href="http://www.youtube.com/watch?feature=player_embedded&v=kX1Z9qHrS6Y
" target="_blank"><img src="http://img.youtube.com/vi/kX1Z9qHrS6Y/0.jpg" 
alt="BitFire Intro Video" width="540" height="420" border="0" /></a>
</p>


BitFire is a Runtime Application Self Protection ( RASP) based firewall for PHP servers. BitFire's RASP for PHP works differently than a traditional Web Application Firewall (WAF), by providing a security sandbox for all database and filesystem access, BitFire can prevent malware infections *and* account takeover for vulnerable plugins, themes and custom PHP code, regardless of of the stack.


#### Prevent all malware infections with FileSystem RASP

**Consider the following PHP vulnerability:**
This vulnerability allows uploading or overwriting any PHP file.

```php
<?php
file_put_contents($_GET['filename'], $_GET['content']);
```

BitFire's RASP filesystem sandbox runs for all non-administrator users and will intercept this file write, and check both `$_GET['filename']` and  `$_GET['content']` for any attempt to access a php file. When detected the malware infection fails and a blocking page is immediately displayed.

*BitFire natively understands WordPress administrators, and you can add support for any CMS by implementing this simple function:*
```php
namespace BitFire\Plugin

function is_admin() : bool {
  if (my_custom_acl_check($_COOKIE)) { 
    return true;
  }
  return false;

  // OR simply: 
  return my_custom_acl_check();
}
```

#### Prevent Privilege Escalation with Database-RASP

Hacker's exploit security vulnerabilities to create backdoor administrator accounts. These accounts are then used later to install malware or other spam content. BitFire secures this vulnerability by inspecting all database updates and checking for privilege escalation.

**Consider the following wordpress vulnerability:**
This vulnerability can allow an attacker to set privilege level to any value including "administrator" without any verification.
```php
$user = get_current_user();
$user->setRole($_GET['user_role']);
```

 When the BitFire Database sandbox inspects the underlying database update, it will compare the user privilege being set against the the user privilege making the change. If the user does not have the permission to grant administrator access, the database write is denied and a block page is served to the user.

BitFire comes pre-configured for popular CMS's including WordPress, Joomla and Drupal.

***You can implement your own database checks as well:***

```php
QueryBlockList::new("table_name", "insert/update/delete", ["matching", "query", "criteria"], 'privilege_check_function');
```

This would trigger on any update of the table_name table with matching criteria to authenticate the SQL query using the PHP function privilege_check_function().

***Example query blocked:***
```sql
UPDATE table_name SET wp_capabilities = 'a:1:{s:13:"administrator";b:1;}' WHERE umeta_id = 20;
```

#### Prevent Automated Bot Access with RASP-Bot-Protect

99% of web attacks come from automated scripts. BitFire RASP protects your site from automated attacks in 2 ways. First, it allows good bots like google and bing by authenticating their network origin. Google bot only connects from google owned IP addresses, and bing from Microsoft. BitFire has a list of over 150 known and approved bots, SEO tools and their origin networks.

Second, for web browsers like Chrome, Safari, etc, BitFire sends a transparent JavaScript challenge. This JavaScript challenge takes only milliseconds to complete and verifies that the client is a real browser and not a hacking tool. This way your website only sees the verified browser traffic. This is similar to Cloudflare's Super Bot Fight Mode.

** **

![BitFire Screen Shot](https://bitfire.co/assets/img/dash_1b.webp)

Here's How BitFire is different:
* ![speed](https://fonts.gstatic.com/s/i/materialicons/speed/v6/24px.svg) Speed. <2 ms block times - BitFire is up to 100x faster than the most popular PHP Firewalls
* ![bot](https://fonts.gstatic.com/s/i/materialicons/dns/v6/24px.svg) Bot authentication. Authenticates good bots like google, facebook, bing, ahrefs, by source network
* ![browser](https://fonts.gstatic.com/s/i/materialicons/computer/v6/24px.svg) Browser verification. Transparent JavaScript browser verification ensures user's are real
* ![browser](https://fonts.gstatic.com/s/i/materialicons/policy/v6/24px.svg) Client Integrity. Automatically generate browser policy preventing browser takeover
* ![browser](https://fonts.gstatic.com/s/i/materialicons/lock/v6/24px.svg) Server Integrity. Authenticated file access prevents server code modification 
* ![browser](https://fonts.gstatic.com/s/i/materialicons/text_rotation_none/v6/24px.svg) Grammar based firewall.  Parses SQL, HTTP, HTML for the most accurate blocking


### Built With

BitFire is built from pure PHP and has no external dependencies.  BitFire can take advantage of several PHP shared memory caches including APCu, SHM, shmop and OpCache
* [PHP](https://php.com)
* [TinyTest](https://github.com/bitslip6/tinytest)



<!-- 
## Getting Started

Security from F to A in 5 minutes https://www.youtube.com/watch?v=DHhEW2otdng
Install Guide: https://bitfire.co/bitfire-install
GETTING STARTED -->

### Prerequisites

You will need: a web-server (apache, nginx), PHP >= 7.1, a login, and a text editor.


### Installation

- *Install via GitHub*
   ```sh
   git clone https://github.com/bitslip6/bitfire.git
   add: auto_prepend_file = "/path/to/bitfire/startup.php" to root .user.ini file
   ```
- or *Install via Composer*
   ```
   composer require bitslip6/bitfire
   add: auto_prepend_file = "/path/to/bitfire/startup.php" to root .user.ini file
   ```
- *Bitfire is now installed!* Open the configuration wizard to enable the firewall by visiting /bitfire/startup.php in your web browser. If you installed BitFire outside your web_root, you can access the dashboard by visiting the url /bitfire-admin which is defined in /bitfire/config.ini.

- **Congratulations! Time for a beer**



Detailed configuration and installation is available on our [Support Center](https://bitfire.co/support-center)



<!-- SETUP -->
## Setup / Configuration Quick-start

The default configuration is very conservative and will only block bots identifying themselves as malicious scripts. The configuration is stored in `config.ini` in the BitFire home directory (for composer: vendor/bitslip6/bitfire/config.ini)

Now visit your website at path "your_domain.com/bitfire_dashboard"
enter the password when prompted, then click on "Settings" and configure the settings you want to use.

On first page view BitFire will auto configure itself for your server and rarely needs to be adjusted.


#### Feature flags support 3 values:
 - *false*: disable the feature
 - *report*: don't block the traffic but add an entry to the report_file (config.ini setting)
 - *block*: block the request, server response_code (config.ini) from views/block.php
 we recommend beginning with _report_ and then moving to *block* only after verifying that you would not be blocking good traffic.  https://github.com/bitslip6/bitfire/wiki/block_reporting for details.
 


*1*. Require full browser.  If your website uses JavaScript and cookies (99% of all websites) you can
require all web browers to prove they support both by enabling *require_full_browser*.  Since >95% of
all exploit scripts and worms do not support JavaScript or cookies this is the single best protection
you can install to prevent breakins.  This cookie is non user-identifying and so is fully GDPR compliant
and does not require a GDPR notification.
```ini
require_full_browser = report | block
```


*2*. Enable bot whitelist.  Futher limit bots by allowing only verified whitelisted robots.  A preconfigured
list of common bots included with BitFire.  Refer to our wiki for how to add additional bots.
```ini
whitelist_enable = report | block
```

*3*. Enable core web filters.  The web filter blocks malicious requets like XSS, LFI, RCE and SQLi as well as many others.
The entire web filter can be enabled or disabled with the *web_filter_enabled* parameter.  We recommend
the following configuration:
```ini
web_filter_enabled = report | block
xss_block = report | block
web_block = report | block
file_block = report | block
sql_block = report | block
```

*4*. Enable IP blocking.  By default BitFire will not black list IP addresses.  We recommend you enable this feature which allows for the fastest possbile drop of HTTP floods.
```ini
allow_ip_block = true
```



_For detailed documentation, please refer to the [Documentation](https://github.com/bitslip6/bitfire/wiki)_



<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/bitslip6/bitfire/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Additions to the bot whitelist and additional attack signatures or bypasses are greatly appreciated.  If your contributions are included you will recieve discounts on comercial licencing for BitFire Pro.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the Apache 2.0 License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

Cory - [@bitslip6](https://twitter.com/bitslip6) - info@bitslip6.com

Project Link: [https://github.com/bitslip6/bitfire](https://github.com/bitslip6/bitfire)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [Img Shields](https://shields.io)
* [Font Awesome](https://fontawesome.com)
* [Bootstrap](https://getbootstrap.com)
* [Icons by freepik](https://www.flaticon.com/authors/freepik)
* [IP2Location](http://lite.ip2location.com)
