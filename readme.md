
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
    <img src="views/bitslip.png" alt="Logo" width="80" height="80">
  <h3 align="center">BitFire</h3> </a>


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
## About BitFire

![BitFire Screen Shot](https://bitfire.co/assets/img/dash_1.webp)

There are many choices for PHP firewalls to protect your webservers, most can be easily bypassed.

Here's How BitFire is different:
* ![speed](https://fonts.gstatic.com/s/i/materialicons/speed/v6/24px.svg) Speed. <1 ms block times - BitFire is up to 100x faster than the most popular PHP Firewalls
* ![bot](https://fonts.gstatic.com/s/i/materialicons/dns/v6/24px.svg) Bot authentication. Authenticates good bots like google, facebook, bing, ahrefs, by source network
* ![browser](https://fonts.gstatic.com/s/i/materialicons/computer/v6/24px.svg) Browser verification. Transparant JavaScript browser verification ensures user's are real
* ![browser](https://fonts.gstatic.com/s/i/materialicons/policy/v6/24px.svg) Client Integrity. Automatically generate browser policy preventing browser takeover
* ![browser](https://fonts.gstatic.com/s/i/materialicons/lock/v6/24px.svg) Server Integrity. Prevent atackers from modifying server files with Operating System locks
* ![browser](https://fonts.gstatic.com/s/i/materialicons/text_rotation_none/v6/24px.svg) Grammer based firewall.  Parses SQL, HTTP, HTML for the most accurate blocking


### Built With

BitFire is built from pure PHP and has no external dependencies.  BitFire can take advantage of several PHP shared memory caches including APCu, SHM, shmop and OpCache
* [PHP](https://php.com)
* [TinyTest](https://github.com/bitslip6/tinytest)
* [APCu](https://pecl.php.net/package/APCU)



<!-- GETTING STARTED -->
## Getting Started

Security from F to A in 5 minutes https://www.youtube.com/watch?v=DHhEW2otdng
Install Guide: https://bitfire.co/bitfire-install

### Prerequisites

You will need: a webserver (apache, nginx), PHP >= 7.1, a login, text editor, sudo access to edit php.ini.


### Installation

- *Install via GitHub*
   ```sh
   git clone https://github.com/bitslip6/bitfire.git
   ./bitfire/updatekeys.sh
   ```
- or *Install via Composer*
   ```
   composer require bitslip6/bitfire
   ./vendor/bin/updatekeys.sh
   ```
- be sure to allow updatekeys to install in your fpm and apache php.ini files when prompted.

- *Bitfire is now installed!* The default config will not block anything until enabled.  set *_bitfire_enabled_* in `config.ini` and see the quickstart in this readme.
   ```ini
   bitfire_enabled = true;
   ```
- Congratulations! Time for a beer

- You may also install by-hand. set *_config.ini.php_* and *_cache_* to web writeable, update *_encryption_key_* and *_secret_* in config.ini then, 
in php.ini update auto_prepend_file 
```ini 
auto_prepend_file ='/full/path/to/bitfire/startup.php';
```

Detailed configuration is available on our [Wiki](https://github.com/bitslip6/bitfire/wiki)


<!-- SETUP -->
## Setup / Configuration Quickstart

The default configuration is very conservative and will only block
bots identifying themselves as malicious scripts. The configuration is stored in `config.ini` in the BitFire
home directory (your github checkout location, or for composer vendor/bitslip6/bitfire/config.ini)

#### Feature flags support 3 values:
 - *false*: disable the feature
 - *report*: don't block the traffic but add an entry to the report_file (config.ini setting)
 - *block*: block the request, server response_code (config.ini) from views/block.php
 we recommend beginning with _report_ and then moving to *block* only after verifying that you would not be blocking good traffic.  https://github.com/bitslip6/bitfire/wiki/block_reporting for details.
 

*1*. First setup your in-memory cache type.  BitFire stores server state in memory for fast response 
time and supports all PHP in memory caches. We preefeer in order: *shmop*, *apcu* .  If you
are unsure which cache your server supports, see php_info() output.  Look for "shmop", and "apcu"
and set *_cache_type_* in `config.ini` to your chosen cache or 'nop' for no cache.


*2*. Next configure a browser honey pot.  Set *_honeypot_url*_ in `config.ini` to anything you like, 
or leave the default.  Malicious bots looking for secure areas of your site will read this, request
the url and get banned for 24 hours.  Good bots will respect the Disallow and not be effected. Add 
your url to your robots.txt file:
```ini
honeypot_url = '/not_important/contact'
```

```ini
User-agent: *
Disallow: /not_important/contact
```


*3*. Require full browser.  If your website uses JavaScript and cookies (99% of all websites) you can
require all web browers to prove they support both by enabling *require_full_browser*.  Since >95% of
all exploit scripts and worms do not support JavaScript or cookies this is the single best protection
you can install to prevent breakins.  This cookie is non user-identifying and so is fully GDPR compliant
and does not require a GDPR notification.
```ini
require_full_browser = report | block
```


*4*. Enable bot whitelist.  Futher limit bots by allowing only verified whitelisted robots.  A preconfigured
list of common bots included with BitFire.  Refer to our wiki for how to add additional bots.
```ini
whitelist_enable = report | block
```

*5*. Enable core web filter.  The web filter blocks malicious requets like XSS, LFI, RCE and SQLi as well as many others.
The entire web filter can be enabled or disabled with the *web_filter_enabled* parameter.  We recommend
the following configuration:
```ini
web_filter_enabled = report | block
xss_block = report | block
web_block = report | block
file_block = report | block
sql_block = report | block
```

*6*. Enable IP blocking.  By default BitFire will not black list IP addresses.  We recommend you enable this feature which allows for the fastest possbile drop of HTTP floods.
```ini
allow_ip_block = true
```



_For detailed documentation, please refer to the [Documentation](https://github.com/bitslip6/bitfire/wiki)_



<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/bitslip6/bitfire/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Additions to the bot whitelist and additional attack signatures or bypasses are **greatly appreciated**.  If your contributions are included you will recieve discounts on comercial licencing for BitFire Pro.

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
