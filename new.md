
<!-- SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
-->
[![Issues][issues-shield]][issues-url]
[![Apache 2.0 License][license-shield]][license-url]



<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/bitslip6/bitfire">
    <img src="views/bitslip.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">BitFire</h3>

  <p align="center">
Enterprise class security for everyone
    <br />
    <a href="https://github.com/bitslip6/bitfire/wiki"><strong>Explore the docs »</strong></a>
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

[![BitFire Screen Shot][product-screenshot]](https://example.com)

There are many choices for PHP firewalls to protect your webservers, 90% can be easily bypassed.

Here's How BitFire is different:
* Speed. <1 ms block times - BitFire is up to 200x faster than the competition
* Bot authentication. Verifies allowed bot network origin and blocks all invalid bots
* Browser verification. Transparant JavaScript browser verification ensures user's are real
* Client Integrity. Automatically generate browser policy preventing browser takeover
* Server Integrity. Prevent atackers from modifying server files with Operating System locks


### Built With

BitFire is built from pure PHP and has no external dependencies.  BitFire can take advantage of several PHP shared memory caches including APCu, SHM, shmop and OpCache
* [PHP](https://php.com)
* [TinyTest](https://github.com/bitslip6/tinytest)
* [APCu](https://pecl.php.net/package/APCU)



<!-- GETTING STARTED -->
## Getting Started

Security from F to A in 5 minutes https://www.youtube.com/watch?v=DHhEW2otdng

### Prerequisites

You will need a webserver running PHP >= 7.1, a login, sudo access to edit php.ini and a text editor.


### Installation

1. Clone the repo *OR* install via composer
   ```sh
   git clone https://github.com/bitslip6/bitfire.git
   composer require bitslip6/bitfire
   ```
2. Install.  The update script will create new encryption keys and will prompt to add bitfire your php.ini files.
   ```
   bitfire/updatekeys.sh
   or for composer:
   vendor/bin/updatekeys.sh
   ```
3. *Optional.*  Hand install.  Edit bitfire/config.ini and change: *_encryption_key_* and *_secret_*.  
Edit your php.ini file (/etc/php/7.4/fpm/php.ini or similar) and set 
```ini 
auto_prepend_file ='/full/path/to/bitfire/startup.php';
```

4. Bitfire is now installed. The default config will not block anything until enabled.  set *_bitfire_enabled_* in `config.ini`
   ```ini
   bitfire_enabled = true;
   ```
5. congradulations!  BitFire is installed.



<!-- SETUP -->
## Setup / Configuration Quickstart


All BitFire settings are optional.  The default config is very conservative and will only block
bots identifying themselves as malicious scripts. The configuration is stored in `config.ini` in the BitFire
home directory (your github checkout location, or for composer vendor/bitslip6/bitfire/config.ini)

1. First setup your in-memory cache type.  BitFire stores server state in memory for fast response 
time and supports all PHP in memory caches. We preefeer in order: *shm*, *apcu*, *shmop*.  If you
are unsure which cache your server supports, see php_info() output.  Look for "shm", "apcu" and "shmop"
and set *_cache_type_* in `config.ini` to your chosen cache or 'nop' for no cache.


2. Next configure a browser honey pot.  Set *_honeypot_url*_ in `config.ini` to anything you like, 
or leave the default.  Malicious bots looking for secure areas of your site will read this, request
the url and get banned for 24 hours.  Good bots will respect the Disallow. Add your url to your robots.txt file:
```ini
honeypot_url = '/not_important/contact'
```

```ini
User-agent: *
Disallow: /not_important/contact
```


3. Require full browser.  If your website uses JavaScript and cookies (99% of all websites) you can
require all web browers to prove they support both by enabling *require_full_browser*.  Since >95% of
all exploit scripts and worms do not support JavaScript or cookies this is the single best protection
you can install to prevent breakins.  This cookie is non user-identifying and so is fully GDPR compliant
and does not require a GDPR notification.
```ini
require_full_browser = true
```


4. Enable bot whitelist.  Futher limit bots by allowing only verified whitelisted robots.  A preconfigured
list of common bots included with BitFire.  Refer to our wiki for how to add additional bots.
```ini
whitelist_enable = true
```

5. Enable core web filter.  The web filter blocks malicious requets like XSS and SQLi as well as many others.
The entire web filter can be enabled or disabled with the *web_filter_enabled* parameter.  We recommend
the following configuration:
```ini
web_filter_enabled = true
xss_block = true
sql_block = true
```

6. Enable IP blocking.  By default BitFire will not black list IPS.  We recommend you enable this feature since
it allows for the fastest possbile drop of request floods for HTTP floods.
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

Your Name - [@bitslip6](https://twitter.com/bitslip6) - info@bitslip6.com

Project Link: [https://github.com/bitslip6/bitfire](https://github.com/bitslip6/bitfire)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [Img Shields](https://shields.io)
* [Choose an Open Source License](https://choosealicense.com)
* [Font Awesome](https://fontawesome.com)
* [Bootstrap](https://getbootstrap.com)





<!-- MARKDOWN LINKS & IMAGES -->
