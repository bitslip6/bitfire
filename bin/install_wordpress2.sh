#!/bin/sh

cp -r startup.php /var/www/wordpress/bitfire/startup.php
cp -r firewall/src/* /var/www/wordpress/bitfire/src
cp -r firewall/views/* /var/www/wordpress/bitfire/views
cp -r public/* /var/www/wordpress/bitfire/public
cp -r wordpress-plugin/*.php /var/www/wordpress/bitfire/wordpress-plugin
cp -r custom-plugin/*.php /var/www/wordpress/bitfire/custom-plugin
cp -r startup.php /var/www/wordpress/bitfire/

#rm /var/www/wordpress/wp-content/plugins/bitfire/startup.php
#cp -L startup.php /var/www/wordpress/wp-content/plugins/bitfire/

#sed -i "s/__VERSION__/$1/g" /var/www/wordpress/wp-content/plugins/bitfire/readme.txt
#sed -i "s/__VERSION__/$1/g" /var/www/wordpress/wp-content/plugins/bitfire/bitfire-plugin.php
#sed -i "s/__VERSION__/$1/g" /var/www/wordpress/wp-content/plugins/bitfire/vendor/bitfire/const.php
#sed -i "s/__VERSION_NUM__/$2/g" /var/www/wordpress/wp-content/plugins/bitfire/vendor/bitfire/const.php
echo '<?php $ini_type = "shmop";' > /var/www/wordpress/bitfire/ini_info.php 
