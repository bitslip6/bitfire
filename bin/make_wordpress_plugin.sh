#!/bin/sh
#
#
# Script to create a bitfire WordPress plugin
echo "Creating wordpress plugin version $1 [$2]"

#cp -r wordpress-plugin/* /home/cory/dev/wordpress/bitfire/trunk
#cp -r public /home/cory/dev/wordpress/bitfire/trunk/
#cp -r firewall/src /home/cory/dev/wordpress/bitfire/trunk/
#cp -r firewall/cache /home/cory/dev/wordpress/bitfire/trunk/
#cp -r firewall/views /home/cory/dev/wordpress/bitfire/trunk/


sed -i "s/__VERSION__/$1/g" /home/cory/dev/wordpress/bitfire/trunk/readme.txt
sed -i "s/__VERSION__/$1/g" /home/cory/dev/wordpress/bitfire/trunk/bitfire-plugin.php
sed -i "s/9\.9\.9\";\/\/\"//g" /home/cory/dev/wordpress/bitfire/trunk/src/const.php
sed -i "s/__VERSION__/$1/g" /home/cory/dev/wordpress/bitfire/trunk/src/const.php
sed -i "s/__VERSION_NUM__/$2/g" /home/cory/dev/wordpress/bitfire/trunk/src/const.php

echo "[]" > /home/cory/dev/wordpress/bitfire/trunk/cache/errors.json
echo "[]" > /home/cory/dev/wordpress/bitfire/trunk/cache/alerts.json


echo "new build directory"
rm -rf _build
mkdir _build
cd _build

cp -r ../wordpress-plugin bitfire

echo "copy config startup files"
cp --remove-destination -L ../wordpress-plugin/config.ini bitfire/config.ini
cp --remove-destination -L ../startup.php bitfire/startup.php
cp --remove-destination -L ../wordpress-plugin/config-sample.ini bitfire/config-sample.ini
rm -r bitfire/public
cp -r ../public bitfire
cd bitfire



#mkdir src
cp -r ../../firewall/src src
cp ../../readme.md src
cp ../../CODE_OF_CONDUCT.md src
cp ../../LICENSE src
cp ../../SECURITY.md src
cp -r ../../firewall/views .
cp -r ../../firewall/cache .
mkdir blocks
mkdir quarantine

# define("BitFire\WAF_SRC", \BitFire\WAF_ROOT . "src/"); 
sed -i 's/WAF_ROOT . "src/WAF_ROOT . "src/g' startup.php
# cp ../../config.* .
cp ../../exceptions.json .
# cp ../../LICENSE .
echo "[]" > cache/errors.json
pwd
#cp firewall/startup.php .
#mv firewall/config.ini* .
cd ..
pwd
# update configuration and set defaults
#rm bitfire/config.ini.php
#rm bitfire/config.ini
#cp bitfire/config-sample.ini bitfire/config.ini
echo "[]" > bitfire/cache/errors.json
echo '{"time":"Wed, 25 May 2022 16:44:17 +0000","tv":1653497057,"exec":"1,653,496,913.655711 sec","block":{"code":26001,"parameter":"REQUEST_RATE","value":"41","pattern":"40","block_time":2},"request":{"headers":{"requested_with":"","fetch_mode":"","accept":"","content":"","encoding":"","dnt":"","upgrade_insecure":"","content_type":"text\/html"},"host":"unit_test","path":"\/","ip":"127.0.0.1","method":"GET","port":8080,"scheme":"http","get":[],"get_freq":[],"post":[],"post_raw":"","post_freq":[],"cookies":[],"agent":"test request rate alert","referer":null},"http_code":404}' > bitfire/cache/alerts.json
echo '{"time":"Wed, 04 May 2022 14:46:33 -0600","tv":1651697193,"exec":"0.001865 sec","block":{"code":10020,"parameter":"bitfire_block_test","value":"event.path","pattern":"static match","block_time":0},"request":{"headers":{"requested_with":"","fetch_mode":"","accept":"*\/*","content":"","encoding":"","dnt":"","upgrade_insecure":"","content_type":"text\/html"},"host":"localhost","path":"\/","ip":"127.0.0.1","method":"GET","port":80,"scheme":"http","get":{"test_block":"event.path"},"get_freq":{"test_block":{"46":1}},"post":[],"post_raw":"","post_freq":[],"cookies":[],"agent":"curl\/7.74.0"},"browser":{"os":"bot","whitelist":true,"browser":"curl\/7.74.0","ver":"x","bot":true,"valid":0},"rate":{"rr":1,"rr_time":1651697370,"ref":null,"ip_crc":3619153832,"ua_crc":3606776447,"ctr_404":0,"ctr_500":0,"valid":0,"op1":293995,"op2":2607,"oper":4,"ans":0},"http_code":403}' > bitfire/cache/blocks.json

rm -rf bitfire/tests
rm -rf bitfire/src/notes.txt
rm -rf bitfire/coverage
rm -rf bitfire/src/plugins
rm -rf bitfire/src/pro*
rm -rf bitfire/cache/*.raw
rm -rf bitfire/cache/*.log
rm -f ../bitfire-$1.zip

find bitfire -type f | xargs chown cory:cory
find bitfire -type f | xargs chmod 664
find bitfire -type d | xargs chmod 775

sed -i "s/__VERSION__/$1/g" bitfire/readme.txt
sed -i "s/__VERSION__/$1/g" bitfire/bitfire-plugin.php
sed -i "s/9\.9\.9\";\/\/\"//g" bitfire/src/const.php
sed -i "s/__VERSION__/$1/g" bitfire/src/const.php
sed -i "s/__TYPE__/WORDPRESS/g" bitfire/src/startup.php
sed -i "s/__VERSION_NUM__/$2/g" bitfire/src/const.php
#sed -i "s/debug_file = \"\"/debug_file = \"/tmp/log.txt\"/g" bitfire/config.ini





# some WordPress specific files
cp wordpress-plugin/readme.txt bitfire
cp wordpress-plugin/license.txt bitfire
cp wordpress-plugin/.htaccess bitfire
cp ../config.ini bitfire
cp ../config-sample.ini bitfire

rm bitfire/public/xss.svg
cp bitfire/public/code.svg bitfire/public/xss.svg

zip -r ../bitfire-$1.zip bitfire --exclude 'bitfire/quarantine/*' --exclude 'bitfire/cache/profile/*'
cd ..
pwd
ls -l 
#rm -rf _build
#rm -rf wordpress-plugin/src
#rm -rf wordpress-plugin/blocks
#rm -rf wordpress-plugin/cache
#rm -rf wordpress-plugin/quarantine
#rm -rf wordpress-plugin/tests
#rm -rf wordpress-plugin/views

