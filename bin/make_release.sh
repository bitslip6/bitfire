#!/bin/sh
#
#
# Script to create a bitfire WordPress plugin
echo "Creating standalone BitFire install version $1 [$2]"

#cp -r wordpress-plugin/* /home/cory/dev/wordpress/bitfire/trunk
#cp -r public /home/cory/dev/wordpress/bitfire/trunk/
#cp -r firewall/src /home/cory/dev/wordpress/bitfire/trunk/
#cp -r firewall/cache /home/cory/dev/wordpress/bitfire/trunk/
#cp -r firewall/views /home/cory/dev/wordpress/bitfire/trunk/


#sed -i "s/__VERSION__/$1/g" /home/cory/dev/wordpress/bitfire/trunk/readme.txt
#sed -i "s/__VERSION__/$1/g" /home/cory/dev/wordpress/bitfire/trunk/bitfire-plugin.php
#sed -i "s/__VERSION__/$1/g" /home/cory/dev/wordpress/bitfire/trunk/src/const.php
#sed -i "s/__VERSION_NUM__/$2/g" /home/cory/dev/wordpress/bitfire/trunk/src/const.php

echo "new build directory"
rm -rf _build
mkdir -p _build/bitfire
mkdir -p _build/bitfire/quarantine
cd _build

cp -r ../wordpress-plugin bitfire/
cp -r ../custom-plugin bitfire/

echo "copy config startup files"
cp --remove-destination -L ../config.ini bitfire/config.ini
cp --remove-destination -L ../config-sample.ini bitfire/config-sample.ini
cp --remove-destination -L ../startup.php bitfire/startup.php
cp -r --remove-destination -L ../public bitfire/public

cp -r ../firewall/blocks bitfire/blocks
cp -r ../firewall/src bitfire/src
cp ../readme.md bitfire
cp ../CODE_OF_CONDUCT.md bitfire
cp ../LICENSE bitfire
cp ../SECURITY.md bitfire
cp -r ../firewall/views bitfire/views
cp -r ../firewall/cache bitfire/cache

# define("BitFire\WAF_SRC", \BitFire\WAF_ROOT . "src/"); 
# cp ../../config.* .
cp ../exceptions.json bitfire
echo "[]" > bitfire/cache/errors.json
echo '{"time":"Wed, 25 May 2022 16:44:17 +0000","tv":1653497057,"exec":"1,653,496,913.655711 sec","block":{"code":26001,"parameter":"REQUEST_RATE","value":"41","pattern":"40","block_time":2},"request":{"headers":{"requested_with":"","fetch_mode":"","accept":"","content":"","encoding":"","dnt":"","upgrade_insecure":"","content_type":"text\/html"},"host":"unit_test","path":"\/","ip":"127.0.0.1","method":"GET","port":8080,"scheme":"http","get":[],"get_freq":[],"post":[],"post_raw":"","post_freq":[],"cookies":[],"agent":"test request rate alert","referer":null},"http_code":404}' > bitfire/cache/alerts.json
echo '{"time":"Wed, 04 May 2022 14:46:33 -0600","tv":1651697193,"exec":"0.001865 sec","block":{"code":10020,"parameter":"bitfire_block_test","value":"event.path","pattern":"static match","block_time":0},"request":{"headers":{"requested_with":"","fetch_mode":"","accept":"*\/*","content":"","encoding":"","dnt":"","upgrade_insecure":"","content_type":"text\/html"},"host":"localhost","path":"\/","ip":"127.0.0.1","method":"GET","port":80,"scheme":"http","get":{"test_block":"event.path"},"get_freq":{"test_block":{"46":1}},"post":[],"post_raw":"","post_freq":[],"cookies":[],"agent":"curl\/7.74.0"},"browser":{"os":"bot","whitelist":true,"browser":"curl\/7.74.0","ver":"x","bot":true,"valid":0},"rate":{"rr":1,"rr_time":1651697370,"ref":null,"ip_crc":3619153832,"ua_crc":3606776447,"ctr_404":0,"ctr_500":0,"valid":0,"op1":293995,"op2":2607,"oper":4,"ans":0},"http_code":403}' > bitfire/cache/blocks.json

rm -rf bitfire/coverage
rm -rf bitfire/src/pro*
rm -rf bitfire/cache/profile
rm -rf bitfire/cache/*.log
rm -rf bitfire/cache/file_roots.json
rm -f ../bitfire-standalone-$1.zip
mkdir -p bitfire/cache/profile


sed -i "s/__VERSION__/$1/g" bitfire/readme.txt
sed -i "s/__VERSION__/$1/g" bitfire/wordpress-plugin/bitfire-plugin.php
sed -i "s/__TYPE__/WORDPRESS/g" bitfire/startup.php
sed -i "s/9.9.9/$1/g" bitfire/src/const.php
sed -i "s/999/$2/g" bitfire/src/const.php





# some WordPress specific files
#cp wordpress-plugin/readme.txt bitfire
#cp wordpress-plugin/license.txt bitfire
#cp wordpress-plugin/.htaccess bitfire

find . -type d | xargs chmod 775
find . -type f | xargs chmod 664
zip -r ../bitfire-standalone-$1.zip bitfire --exclude 'bitfire/quarantine/*' --exclude 'bitfire/cache/profile/*'
tar zcf ../bitfire-standalone-$1.tar.gz bitfire --exclude 'bitfire/quarantine/*' --exclude 'bitfire/cache/profile/*'
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

