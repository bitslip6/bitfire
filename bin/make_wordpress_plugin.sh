#!/bin/sh
#
#
# Script to create a bitfire WordPress plugin
echo "Creating wordpress plugin version $1"

rm -rf tmp
mkdir tmp
cd tmp
cp -r ../wordpress-plugin bitfire
cp --remove-destination -L ../wordpress-plugin/config.ini bitfire/config.ini
cp --remove-destination -L ../wordpress-plugin/config-sample.ini bitfire/config-sample.ini
cd bitfire

rm -f firewall
rm -f startup.php
rm -f config.*
mkdir vendor
cp -r ../../firewall/src vendor/bitfire
cp ../../readme.md vendor/bitfire
cp ../../CODE_OF_CONDUCT.md vendor/bitfire
cp ../../LICENSE vendor/bitfire
cp ../../SECURITY.md vendor/bitfire
cp -r ../../firewall/views .
cp -r ../../firewall/cache .
mkdir blocks
mkdir quarantine

cp ../../startup.php .
# define("BitFire\WAF_SRC", \BitFire\WAF_ROOT . "src/"); 
sed -i 's/WAF_ROOT . "src/WAF_ROOT . "vendor\/bitfire/g' startup.php
cp ../../config.* .
cp ../../exceptions.json .
# cp ../../LICENSE .
echo "[]" > cache/errors.json
pwd
#cp firewall/startup.php .
#mv firewall/config.ini* .
cd ..
pwd
# update configuration and set defaults
rm bitfire/config.ini.php
rm bitfire/config.ini
cp bitfire/config-sample.ini bitfire/config.ini
echo "[]" > bitfire/cache/errors.json
echo '{"time":"Wed, 25 May 2022 16:44:17 +0000","tv":1653497057,"exec":"1,653,496,913.655711 sec","block":{"code":26001,"parameter":"REQUEST_RATE","value":"41","pattern":"40","block_time":2},"request":{"headers":{"requested_with":"","fetch_mode":"","accept":"","content":"","encoding":"","dnt":"","upgrade_insecure":"","content_type":"text\/html"},"host":"unit_test","path":"\/","ip":"127.0.0.1","method":"GET","port":8080,"scheme":"http","get":[],"get_freq":[],"post":[],"post_raw":"","post_freq":[],"cookies":[],"agent":"test request rate alert","referer":null},"http_code":404},' > bitfire/cache/alerts.json
echo '{"time":"Wed, 04 May 2022 14:46:33 -0600","tv":1651697193,"exec":"0.001865 sec","block":{"code":10020,"parameter":"block_test","value":"event.path","pattern":"static match","block_time":0},"request":{"headers":{"requested_with":"","fetch_mode":"","accept":"*\/*","content":"","encoding":"","dnt":"","upgrade_insecure":"","content_type":"text\/html"},"host":"localhost","path":"\/","ip":"127.0.0.1","method":"GET","port":80,"scheme":"http","get":{"test_block":"event.path"},"get_freq":{"test_block":{"46":1}},"post":[],"post_raw":"","post_freq":[],"cookies":[],"agent":"curl\/7.74.0"},"browser":{"os":"bot","whitelist":true,"browser":"curl\/7.74.0","ver":"x","bot":true,"valid":0},"rate":{"rr":1,"rr_time":1651697370,"ref":null,"ip_crc":3619153832,"ua_crc":3606776447,"ctr_404":0,"ctr_500":0,"valid":0,"op1":293995,"op2":2607,"oper":4,"ans":0},"http_code":403}' > bitfire/cache/blocks.json

rm -rf bitfire/tests
rm -rf bitfire/tests
rm -rf bitfire/coverage
rm -rf bitfire/src/plugins
rm -rf bitfire/src/pro*
rm -rf bitfire/cache/*.raw
rm -rf bitfire/cache/*.log
rm -f ../bitfire-$1.zip

find -type f bitfire | xargs chown cory:cory
find -type f bitfire | xargs chmod 664
find -type d bitfire | xargs chmod 775

zip -r ../bitfire-$1.zip bitfire --exclude 'bitfire/quarantine/*' --exclude 'bitfire/cache/profile/*'
cd ..
pwd
ls -l 
rm -rf tmp
rm -rf wordpress-plugin/src
rm -rf wordpress-plugin/blocks
rm -rf wordpress-plugin/cache
rm -rf wordpress-plugin/quarantine
rm -rf wordpress-plugin/tests
rm -rf wordpress-plugin/views

