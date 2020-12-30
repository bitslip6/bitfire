#!/bin/sh
where=$( dirname $(realpath "$0") )
config="$where/config.ini"
echo "updating secrets and keys $config..."

sed -i "s/secret\s*=.*/secret = '`tr -dc A-Za-z0-9 </dev/urandom | head -c 16`'/" $config
sed -i "s/encryption_key\s*=.*/encryption_key = '`tr -dc A-Za-z0-9 </dev/urandom | head -c 24`'/" $config
sed -i "s/user_tracking_cookie\s*=.*/user_tracking_cookie = '_`tr -dc a-z </dev/urandom | head -c 4`'/" $config
sed -i "s/user_tracking_param\s*=.*/user_tracking_param = '_`tr -dc a-z </dev/urandom | head -c 8`'/" $config
sed -i "s/honeypot_url\s*=.*/honeypot_url = '\/`tr -dc a-z </dev/urandom | head -c 8`\/contact'/" $config

echo "done. your site secret, encryption keys and BitFire cookie are all uniquely named"
