#!/bin/sh
echo "createing new random keys..."

sed -i "s/secret\s*=.*/secret = '`tr -dc A-Za-z0-9 </dev/urandom | head -c 16`'/" config.ini
sed -i "s/encryption_key\s*=.*/encryption_key = '`tr -dc A-Za-z0-9 </dev/urandom | head -c 24`'/" config.ini
sed -i "s/user_tracking_cookie\s*=.*/user_tracking_cookie = '_`tr -dc a-z </dev/urandom | head -c 4`'/" config.ini
sed -i "s/user_tracking_param\s*=.*/user_tracking_param = '_`tr -dc a-z </dev/urandom | head -c 8`'/" config.ini
sed -i "s/honeypot_url\s*=.*/honeypot_url = '\/`tr -dc a-z </dev/urandom | head -c 8`\/contact'/" config.ini

echo "done. your site secret, encryption keys and BitFire cookie are all uniquely named"
