#!/bin/sh
ver=1.0.4
where=$( dirname $(realpath "$0") )
config="$where/config.ini"
echo "\e[0;36mBitFire $ver \e[0mconfig: $config"
pass=$( shuf -n 3 cache/words.txt | tr '\n' '_' | sed 's/_$/\n/' )

sed -i "s/secret\s*=.*/secret = '`tr -dc A-Za-z0-9 </dev/urandom | head -c 16`'/" $config
sed -i "s/encryption_key\s*=.*/encryption_key = '`tr -dc A-Za-z0-9 </dev/urandom | head -c 24`'/" $config
sed -i "s/browser_cookie\s*=.*/browser_cookie = '_`tr -dc a-z </dev/urandom | head -c 4`'/" $config
sed -i "s/bitfire_param\s*=.*/bitfire_param = '_`tr -dc a-z </dev/urandom | head -c 8`'/" $config
sed -i "s/honeypot_url\s*=.*/honeypot_url = '\/`tr -dc a-z </dev/urandom | head -c 8`\/contact'/" $config
sed -i "s/password\s*=.*/password = '$pass'/" $config

echo "encryption keys updated"
echo "please write down the new dashboard password: \"\e[0;35m$pass\e[0m\""


#echo "These php.ini files do not currently have auto_prepend_file"
rm -f /tmp/_bitfire_ini
find $(dirname $(dirname `php -i | grep '(php.ini)' | cut -d '>' -f 2`)) -name php.ini | xargs egrep -l -e '\s*[^;\s]\s*auto_prepend_file' > /tmp/_bitfire_ini
find $(dirname $(dirname `php -i | grep '(php.ini)' | cut -d '>' -f 2`)) -name php.ini | xargs egrep -l -e 'auto_prepend_file\s*=\s*""' >> /tmp/_bitfire_ini
cat /tmp/_bitfire_ini | sort | uniq > /tmp/_bitfire_ini2
mv /tmp/_bitfire_ini2 /tmp/_bitfire_ini

# cat /tmp/_bitfire_ini | while read line
for file in $(cat /tmp/_bitfire_ini); do
    echo 
    echo "\e[0;34m$file \e[0;90m"
    echo "sudo sed -i 's/^.*auto_prepend_file.*$/auto_prepend_file = "startup.php"/' $file\e[m";
    read -p "add BitFire support to $file (y/n)? " ans 
    case $ans in
        [yY]* ) sudo sed -i 's/^.*auto_prepend_file.*$/auto_prepend_file = "startup.php"/' $file;;
    esac
done
rm -f /tmp/_bitfire_ini
