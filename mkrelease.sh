#!/bin/sh

rm -rf rel_$1

mkdir rel_$1
cp *.php rel_$1
find rel_$1 -name '*.php' | xargs sed -i 's/ declare(strict_types=1);//g'
cp updatekeys.sh rel_$1
cp *.ini rel_$1
cp *.md rel_$1
cp -rp views rel_$1
mv cache/would_block.json /tmp/would_block.json
mv cache/block.json /tmp/block.json
touch cache/would_block.json
touch cache/block.json

cp -rp cache rel_$1
mv rel_$1/whitelist_agents.ini rel_$1/cache
chmod 664 rel_$1/cache/*.json

tar zcf rel_$1.tgz rel_$1
