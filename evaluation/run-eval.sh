#!/bin/bash

if [ $# -ne 3 ] || [ "$1" != "SGX" -a "$1" != "BASELINE" ] ||  ! [ "$3" -eq "$3" ] || [ "$3" -le "0" ]; then
    echo "Usage: $0 SGX|BASELINE SEED REPS"
    exit 1
fi

BASE_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"

URL=$(cd "$BASE_DIR"; echo "console.log(JSON.parse(require('fs').readFileSync('config.json', 'utf-8')).platformURL)" | node)

old_pwd=$(pwd)
tmp=$(mktemp -d)
cd $tmp

# start platform server
if [ "$1" = "SGX" ]; then
    $BASE_DIR/bin/peqes-runner "$BASE_DIR/bin/peqes-server.sgxs" > /dev/null &
else
    $BASE_DIR/bin/peqes-server > /dev/null &
fi

# wait until server is up
wget -q -O - --retry-connrefused $URL/studies > /dev/null || exit 1

# run eval script
node "$BASE_DIR/index.js" "$BASE_DIR/config.json" "$2" "$3" | tee $tmp/eval-log.txt

# kill server
kill %1

# wait for server to be shutdown
until [ -z "$(ss -Halt sport = :3001)" ]; do
    sleep 1
done

# restore pwd and return tmp directory
cd $old_pwd
echo $tmp
