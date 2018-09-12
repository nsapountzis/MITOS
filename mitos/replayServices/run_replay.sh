# Update the directory names
BASE_DIR="/home/hari/faros/"
RECORDS_DIR="/home/hari/ReplayServer/records/"
# Give the IP addresses of ADAPT, MARPLE and RIPE replay machines instead of localhost
URL1="http://localhost:9000"
URL2="http://localhost:9000"
URL3="http://localhost:9000"
# Give the IP addresses of the publisher machine instead of localhost
PUB_URL="http://localhost:9100"
wget "$URL1/addToSet?rec=$1"
wget "$URL2/addToSet?rec=$1"
wget "$URL3/addToSet?rec=$1"
cd $RECORDS_DIR
mkdir -p $1
cd $1
"$BASE_DIR"faros/panda/qemu/i386-softmmu/qemu-system-i386 -replay "$RECORDS_DIR$1" -m 4048 --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -panda faros:start_immediately=on,rolling=off,taint_level=full,taint_enable=on
python "$BASE_DIR"faros/translator/translate.py faros.trace faros.cr3 faros.string faros.file faros.net faros.txt faros.stateless faros.README 'b' "$BASE_DIR"faros/translator/syscalls.csv
cd "../"
wget "$PUB_URL/addToPublisher?rec=$1"

