#!/bin/bash
BASE_DIR="/home/hari/faros/"
GUEST_FS="/home/hari/guestfs"
PSB_DIR="/home/hari/PSBLogs/"
curr_time="$(date +%s)"
sudo guestmount -a /home/hari/Win-7-32.qcow2 -m /dev/sda2 --ro "$GUEST_FS"
cd "$GUEST_FS"/PSB
eval "sorted_files=($(ls -t --quoting-style=shell-always))"
sorted_files=("${sorted_files[@]:0:30}")
idx=${#sorted_files[@]}
i=1
while [ $i -le 30 ]
do
    cp -- "${sorted_files[$idx-$i]}" $PSB_DIR/"${sorted_files[$idx-$i]}#$curr_time" 
    (( i++ ))
done
#/usr/bin/flock -n /tmp/psb_publish.lock cp -- "${sorted_files[@]:0:30}" $PSB_DIR/
if [ ! -e /tmp/info.txt ]
then
    cp "$GUEST_FS"/Users/faros/HostInfo/info.txt /tmp/info.txt
fi
cd $BASE_DIR
guestunmount "$GUEST_FS"

