#!/bin/bash

# Run the qemu with qmp -qmp tcp:127.0.0.1:4444,server,nowait
# sudo ./i386-softmmu/qemu-system-i386 -hda ~/win7_vm/win7-ultimate.qcow -m 4048 --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -vnc :1 -qmp tcp:127.0.0.1:4444,server,nowait
# cd scripts
# Update base directory and record size accordingly
# Run ./record_chunks.sh | telnet localhost 4444

sleep_time_init=1
sleep_time=1
sleep $sleep_time_init
echo '{ "execute": "qmp_capabilities" }'
sleep $sleep_time_init
i=1
record_size=60
BASE_DIR="/home/hari/ReplayServer/records/"
#start_time=$(date +%s)
#wget "http://localhost:9000/registerStartTime?time=${start_time}" -O /dev/null -o /dev/null
#echo start_time > recordStartTime.txt
tz="America/New_York"
day=$(TZ=$tz date +%u)
hour=$(TZ=$tz date +%H)
while true
do	
	if [ "$day" -ge 1 ] && [ "$day" -le 5 ] && [ "$hour" -ge 9 ] && [ "$hour" -le 16 ]
	then	
		i=$(date +%s)
        	i=$((i/record_size))
		fileNamePos=$i
		fileName=$BASE_DIR$fileNamePos
		rec_command='{ "execute": "human-monitor-command", "arguments": {"command-line" : "begin_record '
		rec_command=$rec_command$fileName
		rec_command=$rec_command'\r" }}'
		echo $rec_command
		sleep $record_size
		echo '{ "execute": "human-monitor-command", "arguments": {"command-line" : "end_record\r" }}'
	fi
	day=$(TZ=$tz date +%u)	
	hour=$(TZ=$tz date +%H)
done
