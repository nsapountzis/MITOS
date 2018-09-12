#!/bin/bash

# Run the qemu with qmp -qmp tcp:127.0.0.1:4444,server,nowait
# sudo ./i386-softmmu/qemu-system-i386 -hda ~/win7_vm/win7-ultimate.qcow -m 4048 --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -vnc :1 -qmp tcp:127.0.0.1:4444,server,nowait
# cd scripts
# Run ./record_chunks.sh | telnet localhost 4444


sleep_time_init=1
sleep_time=1
sleep $sleep_time_init
echo '{ "execute": "qmp_capabilities" }'
sleep $sleep_time_init
for i in {1..100}
do	
	fileNmaePre="z_"
	fileNamePos=$i
	fileName=$fileNmaePre$fileNamePos
	# rec_command='{ "execute": "begin_record", "arguments": {"file_name" : "'
	# rec_command=$rec_command$fileName
	# rec_command=$rec_command'"}}'
	
	# { "execute": "human-monitor-command", "arguments": {"command-line" : "begin_record zzzz_111222\r" }}
	# { "execute": "human-monitor-command", "arguments": {"command-line" : "end_record\r" }}	
	rec_command='{ "execute": "human-monitor-command", "arguments": {"command-line" : "begin_record '
	rec_command=$rec_command$fileName
	rec_command=$rec_command'\r" }}'
	echo $rec_command
	sleep 300
	# echo '{ "execute": "end_record"}'
	echo '{ "execute": "human-monitor-command", "arguments": {"command-line" : "end_record\r" }}'
	# sleep 5 
done
