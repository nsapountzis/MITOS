#!/bin/bash
BASE_DIR="/home/hari/faros/"
PSB_DIR="/home/hari/PSBLogs/"
PSBPUB_DIR="/home/hari/PSBWorkspace/"
sleep 1m
while true
do
    curr_time="$(date +%s)"
    cp /tmp/info.txt "$PSBPUB_DIR"z.txt
    if [ ! -z "$(ls -A $PSB_DIR)" ]
    then
	cd $PSB_DIR
        eval "sorted_files=($(/usr/bin/flock -n /tmp/psb_publish.lock ls -rt --quoting-style=shell-always))"
        /usr/bin/flock -n /tmp/psb_publish.lock mv "${sorted_files[@]:0:25}" $PSBPUB_DIR
        cd $BASE_DIR
        java -jar "$BASE_DIR"PSA_CDM/ta1-integration-faros/target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar -PSB $PSBPUB_DIR ta1-faros-pandex-cdm17 -ks 10.0.50.19:9092 -psf "$BASE_DIR"PSA_CDM/ta3-serialization-schema/avro/TCCDMDatum.avsc -delay 0
        #java -jar "$BASE_DIR"PSA_CDM/ta1-integration-faros/target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar -PSB $PSBPUB_DIR file:/home/hari/PSBCDMOutputs/"$curr_time".json -psf   "$BASE_DIR"PSA_CDM/ta3-serialization-schema/avro/TCCDMDatum.avsc -wj
        rm -rf "$PSBPUB_DIR"*
     fi
done
