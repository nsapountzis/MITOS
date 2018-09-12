BASE_DIR="/home/hari/faros/"
cd /data/PSALogs/
unzip "*zip"
rm "*zip"
cd /data/PSBLogs/
unzip "*zip"
rm "*zip"
java -jar "$BASE_DIR"PSA_CDM/ta1-integration-faros/target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar -PSA /data/PSALogs/ ta1-faros-pandex-cdm17 -ks 10.0.50.19:9092 -psf "$BASE_DIR"PSA_CDM/ta3-serialization-schema/avro/TCCDMDatum.avsc -delay 0
java -jar "$BASE_DIR"PSA_CDM/ta1-integration-faros/target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar -PSB /data/PSBLogs/ ta1-faros-pandex-cdm17 -ks 10.0.50.19:9092 -psf "$BASE_DIR"PSA_CDM/ta3-serialization-schema/avro/TCCDMDatum.avsc -delay 0
#java -jar "$BASE_DIR"PSA_CDM/ta1-integration-faros/target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar -PSA /data/PSALogs/ file:/mnt/c/Users/Hari-FICS/Desktop/PSA/faros-psa.json -psf "$BASE_DIR"PSA_CDM/ta3-serialization-schema/avro/TCCDMDatum.avsc -wj
#java -jar "$BASE_DIR"PSA_CDM/ta1-integration-faros/target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar -PSB /data/PSBLogs/ file:/mnt/c/Users/Hari-FICS/Desktop/PSA/faros-psa.json -psf "$BASE_DIR"PSA_CDM/ta3-serialization-schema/avro/TCCDMDatum.avsc -wj
rm -rf /data/PSALogs/*
rm -rf /data/PSBLogs/*
