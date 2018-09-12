BASE_DIR="/home/hari/faros/"
RECORDS_DIR="/home/hari/ReplayServer/records/"
cd $RECORDS_DIR
cd $1
#java -jar "$BASE_DIR"faros/CDM/ta1-integration-faros/target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar faros.stateless file:faros.json -psf "$BASE_DIR"faros/CDM/ta3-serialization-schema/avro/TCCDMDatum.avsc -wj -recNum $1 -injection faros.injection
java -jar "$BASE_DIR"faros/CDM/ta1-integration-faros/target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar faros.stateless ta1-faros-pandex-cdm17 -ks 10.0.50.19:9092 -psf "$BASE_DIR"faros/CDM/ta3-serialization-schema/avro/TCCDMDatum.avsc -recNum $1 -injection faros.injection -delay 0
