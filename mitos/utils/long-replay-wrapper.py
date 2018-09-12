#!/usr/bin/python
import sys
import os
import glob
import time

# how to run: sudo python long-replay-wrapper.py faros_outputs_directory translator_directory ta1-integration-faros_directory output_directory



subdir_list = next(os.walk(sys.argv[1]))[1]
subdir_list.sort()
print subdir_list
for sub_dir in subdir_list:

    cur_dir = sub_dir
    print ">> Current Directory: ", cur_dir
    out_dir = "\"" + sys.argv[1] + "\"" + sub_dir
    for file in os.listdir( sys.argv[1] + sub_dir + "/"):
        if file.endswith(".trace"):
            trace_file = out_dir + "/" + file
        if file.endswith(".string"):
            string_file = out_dir + "/" + file
        if file.endswith(".cr3"):
            cr3_file = out_dir + "/" + file
        if file.endswith(".file"):
            file_file = out_dir + "/" + file
        if file.endswith(".net"):
            net_file = out_dir + "/" + file
    filename = "faros-" + sub_dir
    txt_file = out_dir + "/" + filename + ".txt"
    stateless_file = out_dir + "/" + filename + ".stateless"
    avro_file = out_dir + "/" + filename + "avro"
    json_file = out_dir + "/" + filename + ".json"
    readme_file = out_dir + "/" + filename + ".README"

    os.chdir(sys.argv[2])
    # Generate .txt and .stateless output files
    os.system("sudo python translate.py " + trace_file + " " + cr3_file + " " + string_file + " " + file_file + " " + net_file + " " + txt_file + " " + stateless_file + " " + readme_file + " b")
    
    os.chdir(sys.argv[3])
    
    # Generate .json output file
    os.system("java -jar target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar " + stateless_file + " file:" + avro_file + " -psf ../ta3-serialization-schema/avro/TCCDMDatum.avsc -delay 0")
    #os.system("java -jar target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar " + stateless_file + " ta1-faros-cdm13-fullprov-corrected-1 -ks 129.55.12.59:9092 -psf ../ta3-serialization-schema/avro/TCCDMDatum.avsc -delay 0")
    # Generate .json output file
    #os.system("java -jar target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar " + stateless_file + " file:" + json_file + " -psf ../ta3-serialization-schema/avro/TCCDMDatum.avsc -wj -delay 0")
    
    os.system("mv " + out_dir + " " + "\"" + sys.argv[4] + "\"")
    print ">> outputs for the current directory are created and moved successfully!"



