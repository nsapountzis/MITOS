#!/usr/bin/python
import sys
import os
import glob
import time

# how to run: python wrapper.py faros_outputs-direcotory translator-directory ta1-integration-faros-directory final_outputs-directory

time.sleep(60*60)

while True:
    time.sleep(30*60)
    subdir_list = next(os.walk(sys.argv[1]))[1]
    for sub_dir in subdir_list:
        cur_dir = sys.argv[1] + sub_dir
        print ">> Current Directory: ", cur_dir
        for file in os.listdir(cur_dir):
            if file.endswith(".trace"):
                trace_file = cur_dir + "/" + file
            if file.endswith(".string"):
                string_file = cur_dir + "/" + file
            if file.endswith(".cr3"):
                cr3_file = cur_dir + "/" + file

        txt_file = cur_dir + "/faros.txt"
        stateless_file = cur_dir + "/faros.stateless"
        avro_file = cur_dir + "/faros.avro"
        json_file = cur_dir + "/faros.json"
        readme_file = cur_dir + "/faros.README"
        
        os.chdir(sys.argv[2])
        # Generate .txt and .stateless output files
        os.system("python translate.py " + trace_file + " " + cr3_file + " " + string_file + " " + txt_file + " " + stateless_file + " " + readme_file)
        
        os.chdir(sys.argv[3])
        # Generate .json output file
        os.system("java -jar target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar " + stateless_file + " file:" + avro_file + " -psf ../ta3-serialization-schema/avro/TCCDMDatum.avsc")
        # Generate .json output file
        os.system("java -jar target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar " + stateless_file + " file:" + json_file + " -psf ../ta3-serialization-schema/avro/TCCDMDatum.avsc -wj")        
    
        # Move folder
        os.system("mv " + cur_dir + " " + sys.argv[4])
        print ">> outputs for for the current directory are created and moved successfully!"
