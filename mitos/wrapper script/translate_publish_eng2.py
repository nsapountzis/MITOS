#!/usr/bin/python
import sys
import os
import glob
import time

# how to run: sudo python translate_publish_eng2.py <faros_outputs_directory> <translator_directory> <ta1-integration-faros_directory>
# sudo python translate_publish_eng2.py /data/eng-2-pandex/f_o/ /data/faros-h-git/faros/translator/ /data/faros-h-git/faros/CDM/ta1-integration-faros/

# For publishing to Kafka the topic name and the ip address should be change base on the task. (Here is default for the engagement2 on marple kafka server)



subdir_list = next(os.walk(sys.argv[1]))[1]
subdir_list.sort(key=lambda f: int(filter(str.isdigit, f)))
print subdir_list
for sub_dir in subdir_list:
	# print sub_dir
	# print sys.argv[1]
	# print sys.argv[1] + sub_dir
	# subsubdir_list = next(os.walk(sys.argv[1] + sub_dir))[1]
	# print subsubdir_list
	# subsubdir_list.sort()
	# print subsubdir_list
	# print "==="

    cur_dir = sub_dir
    print ">> Current Directory: ", cur_dir
    out_dir = sys.argv[1] + sub_dir
    print ">> Output Directory: ", out_dir
    # print ">> outdire Directory: ", out_dir + "/" + "translated"

    if not os.path.exists(sys.argv[1] + sub_dir + "/" + "translated"):
    	print ("---FOLDER CREATED!---")
    	os.makedirs(sys.argv[1] + sub_dir + "/" + "translated")
    else:
    	print ("---FOLDER EXIST!---")

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
    txt_file = out_dir + "/" + "translated" + "/" + filename + ".txt"
    stateless_file = out_dir + "/" + "translated" + "/" + filename + ".stateless"
    avro_file = out_dir + "/" + "translated" + "/" + filename + "avro"
    json_file = out_dir + "/" + "translated" + "/" + filename + ".json"
    readme_file = out_dir + "/" + "translated" + "/" + filename + ".README"

    os.chdir(sys.argv[2])
    #Generate .txt and .stateless output files
    print( "===== Generate .txt and .stateless output files =====")

    os.system("sudo python translate.py " + trace_file + " " + cr3_file + " " + string_file + " " + file_file + " " + net_file + " " + txt_file + " " + stateless_file + " " + readme_file + " b")
    
    print( "=== Publish to Kafka ===")
    os.chdir(sys.argv[3])

    #os.system("java -jar target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar " + stateless_file + " ta1-faros-pandex-cdm17 -ks 10.0.50.19:9092 -psf ../ta3-serialization-schema/avro/TCCDMDatum.avsc -delay 0")
    print( "===== DONE! =====")
    print( "" )
