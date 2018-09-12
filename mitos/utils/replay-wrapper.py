#!/usr/bin/python
import sys
import os
import glob
import time

# how to run: sudo python replay-wrapper.py PANDA_traces_directory  qemu_directory translator_directory ta1-integration-faros_directory output_directory



subdir_list = next(os.walk(sys.argv[1]))[1]
subdir_list.sort()
print subdir_list
for sub_dir in subdir_list:
    
    subsubdir_list = next(os.walk(sys.argv[1] + sub_dir))[1]
    subsubdir_list.sort()
    for subsub_dir in subsubdir_list:
        cur_dir = sys.argv[1] + sub_dir + "/" + subsub_dir
        print ">> Current Directory: ", cur_dir
        # replay the trace
        # pars pids
        f = open(cur_dir + "/command.csv", 'r')
        line = f.readlines()
        pids_list = line[0].split()
        pids = " -panda faros:start_immediately=on,taint_level=full,rolling=off,pid="
        for i in range(len(pids_list)):
            pids += pids_list[i]
            if i != (len(pids_list) - 1):
                pids += "-"
        pids += " "
        print pids
        raw_command = line[1].rstrip()
        command = raw_command[:45] + " \"" + cur_dir + "\"" + "/" + raw_command[45:] + pids
        print command
        os.chdir(sys.argv[2])
        # Replay the trace and generate the .trace output
        os.system(command)
        
        out_dir = "\"" + sys.argv[5] + "\"" + sub_dir + "/" + subsub_dir
        os.system("sudo mkdir -p " +  out_dir)
        os.system("sudo rm faros.log")
        os.system("sudo mv faros.* " +  out_dir + "/")
        print out_dir
        for file in os.listdir( sys.argv[5] + sub_dir + "/" + subsub_dir + "/"):
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
        txt_file = out_dir + "/faros.txt"
        stateless_file = out_dir + "/faros.stateless"
        avro_file = out_dir + "/faros.avro"
        json_file = out_dir + "/faros.json"
        readme_file = out_dir + "/faros.README"

        os.chdir(sys.argv[3])
        # Generate .txt and .stateless output files
        os.system("sudo python translate.py " + trace_file + " " + cr3_file + " " + string_file + " " + file_file + " " + net_file + " " + txt_file + " " + stateless_file + " " + readme_file + " b")
        
        os.chdir(sys.argv[4])
        
        # Generate .json output file
        os.system("java -jar target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar " + stateless_file + " file:" + avro_file + " -psf ../ta3-serialization-schema/avro/TCCDMDatum.avsc -delay 0")
        #os.system("java -jar target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar " + stateless_file + " ta1-faros-cdm13-fullprov-corrected-1 -ks 129.55.12.59:9092 -psf ../ta3-serialization-schema/avro/TCCDMDatum.avsc -delay 0")
        # Generate .json output file
        os.system("java -jar target/ta1-integration-faros-1.0-SNAPSHOT-jar-with-dependencies.jar " + stateless_file + " file:" + json_file + " -psf ../ta3-serialization-schema/avro/TCCDMDatum.avsc -wj -delay 0")
        print ">> outputs for the current directory are created and moved successfully!"



