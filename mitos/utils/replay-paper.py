#!/usr/bin/python
import sys
import os
import glob
import time

# how to run: sudo python replay-paper.py PANDA_traces_directory qemu_directory output_directory



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
        
        out_dir = "\"" + sys.argv[3] + "\"" + sub_dir + "/" + subsub_dir
        os.system("sudo mkdir -p " +  out_dir)
        os.system("sudo rm faros.log")
        os.system("sudo mv faros.* " +  out_dir + "/")
        print out_dir

        print ">> outputs for the current directory are created and moved successfully!"



