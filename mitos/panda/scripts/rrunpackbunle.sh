#!/bin/bash


for rec in {1}
do
   echo "/faros/benign_data_collection/benign_record_files/z_"$rec".rr"
   python rrunpack.py "/faros/benign_data_collection/benign_record_files/z_"$rec".rr"
done



