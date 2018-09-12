#!/bin/bash


for rec in {1..18}
do
   echo "../qemu/z_"$rec
   python rrpack.py "../qemu/z_"$rec
done
