#!/usr/bin/env bash 


for line in $(cat /Users/tomrush/Desktop/firmware_road.txt)
do
	ida64 -A -S"/Users/tomrush/Desktop/Road_arm.py $line" $line 
	#python3 /Users/tomrush/PycharmProjects/first/2_CallGraph.py $line
	echo $line 
done

