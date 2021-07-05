#!/usr/bin/env bash 
parentDir="/Users/tomrush/Desktop/result"
for line in $(cat /Users/tomrush/Desktop/firmware_name.txt)
do 
	dirAndName=$parentDir/$line
	mkdir $dirAndName
	
	file1="ROAD_func_middle"
	dirAndName1=$parentDir/$line/$file1
	mkdir $dirAndName1
	
	file2="CFG"
	dirAndName2=$parentDir/$line/$file2
	mkdir $dirAndName2
	
	file3="CallGraph"
	dirAndName3=$parentDir/$line/$file3
	mkdir $dirAndName3
done


