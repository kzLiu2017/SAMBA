#!/bin/bash

path='/home/flower/Documents/firmware/'
#path='/home/flower/karonte_dataset/d-link/analyzed/DIR-880/firmware/_DIR-880L_A1_FW107WWb08.bin.extracted/squashfs-root/lib/'
arm_arch='ARM'
ssl_files='/home/flower/Documents/ssl_files_fr/'
ssl_firmware='/home/flower/Documents/firmware_test/'

function recursive_list_dir(){
    for file_or_dir in `ls $1`
    do
        if [ -d $1"/"$file_or_dir ]
        then
            if [ ${#file_or_dir} -lt 170 ]
            then
                echo $file_or_dir
                recursive_list_dir $1"/"$file_or_dir 
            fi
        else
            filename=$1"/"$file_or_dir
            readelf_result=$(readelf -a $filename 2>>/dev/null)
            result_arm=$(echo $readelf_result | grep 'Machine.\{0,50\}ARM')
            result_openssl=$(echo $readelf_result | grep 'libssl.so')
            echo $filename
            if [[ "$result_arm" != "" ]] && [[ "$result_openssl" != "" ]];
            then
                so_file=$(echo $filename | grep '\.so')
                if [[ "$so_file" == "" ]]
                then
                    new_filename="$( echo $filename | sed 's./.+.g' )"
                    echo $new_filename
                    cp $filename $ssl_files$new_filename
                fi
            fi
        fi
    done
}

function binwalk_extract(){
    for file_or_dir in `ls $1`
    do
        full_filename=$ssl_firmware$file_or_dir
        echo $file_or_dir
        zipfile=$(echo $file_or_dir | grep '.zip')
        binfile=$(echo $file_or_dir | grep '.bin')
        if [[ "$zipfile" != "" ]]
        then
            dir_name=${file_or_dir%.*}
            dir=$dir_name
            echo $dir
            echo $full_filename
            unzip $full_filename -d $dir
        fi
        if [[ "$binfile" != "" ]]
        then
            binwalk -e $full_filename
        fi
        rm $full_filename
    done
}
#binwalk_extract $ssl_firmware
recursive_list_dir $path

#signalc_path='/home/flower/karonte_dataset/d-link/analyzed/DIR-880/firmware/_DIR-880L_A1_FW107WWb08.bin.extracted/squashfs-root/mydlink/signalc'