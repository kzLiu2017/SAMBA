import os
import time
import sys
import pdb
import copy
from collections import Counter

SSL_API_List = []
func_list = []
import_func_name = ""

lib_to_lib_list = [] 
all_lib_list = [] 
export_func_list = []
func_to_func_list = []
func_to_func_list_in_one_file = []

result_path = os.getcwd() + "/"

file_name = "relayd"
machine = "mips"
file_path = os.getcwd()
all_lib_list.append(file_name)
return_list = []
func_to_func_list_tmp = []

filtered_API = ['SSL_CTX_set_verify','SSL_set_verify', 'SSL_connect', 'SSL_write','SSL_read']
SSL_IO_function = ['BIO_read', 'BIO_write', 'SSL_write', 'SSL_read', '.BIO_read', '.BIO_write', '.SSL_write', '.SSL_read', '_BIO_read', '_BIO_write', '_SSL_write', '_SSL_read']

SSL_version_function = ['TLSv1_client_method',
    'TLS_client_method',
    'TLSv1_1_client_method',
    'TLSv1_2_client_method',
    'TLSv1_3_client_method',
    'SSLv2_client_method',
    'SSLv3_client_method',
    'SSLv23_client_method',
    'TLSv1_method',
    'TLS_method',
    'TLSv1_1_method',
    'TLSv1_2_method',
    'TLSv1_3_method',
    'SSLv2_method',
    'SSLv3_method',
    'SSLv23_method']

SSL_function = {
    'TLS_client_method': 0,
    'TLSv1_client_method': 0,
    'TLS_client_method':0,
    'TLSv1_1_client_method': 0,
    'TLSv1_2_client_method': 0,
    'TLSv1_3_client_method': 0,
    'SSLv2_client_method': 0,
    'SSLv3_client_method': 0,
    'SSLv23_client_method': 0,
    'TLSv1_method': 0,
    'TLS_method': 0,
    'SSL_new': 0,
    'TLSv1_1_method': 0,
    'TLSv1_2_method': 0,
    'TLSv1_3_method': 0,
    'SSLv2_method': 0,
    'SSLv3_method': 0,
    'SSLv23_method': 0,
    'SSL_CTX_set_verify': 0,
    'SSL_set_verify':0,
    'SSL_set_options': 0,
    'SSL_CTX_set_options': 0,
    'SSL_CTX_set_min_proto_version': 0,
    'SSL_CTX_ctrl': 0,
    'SSL_connect': 0,
    'SSL_set_connect_state': 0,
    'SSL_do_handshake': 0,
    'SSL_get_peer_certificate': 0,
    'SSL_get_verify_result': 0,
    'SSL_write': 0,
    'SSL_read': 0,
    'SSL_CTX_new': 0,
    '.TLS_method': 0,
    '.SSL_CTX_new': 0,
    '.TLSv1_client_method': 0,
    '.TLSv1_1_client_method': 0,
    '.TLSv1_2_client_method': 0,
    '.TLSv1_3_client_method': 0,
    '.SSLv2_client_method': 0,
    '.SSLv3_client_method': 0,
    '.SSLv23_client_method': 0,
    '.TLSv1_method': 0,
    '.TLSv1_1_method': 0,
    '.TLSv1_2_method': 0,
    '.TLSv1_3_method': 0,
    '.SSLv2_method': 0,
    '.SSLv3_method': 0,
    '.SSLv23_method': 0,
    '.SSL_CTX_set_verify': 0,
    '.SSL_set_options': 0,
    '.SSL_CTX_set_options': 0,
    '.SSL_CTX_set_min_proto_version': 0,
    '.SSL_CTX_ctrl': 0,
    '.SSL_connect': 0,
    '.SSL_do_handshake': 0,
    '.SSL_set_connect_state': 0,
    '.SSL_get_peer_certificate': 0,
    '.SSL_get_verify_result': 0,
    '.SSL_write': 0,
    '.SSL_read': 0,
    '.SSL_set_verify': 0,
    '.SSL_new': 0,
    '_TLS_method': 0,
    '_SSL_CTX_new': 0,
    '_SSL_set_verify': 0,
    '_SSL_new': 0,
    '.TLS_client_method': 0,
    '_TLSv1_client_method': 0,
    '_TLS_client_method': 0,
    '_TLSv1_1_client_method': 0,
    '_TLSv1_2_client_method': 0,
    '_TLSv1_3_client_method': 0,
    '_SSLv2_client_method': 0,
    '_SSLv3_client_method': 0,
    '_SSLv23_client_method': 0,
    '_TLSv1_method': 0,
    '_TLSv1_1_method': 0,
    '_TLSv1_2_method': 0,
    '_TLSv1_3_method': 0,
    '_SSLv2_method': 0,
    '_SSLv3_method': 0,
    '_SSLv23_method': 0,
    '_SSL_CTX_set_verify': 0,
    '_SSL_set_options': 0,
    '_SSL_CTX_set_options': 0,
    '_SSL_CTX_set_min_proto_version': 0,
    '_SSL_CTX_ctrl': 0,
    '_SSL_connect': 0,
    '_SSL_do_handshake': 0,
    '_SSL_set_connect_state': 0,
    '_SSL_get_peer_certificate': 0,
    '_SSL_get_verify_result': 0,
    '_SSL_write': 0,
    '_SSL_read': 0
}
necessary_SSL_function = {  #
    'TLS_client_method': 0,
    'TLSv1_client_method': 0,
    'TLSv1_1_client_method': 0,
    'TLSv1_2_client_method': 0,
    'SSLv2_client_method': 0,
    'SSLv3_client_method': 0,
    'SSLv23_client_method': 0,
    'TLS_method': 0,
    'TLSv1_method': 0,
    'TLSv1_1_method': 0,
    'TLSv1_2_method': 0,
    'SSLv2_method': 0,
    'SSLv3_method': 0,
    'SSLv23_method': 0,
    'SSL_CTX_new': 0,
    'SSL_new': 0,
    'SSL_CTX_use_certificate_chain_file': 0,
    'SSL_CTX_use_Private_key': 0,
    'SSL_CTX_use_certificate_file': 0,
    'SSL_CTX_use_PrivateKey_file': 0,
    'SSL_CTX_check_private_key': 0,
    'SSL_CTX_set_verify': 0,
    'SSL_set_verify': 0,
    'SSL_CTX_load_verify_locations': 0,
    'SSL_set_fd': 0,
    'SSL_set_options': 0,
    'SSL_CTX_set_options': 0,
    'SSL_CTX_set_min_proto_version': 0,
    'SSL_CTX_ctrl': 0,
    'SSL_connect': 0,
    'SSL_set_connect_state': 0,
    'SSL_do_handshake': 0,
    'SSL_get_peer_certificate': 0,
    'SSL_get_verify_result': 0,
    'SSL_write': 0,
    'SSL_read': 0,
    'SSL_shutdown': 0,
    'SSL_free': 0,
    'SSL_CTX_free': 0,
    '.TLS_method': 0,
    '.SSL_CTX_new': 0,
    '.TLSv1_client_method': 0,
    '.TLSv1_1_client_method': 0,
    '.TLSv1_2_client_method': 0,
    '.TLSv1_3_client_method': 0,
    '.SSLv2_client_method': 0,
    '.SSLv3_client_method': 0,
    '.SSLv23_client_method': 0,
    '.TLSv1_method': 0,
    '.TLSv1_1_method': 0,
    '.TLSv1_2_method': 0,
    '.TLSv1_3_method': 0,
    '.SSLv2_method': 0,
    '.SSLv3_method': 0,
    '.SSLv23_method': 0,
    '.SSL_CTX_set_verify': 0,
    '.SSL_set_options': 0,
    '.SSL_CTX_set_options': 0,
    '.SSL_CTX_set_min_proto_version': 0,
    '.SSL_CTX_ctrl': 0,
    '.SSL_connect': 0,
    '.SSL_do_handshake': 0,
    '.SSL_set_connect_state': 0,
    '.SSL_get_peer_certificate': 0,
    '.SSL_get_verify_result': 0,
    '.SSL_write': 0,
    '.SSL_read': 0,
    '.SSL_set_verify': 0,
    '.SSL_new': 0,
    '_TLS_method': 0,
    '_SSL_CTX_new': 0,
    '_SSL_set_verify': 0,
    '_SSL_new': 0,
    '.TLS_client_method': 0,
    '_TLSv1_client_method': 0,
    '_TLS_client_method': 0,
    '_TLSv1_1_client_method': 0,
    '_TLSv1_2_client_method': 0,
    '_TLSv1_3_client_method': 0,
    '_SSLv2_client_method': 0,
    '_SSLv3_client_method': 0,
    '_SSLv23_client_method': 0,
    '_TLSv1_method': 0,
    '_TLSv1_1_method': 0,
    '_TLSv1_2_method': 0,
    '_TLSv1_3_method': 0,
    '_SSLv2_method': 0,
    '_SSLv3_method': 0,
    '_SSLv23_method': 0,
    '_SSL_CTX_set_verify': 0,
    '_SSL_set_options': 0,
    '_SSL_CTX_set_options': 0,
    '_SSL_CTX_set_min_proto_version': 0,
    '_SSL_CTX_ctrl': 0,
    '_SSL_connect': 0,
    '_SSL_do_handshake': 0,
    '_SSL_set_connect_state': 0,
    '_SSL_get_peer_certificate': 0,
    '_SSL_get_verify_result': 0,
    '_SSL_write': 0,
    '_SSL_read': 0
}

def remove_no_ssl():
    func_to_func_list_tmp = func_to_func_list
    break_loop = False
    while break_loop == False:
        break_loop = True
        index = 0
        for index in range(0, len(func_to_func_list_tmp)):
            if func_to_func_list_tmp[index][4] == "SSL":
                inter_index = 0
                for inter_index in range(0, len(func_to_func_list_tmp)):
                    if func_to_func_list_tmp[inter_index][2] == func_to_func_list_tmp[index][0] and func_to_func_list_tmp[inter_index][4] == "":
                        func_to_func_list_tmp[inter_index][4] = "SSL"
                        break_loop = False

def match_import_and_export_func_in_one_file(all_lib_list):
    ida_script = result_path + "find_func_ref_in_lib.py"
    for file in all_lib_list:
        txt_file = open("file_name.txt", "w")
        txt_file.write(file)
        txt_file.write("\r\n")
        txt_file.close()
        file_name = os.popen("find ./ -name " + file).read()
        path = os.getcwd()
        file_name = file_name[2:file_name.rfind("\n")]
        command = "ida -A -S\"" + ida_script + " /" + file + "\" " + path + file_name
        os.system(command)

def match_import_func_and_export_func_between_different_libs(import_file, export_file, import_func_list, export_func_list):
    match_import_export = []
    for import_func in import_func_list:
        for export_func in export_func_list:
            if import_func == export_func:
                match_import_export.append([import_file, import_func, export_file, export_func, ""])

    return match_import_export

def find_export_func(file_name, path):
    lib_name_full = os.popen("find ./ -name " + file_name).read()
    sys_table = os.popen("readelf --use-dynamic -a " + os.path.join(path,lib_name_full)).read()
    export_func_list_tmp = []
    sys_table = sys_table[sys_table.find("Symbol table for image:") : ]
    while sys_table.find("FUNC ") >= 0:
        sys_table = sys_table[sys_table.find("FUNC ") : ]
        line = sys_table[ : sys_table.find("\n")]
        sys_table = sys_table[sys_table.find("\n") + 1 : ]
        if line.find("FUNC ") >= 0:
            if line.find(" bad ") >= 0:
                    # export function in library
                export_func = line[line.rfind(" ") + 1: ]
                if import_func_list.count(export_func) > 0:
                    export_func_list_tmp.append(export_func)
    return export_func_list_tmp

def find_lib_and_import_funcs(file_name, path):
    file_name = os.popen("find ./ -name " + file_name).read()
    file_name = file_name[2:file_name.rfind("\n")]
    lib_list = []
    elf_header = os.popen("readelf --use-dynamic -a " + path+file_name).read()
    #if elf_header.find("libssl"):
    last_shared_lib = elf_header.rfind("Shared library")
    start_shared_lib = elf_header.find("Shared library")
    last_pos = elf_header.find("\n", last_shared_lib)
    lib_section = elf_header[start_shared_lib : last_pos]
    lib_name_start = lib_section.find("[")
    while lib_name_start >= 0:
        lib_name_start = lib_name_start + 1
        lib_name_last = lib_section.find("]")
        lib_name = lib_section[lib_name_start : lib_name_last]
        lib_section = lib_section[lib_name_last + 1 : ]
        lib_name_start = lib_section.find("[")
        # delete standard libraries
        if lib_name.find("libcrypto.so") < 0 and lib_name.find("libz.so") and lib_name.find("libgcc") < 0 and lib_name.find("libc.so") < 0 and lib_name.find("libm.so") < 0:
            lib_list.append(lib_name)
    # store the imported functions in the elf header
    return lib_list

def match_import_and_export_func(lib_list, import_func_list):
    lib_func_dir = {}
    for lib_name in lib_list:
        lib_name_full = os.popen("find ./ -name " + lib_name).read()
        sys_table = os.popen("objdump -tT " + lib_name_full).read()
        export_func_list_tmp = []
        while sys_table.find("\n") >= 0:
            line = sys_table[ : sys_table.find("\n")]
            sys_table = sys_table[sys_table.find("\n") + 1 : ]
            if line.find(" g ") >= 0:
                if line.find(" Base ") >= 0:
                    if line.find(" .text") >= 0:
                        # export function in library
                        export_func = line[line.rfind(" ") + 1: ]
                        if import_func_list.count(export_func) > 0:
                            export_func_list_tmp.append(export_func)
        if len(export_func_list_tmp) > 0:
            lib_func_dir[lib_name] = list(set(export_func_list_tmp))
    return lib_func_dir

export_func_list = []

func_list_dir = []
for file in all_lib_list:
    lib_list = find_lib_and_import_funcs(file, file_path)
    all_lib_list.extend(lib_list)
#find all libs that directly or indirectly include by the binary
all_lib_list = list(set(all_lib_list))
leaf_binary = []
all_lib_list_new = []

for file_name in all_lib_list:
    file_name = os.popen("find ./ -name " + file_name).read()
    file_name = file_name[2:file_name.rfind("\n")]
    file_name = os.path.realpath(file_path+file_name)
    file_name = file_name[file_name.rfind("/") + 1:]
    all_lib_list_new.append(file_name)

all_lib_list = all_lib_list_new

def find_the_library_direct_call_libssl(bin_lib, path):
    lib_name_full = os.popen("find ./ -name " + bin_lib).read()
    sys_table = os.popen("readelf --use-dynamic -a " + os.path.join(path,lib_name_full)).read()
    while sys_table.find("FUNC ") >= 0:
        sys_table = sys_table[sys_table.find("FUNC ") : ]
        line = sys_table[ : sys_table.find("\n")]
        sys_table = sys_table[sys_table.find("\n") + 1 : ]
        if line.find("FUNC ") >= 0:
            if line.find(" UND ") >= 0:
                    # export function in library
                import_func = line[line.rfind(" ") + 1: ]
                if import_func in SSL_function:
                    leaf_binary.append(bin_lib)
                    break

for lib in all_lib_list:
    find_the_library_direct_call_libssl(lib, file_path)

ida_script_extract = os.getcwd() + "/get_import_and_export_funcs.py"

for file in all_lib_list:
    file_name = os.popen("find ./ -name " + file).read()
    path = os.getcwd()
    file_name = file_name[2:file_name.rfind("\n")]
    command = "ida -A -S\"" + ida_script_extract + " /" + file + "\" " + path + file_name
    os.system(command)

import_func_file = open(result_path + "import_func.txt", 'r')
export_func_file = open(result_path + "export_func.txt", 'r')

import_export_file_name = []
import_export_func_name_list = []
func_list_dir_import = []

import_line = import_func_file.readline()
lib_name = ""
while import_line:
    if import_line.find(",") <= 0:
        lib_name = import_line[:-1]
    import_funcs = []
    if import_line.find(", ") > 0:
        while import_line.find(", ") > 0:
            import_func_name = import_line[:import_line.find(", ")]
            if len(import_line) >= 3:
                import_line = import_line[import_line.find(", ") + 2:]
                import_funcs.append(import_func_name)
        func_list_dir_import.append({lib_name:import_funcs})
    import_line = import_func_file.readline()


export_line = export_func_file.readline()
func_list_dir_export = []
while export_line:
    if export_line.find(",") <= 0:
        lib_name = export_line[:-1]
    export_funcs = []
    if export_line.find(", ") > 0:
        while export_line.find(", ") > 0:
            export_func_name = export_line[:export_line.find(", ")]
            if len(export_line) >= 3:
                export_line = export_line[export_line.find(", ") + 2:]
                export_funcs.append(export_func_name)
        func_list_dir_export.append({lib_name:export_funcs})
    export_line = export_func_file.readline()

for lib_name_dict_import in func_list_dir_import:
    for lib_name_dict_export in func_list_dir_export:
        for key_import in lib_name_dict_import:
            for key_export in lib_name_dict_export:
                if key_import == key_export:
                    continue
                import_export_file_name = []
                for import_func in lib_name_dict_import[key_import]:
                    for export_func in lib_name_dict_export[key_export]:
                        if import_func == export_func:
                            if [key_import, key_export] not in import_export_file_name:
                                import_export_file_name.append([key_import, key_export])
                            import_export_file_name.append(import_func)
                if len(import_export_file_name) != 0:
                    if import_export_file_name not in import_export_func_name_list:
                        import_export_func_name_list.append(import_export_file_name)
del_lib_to_lib = []

for lib_to_lib_index in range(0,len(import_export_func_name_list)):
    del_list = []
    lib_to_lib = import_export_func_name_list[lib_to_lib_index]
    for fun in range(1,len(lib_to_lib)):
        if lib_to_lib[fun].find("std") == 0:
            del_list.append(lib_to_lib[fun])
    for fun in del_list:
        lib_to_lib.remove(fun)
    if len(lib_to_lib) == 1:
        del_lib_to_lib.append(lib_to_lib)

for i in del_lib_to_lib:
    import_export_func_name_list.remove(i)

BDG = [[0 for i in range(len(all_lib_list))] for j in range(len(all_lib_list))]
for j in all_lib_list:
    if j.find("libssl.so") >= 0:
        for i in leaf_binary:
            BDG[all_lib_list.index(i)][all_lib_list.index(j)] = 1

remove_list = []

loop_break = 0
while True:
    loop_break = 0
    for i in range(0, len(import_export_func_name_list)):
        lib_to_lib = import_export_func_name_list[i]
        parent_binary = lib_to_lib[0][0]
        child_binary = lib_to_lib[0][1]
        if child_binary in leaf_binary:
            if BDG[all_lib_list.index(parent_binary)][all_lib_list.index(child_binary)] != 1:
                BDG[all_lib_list.index(parent_binary)][all_lib_list.index(child_binary)] = 1
                loop_break = 1
        elif child_binary in all_lib_list:
            if sum(BDG[all_lib_list.index(child_binary)]) > 0:
                if BDG[all_lib_list.index(parent_binary)][all_lib_list.index(child_binary)]!= 1:
                    BDG[all_lib_list.index(parent_binary)][all_lib_list.index(child_binary)] = 1
                    loop_break = 1
    if loop_break == 0:
        break

BDG_T = [[0 for j in range(len(all_lib_list))] for i in range(len(all_lib_list))]
for i in range(len(all_lib_list)):
    for j in range(len(all_lib_list)):
        BDG_T[j][i] = BDG[i][j]

delete_lib = []
for i in range(0, len(BDG)):
    if sum(BDG[i]) == 0:
        if sum(BDG_T[i]) == 0:
            delete_lib.append(i)

filtered_lib = []
for i in range(0, len(all_lib_list)):
    if i not in delete_lib:
        filtered_lib.append(all_lib_list[i])

# the final BDG
filtered_BDG = [[0 for j in range(len(filtered_lib))] for i in range(len(filtered_lib))]
filtered_BDG_backup = [[0 for j in range(len(filtered_lib))] for i in range(len(filtered_lib))]
filtered_BDG_backup_3 = [[0 for j in range(len(filtered_lib))] for i in range(len(filtered_lib))]
loop_break = 0
while True:
    loop_break = 0
    for i in range(0, len(import_export_func_name_list)):
        lib_to_lib = import_export_func_name_list[i]
        parent_binary = lib_to_lib[0][0]
        child_binary = lib_to_lib[0][1]
        if child_binary in filtered_lib and parent_binary in filtered_lib:
            if child_binary in leaf_binary:
                if filtered_BDG[filtered_lib.index(parent_binary)][filtered_lib.index(child_binary)] != 1:
                    filtered_BDG[filtered_lib.index(parent_binary)][filtered_lib.index(child_binary)] = 1
                    loop_break = 1
            elif sum(filtered_BDG[filtered_lib.index(child_binary)]) > 0:
                if filtered_BDG[filtered_lib.index(parent_binary)][filtered_lib.index(child_binary)]!= 1:
                    filtered_BDG[filtered_lib.index(parent_binary)][filtered_lib.index(child_binary)] = 1
                    loop_break = 1
    if loop_break == 0:
        break

filtered_BDG_T = [[0 for j in range(len(filtered_lib))] for i in range(len(filtered_lib))]
filtered_BDG_T_backup = [[0 for j in range(len(filtered_lib))] for i in range(len(filtered_lib))]
filtered_BDG_T_backup_3 = [[0 for j in range(len(filtered_lib))] for i in range(len(filtered_lib))]
filtered_BDG_backup_ssl_func = [[0 for j in range(len(filtered_lib))] for i in range(len(filtered_lib))]
filtered_BDG_backup_ssl_func_T = [[0 for j in range(len(filtered_lib))] for i in range(len(filtered_lib))]

for i in range(len(filtered_lib)):
    for j in range(len(filtered_lib)):
        filtered_BDG_T[j][i] = filtered_BDG[i][j]

for i in range(0, len(filtered_lib)):
    for j in range(0, len(filtered_lib)):
        if filtered_BDG[i][j] == 1 and filtered_BDG_T[i][j] == 1:
            for k in range(0, len(import_export_func_name_list)):
                lib_to_lib = import_export_func_name_list[k]
                if lib_to_lib[0][0] == filtered_lib[i] and lib_to_lib[0][1] == filtered_lib[j]:
                    ll_func_list_1 = lib_to_lib[1]
                if lib_to_lib[0][0] == filtered_lib[j] and lib_to_lib[0][1] == filtered_lib[i]:
                    ll_func_list_2 = lib_to_lib[1]
            if len(ll_func_list_2) > len(ll_func_list_1):
                filtered_BDG[i][j] = 0
                filtered_BDG_T[j][i] = 0
            elif len(ll_func_list_1) > len(ll_func_list_2):
                filtered_BDG[j][i] = 0
                filtered_BDG_T[i][j] = 0

filtered_lib_backup = []
filtered_lib_backup_3 = []
filtered_lib_backup_ssl_func = []

for i in range(len(filtered_lib)):
    for j in range(len(filtered_lib)):
        filtered_BDG_backup[i][j] = filtered_BDG[i][j]
        filtered_BDG_T_backup[j][i] = filtered_BDG[i][j]
        filtered_BDG_backup_3[i][j] = filtered_BDG[i][j]
        filtered_BDG_T_backup_3[j][i] = filtered_BDG[i][j]
        filtered_BDG_backup_ssl_func[i][j] = filtered_BDG[i][j]
        filtered_BDG_backup_ssl_func_T[j][i] = filtered_BDG[i][j]
    filtered_lib_backup.append(filtered_lib[i])
    filtered_lib_backup_3.append(filtered_lib[i])
    filtered_lib_backup_ssl_func.append(filtered_lib[i])

##generate the intra_cfg
openssl_leaf_func = []
for key in SSL_function.keys():
    openssl_leaf_func.append(key)

def generatet_call_graph(lib):
    ida_script = result_path + "build_intra_call_graph.py"
    path = os.getcwd()
    file_name = os.popen("find ./ -name " + lib).read()
    command = "ida -A -S\"" + ida_script + " /" + lib + "\" " + path + file_name[2:-1]
    os.system(command)
    delete_lib = []
    for x in range(0, len(filtered_BDG_T[filtered_lib.index(lib)])):
        if filtered_BDG_T[filtered_lib.index(lib)][x] == 1:
            try:
                read_export_func = open(result_path + lib + "_export_func_list.txt", 'r')
                leaf_func_list_all = read_export_func.readlines()
                leaf_func_list = []
                read_export_func.close()
                for line in leaf_func_list_all:
                    line = line.replace("\'", "")
                    line = line.replace(" ", "")
                    line = line[1:-1]
                    line = line.split(',')
                    for i in line:
                        if i != "":
                            leaf_func_list.append(i)
                if len(leaf_func_list) > 0:
                    write_leaf_func_binary = open(result_path + lib +"_export_func_list_binary.txt", 'w')
                    write_leaf_func_binary.write(filtered_lib[x] + "\n")
                    leaf_func_list = list(set(leaf_func_list))
                    write_leaf_func_binary.write(str(leaf_func_list))
                    write_leaf_func_binary.write("\n")
                    write_leaf_func_binary.close()
                if os.path.exists(result_path + filtered_lib[x] +'_leaf_func_list.txt') == True:
                    write_leaf_func = open(result_path + filtered_lib[x] +'_leaf_func_list.txt', 'r')
                    new_leaf_func_list = write_leaf_func.readlines()
                    if len(new_leaf_func_list) != 0:
                        for line in new_leaf_func_list:
                            line = line.replace("\'", "")
                            line = line.replace(" ", "")
                            line = line[1:-1]
                            line = line.split(',')
                            for i in line:
                                i = i.replace("\"", "")
                                leaf_func_list.append(i)
                    write_leaf_func.close()
                write_leaf_func = open(result_path + filtered_lib[x] +'_leaf_func_list.txt', 'w')
                leaf_func_list = list(set())
                write_leaf_func.write(str(leaf_func_list))
                write_leaf_func.close()
            except Exception as e:
                delete_lib.append(filtered_lib[x])
    return delete_lib


break_loop = 0

def Dfs_visit_binary(block_matrix_t, node, visit_BDG, father_BDG, stack_BDG):
    n = len(block_matrix_t)
    visit_BDG[node] = 1
    for i in range(n):  # for all nodes
        if block_matrix_t[i][node] == 1:  # search son in order
            if visit_BDG[i] == 1:
                tmp = node
                circle_begain_index = node
                del stack_BDG[:stack_BDG.index(i)]
                break
            elif visit_BDG[i] == 0:  # son is white
                stack_BDG.append(i)
                father_BDG[i] = node  # father[]: grey node
                Dfs_visit_binary(block_matrix_t, i, visit_BDG, father_BDG, stack_BDG)
                break

filtered_lib_remove_ssl = copy.deepcopy(filtered_lib)

while len(filtered_lib) > 0:
    detect_loop_in_BDG = False
    counter = filtered_BDG
    dindex = len(filtered_BDG)
    index = 0
    while index < dindex:
        if sum(filtered_BDG[index]) == 0: # Leaf binary
            delete_lib = []
            if filtered_lib[index].find("libssl.so") >= 0:
                del filtered_lib_remove_ssl[filtered_lib_remove_ssl.index(filtered_lib[index])]
                del filtered_lib[index]
                for i in range(0,len(filtered_lib) + 1):
                    del filtered_BDG[i][index]
                    del filtered_BDG_T[i][index]
                del filtered_BDG[index]
                del filtered_BDG_T[index]
                dindex = dindex - 1
                continue
            elif filtered_lib[index] in leaf_binary: # binary directly call the SSL/TLS function
                leaf_funcs_list = openssl_leaf_func
                write_leaf_func = open(result_path + filtered_lib[index] +'_leaf_func_list.txt', 'w')
                parent_func = filtered_lib[index]
                for lib_index in range(len(filtered_BDG_backup[filtered_lib_backup.index(parent_func)])):
                    if filtered_BDG_backup[filtered_lib_backup.index(parent_func)][lib_index] == 1:
                        child_func = filtered_lib_backup[lib_index]
                        if os.path.exists(result_path + child_func + "_export_func_list_binary.txt"):
                            file = open(result_path + child_func + "_export_func_list_binary.txt")
                            lines = file.readlines()
                            for line_index in range(len(lines)):
                                if lines[line_index].find(parent_func) >= 0:
                                    append_leaf_func = lines[line_index + 1]
                                    append_leaf_func = append_leaf_func[2: -2]
                                    append_leaf_func_list = append_leaf_func.split("\', \'")
                                    for leaf_func_index in range(len(append_leaf_func_list)):
                                        append_leaf_func_list[leaf_func_index] = append_leaf_func_list[leaf_func_index].replace("\'", "")
                                    leaf_funcs_list = leaf_funcs_list + append_leaf_func_list
                                    break
                write_leaf_func.write(str(leaf_funcs_list))
                write_leaf_func.close()
                delete_lib = generatet_call_graph(filtered_lib[index])
            else:
                delete_lib = generatet_call_graph(filtered_lib[index])
            del filtered_lib[index]
            for index_T in range(0,len(filtered_BDG_T[index])):
                if filtered_BDG_T[index][index_T] == 1:
                    filtered_BDG[index_T][index] = 0
            for i in range(0, len(filtered_lib) + 1):
                del filtered_BDG[i][index]
                del filtered_BDG_T[i][index]
            del filtered_BDG[index]
            del filtered_BDG_T[index]
            dindex = dindex - 1
            for fun in delete_lib:
                for index_T in range(0,len(filtered_BDG_T[filtered_lib.index(fun)])):
                    if filtered_BDG_T[filtered_lib.index(fun)][index_T] == 1:
                        filtered_BDG[index_T][filtered_lib.index(fun)] = 0
                for i in range(0, len(filtered_lib)):
                    del filtered_BDG[i][filtered_lib.index(fun)]
                    del filtered_BDG_T[i][filtered_lib.index(fun)]
                del filtered_BDG[filtered_lib.index(fun)]
                del filtered_BDG_T[filtered_lib.index(fun)]
                filtered_lib.remove(fun)
            break
        if index == len(filtered_lib) - 1:
            detect_loop_in_BDG = True
        index = index + 1
    if detect_loop_in_BDG == True:
        visit_BDG = [0 for j in range(len(filtered_BDG_T))]
        father_BDG = [-1 for j in range(len(filtered_BDG_T))]
        stack_BDG = []
        stack_BDG.append(filtered_lib.index(file_name))
        Dfs_visit_binary(filtered_BDG_T, filtered_lib.index(file_name), visit_BDG, father_BDG, stack_BDG)
        for binary_index in stack_BDG:
            generatet_call_graph(filtered_lib[binary_index])
            export_func_file = open(result_path + filtered_lib[binary_index] +'_export_func_list.txt', 'r')
            export_func_list_str = export_func_file.readlines()
            export_func_list = []
            export_func_file.close()
            for line in export_func_list_str:
                line = line.replace("\'", "")
                line = line.replace(" ", "")
                line = line[1:-1]
                line = line.split(',')
                for i in line:
                    if i != "":
                        export_func_list.append(i)
            if len(export_func_list) == 0:
                for index_j in stack_BDG:
                    if index_j != binary_index:
                        filtered_BDG[index_j][binary_index] = 0
                        filtered_BDG_T[binary_index][index_j] = 0
                        filtered_BDG_backup[index_j][binary_index] = 0
                        filtered_BDG_T_backup[binary_index][index_j] = 0
                        filtered_BDG_backup_ssl_func[index_j][binary_index] = 0
                        filtered_BDG_backup_ssl_func_T[binary_index][index_j] = 0
                        command = 'rm' + result_path + filtered_lib[binary_index] +'_export_func_list.txt'
                        os.system(command)
                        command = 'rm' + result_path + filtered_lib[binary_index] +'_call_graph.txt'
                        os.system(command)
            for index_j in stack_BDG:
                break_loop = False
                for lib_to_lib in import_export_func_name_list:
                    if lib_to_lib[0][0] == filtered_lib[binary_index]:
                        if lib_to_lib[0][1] == filtered_lib[index_j]:
                            for fun in range(1, len(lib_to_lib)):
                                if fun in export_func_list:
                                    filtered_BDG[index_j][binary_index] = 0
                                    filtered_BDG_T[binary_index][index_j] = 0
                                    command = 'rm' + result_path + filtered_lib[index] +'_export_func_list.txt'
                                    os.system(command)
                                    command = 'rm' + result_path + filtered_lib[index] +'_call_graph.txt'
                                    os.system(command)
                                    break_loop = True
                                    break
                            if break_loop == True:
                                break
                if break_loop == False:
                    filtered_BDG_T[index_j][index] = 0
                    filtered_BDG[index][index_j] = 0
                    command = 'rm' + result_path + filtered_lib[index] +'_export_func_list.txt'
                    os.system(command)
                    command = 'rm' + result_path + filtered_lib[index] +'_call_graph.txt'
                    os.system(command)

matrix = []
Func_name = []
All_Road = []
lib_func_num = []
total_num = 0
index = -1

for lib_name in filtered_lib_remove_ssl:
    if lib_name.find("libssl") >= 0:
        continue
    road_file = open(result_path + lib_name + "_all_road.txt", "r")
    lines = road_file.readlines()
    name = ""
    for line in lines:
        if line.find("func_name") >= 0:
            index = index + 1
            All_Road.append([])
            Func_name.append(line[line.rfind(":") + 2 : -1])
            name = line[line.rfind(":") + 2 : -1]
        elif line.find("call_graph") >= 0:
            line = line[line.rfind(":") + 2 : -2]
            line = line.split(",")
            matrix.append(line)
        elif line.find("None") >= 0:
            All_Road[index].append([])
        else:
            road = []
            if line.rfind(",") == (len(line) - 2):
                line = line[:-2]
            else:
                line = line[:-1]
            if line.find(",")>=0:
                road_line = line.split(",")
                for i in range(len(road_line)):
                    if road_line[i] == "next_list":
                        All_Road[index].append(road)
                        road = []
                    else:
                        road.append(road_line[i])
            else:
                All_Road[index].append(line)
    lib_func_num.append(len(Func_name) - total_num)
    total_num = len(Func_name)
for i in range(len(All_Road)):
    for j in range(len(All_Road[i])):
        length = len(All_Road[i][j])
        x = 0
        while x < length:
            if All_Road[i][j][x] == "[]":
                del All_Road[i][j][x]
                x -= 1
                length -= 1
            x += 1

final_matrix = [[0 for j in range(len(Func_name))] for i in range(len(Func_name))]
final_matrix_t = [[0 for j in range(len(Func_name))] for i in range(len(Func_name))]

for index in range(len(Func_name)):
    total_num = 0
    before_number = 0
    after_number = 0
    for func_num in lib_func_num:
        total_num = total_num + func_num
        if total_num >= index:
            before_number = total_num - func_num
            after_number = len(Func_name) - total_num
            break
    for j in range(len(matrix[index])):
        final_matrix[index][j + before_number] = int(matrix[index][j])
for i in range(len(Func_name)):
    for j in range(len(Func_name)):
        final_matrix_t[i][j] = final_matrix[j][i]


function_count = dict(Counter(Func_name))

repeat_func = [k for k,v in function_count.items() if v > 1]
#merge call graph of different binary
delete_func_index = []
for func in repeat_func:
    func_index_list = []
    parent_one = []
    child_one = []
    for func_index in range(len(Func_name)):
        if Func_name[func_index] == func:
            func_index_list.append(func_index)
    for i in func_index_list:
        if sum(final_matrix_t[i]) == 0:
            parent_one.append(i)
        elif sum(final_matrix[i]) == 0:
            child_one.append(i)
            delete_func_index.append(i)
    for m in parent_one:
        for i in child_one:
            for j in range(len(Func_name)):
                final_matrix_t[m][j] = final_matrix_t[i][j]
            All_Road[m] = All_Road[i]

for i in range(len(final_matrix_t)):
    for j in range(len(final_matrix_t[i])):
        final_matrix[i][j] = final_matrix_t[j][i]
index = 0

for func_index in delete_func_index:
    del Func_name[func_index - index]
    del All_Road[func_index - index]
    for i in range(len(final_matrix)):
        del final_matrix[i][func_index-index]
    del final_matrix[func_index - index]
    index = index + 1

final_matrix_t = [[0 for j in range(len(Func_name))] for i in range(len(Func_name))]
for i in range(len(Func_name)):
    for j in range(len(Func_name)):
        final_matrix_t[j][i] = final_matrix[i][j]
j_i = 0
del_list = []
for i in range(len(Func_name)):
    if sum(final_matrix[i]) == 0:
        if Func_name[i] != "start" and Func_name[i] != "_start" and Func_name[i] != "main" and Func_name[i] != "_ftext":
            del_list.append(i)
            j_i = j_i + 1
while True:
    index = 0
    for i in del_list:
        for j in range(len(final_matrix)):
            del final_matrix[j][i - index]
        del final_matrix[i - index]
        del Func_name[i - index]
        del All_Road[i - index]
        index = index + 1
    del_list = []
    for i in range(len(Func_name)):
        if sum(final_matrix[i]) == 0:
            if Func_name[i] != "start" and Func_name[i] != "_start" and Func_name[i] != "main" and Func_name[i] != "_ftext":
                del_list.append(i)
    if len(del_list) == 0:
        break

final_matrix_t = [[0 for j in range(len(Func_name))] for i in range(len(Func_name))]
for i in range(len(Func_name)):
    for j in range(len(Func_name)):
        final_matrix_t[j][i] = final_matrix[i][j]

down_to_up_list = [0 for j in range(len(Func_name))]
#SSL function will be tag as 1 in down_to_up_list
for i in range(len(Func_name)):
    if Func_name[i] in SSL_function:
        down_to_up_list[i] = 1

for i in range(len(Func_name)):
    #all the son function is ssl function, the down_to_up_list is tagged as 1
    if Func_name[i] not in SSL_function:
        out_degree = 0
        # out_degree is the number of son function that is SSL API
        for j in range(len(final_matrix_t)):
            if (final_matrix_t[i][j] == 1) & (Func_name[j] in SSL_function):
                out_degree = out_degree + 1
        if (sum(final_matrix_t[i]) == out_degree) & (out_degree != 0):
            down_to_up_list[i] = 1
            # print Func_name[i]

DFS_SSL = []
#the DFS_SSL is the ssl function and the function that only call the ssl function
for i in range(len(down_to_up_list)):
    if down_to_up_list[i] == 1:
        DFS_SSL.append(Func_name[i])

def DFS_road_read(Test_target, Final_roads, SSL_judge, inline, down_to_up_list):
    # test_target is the function that analyzed
    # final_roads stores the final roads
    # SSL_judge stores the function that only call the SSL API
    # inline stores the 
    global add
    # find first not SSL func
    entrance = -1
    for a in range(len(Test_target)):
        if ('0x' not in Test_target[a]) & (Test_target[a] not in SSL_judge):
            entrance = a
            break
    if entrance == -1:  # ALL SSL
        if inline == 1:
            # simplify in line
            Test_target1 = []
            set_test_target = set(Test_target)
            if len(set_test_target) == len(Test_target):
                for k in range(len(Test_target)):
                    Test_target1.append(Test_target[k])
            # simplify between line
            if Test_target not in Final_roads:
                Final_roads.append(Test_target1)
                add = add + 1
                #print add
        elif inline == 2:
            # simplify between line
            if Test_target not in Final_roads:
                Final_roads.append(Test_target)
                add = add + 1
                #print add
        elif inline == 3:
            Final_roads.append(Test_target)
    else:  # NOT ALL SSL
        func_index = Func_name.index(Test_target[entrance])
        road_count = len(All_Road[func_index]) - 1
        while road_count >= 0:  # for each road
            # update
            Test_target_new = []
            for q in range(len(Test_target)):
                Test_target_new.append(Test_target[q])
            del Test_target_new[entrance]
            # update target_new
            for j in range(len(All_Road[func_index][road_count])):
                h = len(All_Road[func_index][road_count]) - j - 1
                # insert the second parameter to the entrance location in the list
                Test_target_new.insert(entrance, All_Road[func_index][road_count][h])
            Test_target_new_del_list = 0
            if All_Road[func_index][road_count] == []:
                for index in range(len(Test_target_new)):
                    if index >= entrance:
                        if "0x" in Test_target_new[index]:
                            Test_target_new_del_list = Test_target_new_del_list + 1
                        else:
                            break
            for i in range(Test_target_new_del_list):
                del Test_target_new[entrance]
            DFS_road_read(Test_target_new, Final_roads, SSL_judge, inline, down_to_up_list)
            road_count = road_count - 1

def DFS_road_read3():
    Final_roads = []
    matrix_new = copy.deepcopy(final_matrix)
    matrix_new_t = copy.deepcopy(final_matrix_t)
    All_Road_new = copy.deepcopy(All_Road)
    while True:
        for i in range(len(matrix_new)):
            if sum(matrix_new_t[i]) == 0:
                for j in range(len(matrix_new_t[i])):
                    if matrix_new[i][j] == 1: # function j call function i
                        if Func_name[i] in SSL_function:
                            matrix_new_t[j][i] = 0
                            matrix_new[i][j] = 0
                            continue
                        matrix_new_t[j][i] = 0
                        matrix_new[i][j] = 0
                        single_road_list_all = []
                        for m in range(len(All_Road_new[j])): #single road of parent
                            single_road_list = []
                            if Func_name[i] in All_Road_new[j][m]:
                                roads = len(All_Road_new[i])
                                for n in range(roads):
                                    single_road_list.append([])
                                for n in All_Road_new[j][m]: # every function in single road
                                    if n == Func_name[i]: 
                                        for k in range(len(All_Road_new[i])): # all road of child
                                            for p in All_Road_new[i][k]:
                                                single_road_list[k].append(p)
                                    else:
                                        for single_road_tmp in single_road_list:
                                            single_road_tmp.append(n)
                            else:
                                single_road_list.append(All_Road_new[j][m])
                            for single_road_tmp in single_road_list:
                                single_road_list_all.append(single_road_tmp)
                        single_road_list_tmp = []
                        for single_road_tmp in single_road_list_all:
                            if single_road_tmp not in single_road_list_tmp:
                                remove_road = False
                                repeat_func_dict = dict(Counter(single_road_tmp))
                                # & ("SSL_write" not in key) & ("SSL_read" not in key)
                                for key, value in repeat_func_dict.items():
                                    if (value > 1) & ("0x" not in key) & (key in SSL_function):
                                        remove_road = True
                                first_io_func = -1
                                last_non_io_func = -1
                                for func in single_road_tmp:
                                    if func == Func_name[i]:
                                        remove_road = True
                                    if func in SSL_function:
                                        if func in SSL_IO_function:
                                            first_io_func = single_road_tmp.index(func)
                                        elif func not in SSL_IO_function:
                                            last_non_io_func = single_road_tmp.index(func)
                                if (last_non_io_func > first_io_func) & (first_io_func != -1) & (last_non_io_func != -1):
                                    remove_road = True
                                if remove_road == False:
                                    single_road_list_tmp.append(single_road_tmp)
                        if len(single_road_list_tmp) != 0:
                            All_Road_new[j] = copy.deepcopy(single_road_list_tmp)
        sum_num = 0
        for index in range(len(matrix_new)):
            sum_num = sum_num + sum(matrix_new[index])
        if sum_num == 0:
            break
    return All_Road_new
change_mark = 0

print('\n******************************************Middle result')
if "_start" in Func_name:
    c = Func_name.index("_start")
elif "start" in Func_name:
    c = Func_name.index("start")
else:
    c = Func_name.index("main")

print('\n******************************************Final result')
Final_roads = []
Test_target = []
if "_start" in Func_name:
    Test_target.append("_start")
elif "start" in Func_name:
    Test_target.append("start")
elif "main" in Func_name:
    Test_target.append("main")

Final_roads = DFS_road_read3()
All_Road[c] = []
Final_roads = Final_roads[Func_name.index(Test_target[0])]

for i in range(len(Final_roads)):
    for j in range(len(Final_roads[i])):
        if "." in Final_roads[i][j]:
            Final_roads[i][j] = Final_roads[i][j].replace(".", "")
for k in range(len(Final_roads)):
    SSL_API_list = []
    ssl_bool = False
    version_function = 0
    continue_loop = False
    necessary_SSL_function_dum = {}
    for key in necessary_SSL_function.keys():
        necessary_SSL_function_dum[key] = 0
    for road_func in Final_roads[k]:
        if road_func in necessary_SSL_function_dum.keys():
            necessary_SSL_function_dum[road_func] += 1
    for key in necessary_SSL_function_dum.keys():
        if necessary_SSL_function_dum[key] > 1:
            continue_loop = True
    if continue_loop == True:
        continue
    for version_func in SSL_version_function:
        if version_func in Final_roads[k]:
            version_function += 1
    if version_function > 1:
        continue
    if ("SSL_connect" in Final_roads[k]) | ("BIO_connect" in Final_roads[k]) | (("SSL_do_handshake" in Final_roads[k]) & ("SSL_set_connect_state" in Final_roads[k])): # fliter not connect
        IO_function = False
        for func in SSL_IO_function:
            if func in Final_roads[k]:
                IO_function = True
                break
        if IO_function == True:
            for version_func in SSL_version_function:
                if version_func in Final_roads[k]:
                    ssl_bool = True
                    break
            if (("SSL_new" in Final_roads[k]) | ("BIO_new" in Final_roads[k])) & (ssl_bool == True):
                if (("SSL_read" not in Final_roads[k][0]) & ("SSL_write" not in Final_roads[k][0]) & (Final_roads[k][0] != "SSL_get_peer_certificate") & ("0x" not in Final_roads[k][0]) & ("BIO_write" not in Final_roads[k][0]) & ("BIO_read" not in Final_roads[k][0])):
                    if "SSL_read" in Final_roads[k]:
                        SSL_read_index = Final_roads[k].index("SSL_read")
                    if "SSL_write" in Final_roads[k]:
                        SSL_write_index = Final_roads[k].index("SSL_write")
                    if "BIO_read" in Final_roads[k]:
                        BIO_read_index = Final_roads[k].index("BIO_read")
                    if "BIO_write" in Final_roads[k]:
                        BIO_write_index = Final_roads[k].index("BIO_write")
                    if "SSL_new" in Final_roads[k]:
                        SSL_new_index = Final_roads[k].index("SSL_new")
                    elif ("SSL_new" not in Final_roads[k]) & ("BIO_new" in Final_roads[k]):
                        SSL_new_index = Final_roads[k].index("BIO_new")
                    if "SSL_do_handshake" in Final_roads[k]:
                        ssl_do_handshake_index = Final_roads[k].index("SSL_do_handshake")
                        if "SSL_read" in Final_roads[k]:
                            if ssl_do_handshake_index > SSL_read_index:
                                continue
                        if "SSL_write" in Final_roads[k]:
                            if ssl_do_handshake_index > SSL_write_index:
                                continue
                    if "SSL_get_peer_certificate" in Final_roads[k]:
                        SSL_get_peer_certificate_index = Final_roads[k].index("SSL_get_peer_certificate")
                        if "SSL_read" in Final_roads[k]:
                            if SSL_read_index < SSL_get_peer_certificate_index:
                                continue
                        if "SSL_write" in Final_roads[k]:
                            if SSL_write_index < SSL_get_peer_certificate_index:
                                continue
                    if "SSL_connect" in Final_roads[k]:
                        ssl_connect_index = Final_roads[k].index("SSL_connect")
                        if "SSL_read" in Final_roads[k]:
                            if SSL_read_index < ssl_connect_index:
                                continue
                        if "SSL_write" in Final_roads[k]:
                            if SSL_write_index < ssl_connect_index:
                                continue
                    for ssl_fun in SSL_version_function:
                        if ssl_fun in Final_roads[k]:
                            version_index = Final_roads[k].index(ssl_fun)
                            if "SSL_connect" in Final_roads[k]:
                                ssl_connect_index = Final_roads[k].index("SSL_connect")
                            if ("SSL_connect" not in Final_roads[k]) & ("BIO_connect" in Final_roads[k]):
                                ssl_connect_index = Final_roads[k].index("BIO_connect")
                            elif "SSL_do_handshake" in Final_roads[k]:
                                ssl_connect_index = Final_roads[k].index("SSL_do_handshake")
                            if "SSL_read" in Final_roads[k]:
                                if (version_index < SSL_read_index) & (ssl_connect_index > version_index):
                                    All_Road[c].append(Final_roads[k])
                                    break
                            elif "SSL_write" in Final_roads[k]:
                                if (version_index < SSL_write_index) & (ssl_connect_index > version_index):
                                    All_Road[c].append(Final_roads[k])
                                    break
                            elif "BIO_read" in Final_roads[k]:
                                if (version_index < BIO_read_index) & (ssl_connect_index > version_index):
                                    All_Road[c].append(Final_roads[k])
                                    break
                            elif "BIO_write" in Final_roads[k]:
                                if (version_index < BIO_write_index) & (ssl_connect_index > version_index):
                                    All_Road[c].append(Final_roads[k])
                                    break
# store final result
for j in range(len(All_Road[c])):
    for k in range(len(All_Road[c][j])):
        if "." in All_Road[c][j][k]:
            All_Road[c][j][k] = All_Road[c][j][k][1:]

output = open(result_path + '/Road_final.txt', 'w+')
for j in range(len(All_Road[c])):
    for k in range(len(All_Road[c][j])):
        output.write(All_Road[c][j][k])
        output.write(' ')
    output.write('\n')
output.close()
# print('\n****************************************** parement')
parement = {}
parement_value_mark = 0

items = os.listdir(result_path)
binary_file = ""
for item in items:
    if (item.find("_func_list.txt") >= 0) & (item.find("export_func_list")) & (item.find("leaf_func_list")):
        func_list_file = open(result_path + item)
        line = func_list_file.readline()
        if line.find("_set_verify") >= 0:
            binary_file = item
            break

func_binary = binary_file[:binary_file.find("_func_list.txt")]
ida_script = result_path + "parameter_analysis.py"

file_name = os.popen("find ./ -name " + func_binary).read()
command = "ida -A -S\"" + ida_script + " /" + func_binary + "\" " + result_path + file_name[3:-1]
os.system(command)

parameter_file = open(result_path + "parameter_result.txt")
paramter_line = parameter_file.readline()
paramter_line_list = paramter_line.split(" ")
if len(paramter_line_list) > 0:
    parement[str(hex(int(paramter_line_list[0])))+"L"] = paramter_line_list[1]
    parement_value_mark = 1
else:
    parement_value_mark = 0
target_fun='None'
parameter_file.close()
# print('\n****************************************** report')

Method = [0 for j in range(len(All_Road[c]))]
Verify = [0 for j in range(len(All_Road[c]))]

for road_list_index in range(len(All_Road)):
    for road_index in range(len(All_Road[road_list_index])):
        for idx in range(len(All_Road[road_list_index][road_index])):
            if All_Road[road_list_index][road_index][idx].find(".") >= 0:
                All_Road[road_list_index][road_index][idx] = All_Road[road_list_index][road_index][idx].replace(".","")
for i in range(len(All_Road[c])):
    if ('TLSv1_client_method' in All_Road[c][i])|('TLSv1_method' in All_Road[c][i]):
        Method[i] = 1
    if ('TLSv1_1_client_method' in All_Road[c][i])|('TLSv1_1_method' in All_Road[c][i]):
        Method[i] = 2
    if ('SSLv2_client_method' in All_Road[c][i])|('SSLv2_method' in All_Road[c][i]):
        Method[i] = 3
    if ('SSLv3_client_method' in All_Road[c][i])| ('SSLv3_method' in All_Road[c][i]):
        Method[i] = 4
    if ('SSLv23_client_method' in All_Road[c][i])|('SSLv23_method' in All_Road[c][i]):
        Method[i] = 5
        if ('SSL_set_options' in All_Road[c][i]) | ('SSL_CTX_set_options' in All_Road[c][i]):
            Method[i] = 5.5
    if ('TLS_client_method' in All_Road[c][i])|('TLS_method' in All_Road[c][i]):
        Method[i] = 6
        if ('SSL_set_options' in All_Road[c][i]) | ('SSL_CTX_set_options' in All_Road[c][i]) | ('.SSL_set_options' in All_Road[c][i]) | ('.SSL_CTX_set_options' in All_Road[c][i]):
            if 'SSL_set_options' in All_Road[c][i]:
                n=All_Road[c][i].index("SSL_set_options") + 1
            elif 'SSL_CTX_set_options' in All_Road[c][i]:
                n=All_Road[c][i].index("SSL_CTX_set_options") + 1
            if All_Road[c][i][n] in parement:
                if parement[All_Road[c][i][n]] == '2000000h':
                    Method[i] = 6.6
    if ('TLSv1_2_client_method' in All_Road[c][i])|('TLSv1_2_method' in All_Road[c][i]):
        Method[i] = 7
    if ('TLSv1_3_client_method' in All_Road[c][i])|('TLSv1_3_method' in All_Road[c][i]):
        Method[i] = 8

    if ('SSL_CTX_set_verify' not in All_Road[c][i])&('SSL_set_verify' not in All_Road[c][i]):
        if ('SSL_get_peer_certificate' in All_Road[c][i]) & ('SSL_get_verify_result' in All_Road[c][i]):#correct
            Verify[i] = 1
        elif ('SSL_get_peer_certificate' not in All_Road[c][i]) & ('SSL_get_verify_result' in All_Road[c][i]):#wrong
            Verify[i] = 2
        elif ('SSL_get_peer_certificate' in All_Road[c][i]) & ('SSL_get_verify_result' not in All_Road[c][i]):#wrong
            Verify[i] = 3
        elif ('SSL_get_peer_certificate' not in All_Road[c][i]) & ('SSL_get_verify_result' not in All_Road[c][i]):#wrong
            Verify[i] = 4
    else: #'SSL_set_verify' in All_Road[c][i]
        if parement_value_mark==1:
            if 'SSL_CTX_set_verify'in All_Road[c][i]:
                n=All_Road[c][i].index("SSL_CTX_set_verify") + 1
            elif 'SSL_set_verify'in All_Road[c][i]:
                n=All_Road[c][i].index("SSL_set_verify") + 1
            if parement[All_Road[c][i][n]]=='0':
                if ('SSL_get_peer_certificate' in All_Road[c][i]) & ('SSL_get_verify_result' in All_Road[c][i]):
                    Verify[i] = 5
                elif ('SSL_get_peer_certificate' not in All_Road[c][i]) & ('SSL_get_verify_result' in All_Road[c][i]):
                    Verify[i] = 6
                elif ('SSL_get_peer_certificate' in All_Road[c][i]) & ('SSL_get_verify_result' not in All_Road[c][i]):
                    Verify[i] = 7
                elif ('SSL_get_peer_certificate' not in All_Road[c][i]) & ('SSL_get_verify_result' not in All_Road[c][i]):
                    Verify[i] = 8
            else:#1
                Verify[i] = 9#correct
        elif('SSL_get_peer_certificate' in All_Road[c][i]) & ('SSL_get_verify_result' in All_Road[c][i]):
                Verify[i] = 10
        else:
            output = open('E:/result/12.04/RD_need.txt', 'a')
            output.write(folder)
            if "SSL_CTX_set_verify" in function_mark:
                output.write("SSL_CTX_set_verify")
                for addr in XrefsTo(idc.get_name_ea_simple("SSL_CTX_set_verify"), 0):
                    output.write(str(addr.frm))
                    # output.write(idc.get_name_ea_simple(addr.frm))
            if "SSL_CTX_set_options" in function_mark:
                output.write("SSL_CTX_set_options")
                for addr in XrefsTo(idc.get_name_ea_simple("SSL_CTX_set_options"), 0):
                    output.write(str(addr.frm))
                    # output.write(idc.get_name_ea_simple(addr.frm))
            if "SSL_set_options" in function_mark:
                output.write("SSL_set_options")
                for addr in XrefsTo(idc.get_name_ea_simple("SSL_set_options"), 0):
                    output.write(str(addr.frm))
                    # output.write(idc.get_name_ea_simple(addr.frm))
            output.write('\n')
            output.close()

output = open(result_path  + '/Report_verify.txt', 'w+')
output.write(str(len(Verify)))
output.write('\n')
output.write("Correct"+str(Verify.count(1))+" Roads don't use SSL_CTX_set_verify. but use SSL_get_peer_certificate & SSL_get_verify_result")
output.write('\n')
output.write('Road_index:')
for i in range(len(Verify)):
    if Verify[i]==1:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write("Wrong"+str(Verify.count(2))+" Roads don't use SSL_CTX_set_verify & SSL_get_peer_certificate, only use SSL_get_verify_result")
output.write('\n')
output.write('Road_index:')
for i in range(len(Verify)):
    if Verify[i]==2:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write("Wrong"+str(Verify.count(3))+" Roads don't use SSL_CTX_set_verify & SSL_get_verify_result, only use SSL_get_peer_certificate")
output.write('\n')
output.write('Road_index:')
for i in range(len(Verify)):
    if Verify[i]==3:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write("Wrong"+str(Verify.count(4))+" Roads don't use SSL_CTX_set_verify & SSL_get_verify_result & SSL_get_peer_certificate")
output.write('\n')
output.write('Road_index:')
for i in range(len(Verify)):
    if Verify[i]==4:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write("Correct"+str(Verify.count(5))+" Roads use SSL_CTX_set_verify and its parament is SSL_VERIFY_NONE. But use SSL_get_peer_certificate & SSL_get_verify_result")
output.write('\n')
output.write('Road_index:')
for i in range(len(Verify)):
    if Verify[i]==5:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write("Wrong"+str(Verify.count(6))+" Roads use SSL_CTX_set_verify and its parament is SSL_VERIFY_NONE. Don't use SSL_get_peer_certificate, only use SSL_get_verify_result")
output.write('\n')
output.write('Road_index:')
for i in range(len(Verify)):
    if Verify[i]==6:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write("Wrong"+str(Verify.count(7))+" Roads use SSL_CTX_set_verify and its parament is SSL_VERIFY_NONE. Don't use SSL_get_verify_result, only use SSL_get_peer_certificate")
output.write('\n')
output.write('Road_index:')
for i in range(len(Verify)):
    if Verify[i]==7:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')
output.write("Wrong"+str(Verify.count(8))+" Roads use SSL_CTX_set_verify and its parament is SSL_VERIFY_NONE. Don't use SSL_get_verify_result & SSL_get_peer_certificate")
output.write('\n')
output.write('Road_index:')
for i in range(len(Verify)):
    if Verify[i]==8:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write("Correct"+str(Verify.count(9))+" Roads use SSL_CTX_set_verify and its parament is SSL_VERIFY_PEER.")
output.write('\n')
output.write('Road_index:')
for i in range(len(Verify)):
    if Verify[i]==9:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write('\n')
output.write("Correct"+str(Verify.count(10))+" Roads use SSL_CTX_set_verify & use SSL_get_peer_certificate & SSL_get_verify_result")
output.write('\n')
output.write('Road_index:')
for i in range(len(Verify)):
    if Verify[i]==10:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')
output.close()

output = open(result_path + '/Report_method.txt', 'w+')
output.write(machine)
output.write(str(len(Method)))
output.write('\n')
output.write(str(Method.count(1))+' Roads use TLSv1_(client_)method')
output.write('\n')
output.write('Road_index:')
for i in range(len(Method)):
    if Method[i]==1:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write(str(Method.count(2))+' Roads use TLSv1_1_(client_)method')
output.write('\n')
output.write('Road_index:')
for i in range(len(Method)):
    if Method[i]==2:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write(str(Method.count(3))+' Roads use SSLv2_(client_)method')
output.write('\n')
output.write('Road_index:')
for i in range(len(Method)):
    if Method[i]==3:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write(str(Method.count(4))+' Roads use SSLv3_(client_)method')
output.write('\n')
output.write('Road_index:')
for i in range(len(Method)):
    if Method[i]==4:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write(str(Method.count(5))+' Roads only use SSLv23_(client_)method')
output.write('\n')
output.write('Road_index:')
for i in range(len(Method)):
    if Method[i]==5:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write(str(Method.count(5.5))+' Roads use SSLv23_(client_)method & SSL_(CTX_)set_options:')
output.write('\n')
output.write('Road_index:')
for i in range(len(Method)):
    if Method[i]==5.5:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')


output.write(str(Method.count(6))+' Roads use TLS_(client_)method')
output.write('\n')
output.write('Road_index:')
for i in range(len(Method)):
    if Method[i]==6:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write(str(Method.count(6.5)) + ' Roads use TLS_(client)_method and SSL_CTX_set_min_proto_version and the minimum version is higher than SSL 3.0')
output.write('\n')

output.write('Road_index:')
for i in range(len(Method)):
    if Method[i] == 6.5:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write(str(Method.count(6.6)) + ' Roads use TLS_(client)_method and SSL_(CTX_)set_options and disable SSL 3.0:')
output.write('\n')

output.write('Road_index:')
for i in range(len(Method)):
    if Method[i] == 6.6:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write(str(Method.count(7))+' Roads use TLSv1_2_(client_)method')
output.write('\n')
output.write('Road_index:')
for i in range(len(Method)):
    if Method[i]==7:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')

output.write(str(Method.count(8))+' Roads use TLSv1_3_(client_)method')
output.write('\n')
output.write('Road_index:')
for i in range(len(Method)):
    if Method[i]==8:
        output.write(str(i))
        output.write(',')
output.write('\n')
output.write('\n')
output.close()
