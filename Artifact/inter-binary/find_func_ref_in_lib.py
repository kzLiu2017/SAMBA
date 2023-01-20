import idautils
import idc as idc
from idaapi import *
import time
import sys
from ast import literal_eval

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
    'BIO_read': 0,
    'BIO_write': 0,
    'SSL_CTX_new': 0,
    'BIO_new': 0,
    'BIO_new_connect': 0,
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
    '.BIO_read': 0,
    '.BIO_write': 0,
    '.SSL_set_verify': 0,
    '.SSL_new': 0,
    '.BIO_new': 0,
    '.BIO_new_connect': 0,
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
    '_SSL_read': 0,
    '_BIO_read': 0,
    '_BIO_write': 0,
    '_BIO_new': 0,
    '_BIO_new_connect': 0
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
    'BIO_read': 0,
    'BIO_write': 0,
    'SSL_shutdown': 0,
    'SSL_free': 0,
    'SSL_CTX_free': 0,
    'BIO_new': 0,
    'BIO_new_connect': 0,
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
    '.BIO_read': 0,
    '.BIO_write': 0,
    '.SSL_set_verify': 0,
    '.SSL_new': 0,
    '.BIO_new': 0,
    '.BIO_new_connect': 0,
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
    '_SSL_read': 0,
    '_BIO_read': 0,
    '_BIO_write': 0,
    '_BIO_new': 0,
    '_BIO_new_connect': 0,
}
idaapi.autoWait()
result_path = os.getcwd()
result_path = result_path[:result_path.find("squashfs-root/") + 14]
txt_file = open(result_path + "func_to_func_list.txt", "r")
func_to_func_str = txt_file.readlines()
txt_file.close()
txt_file = open(result_path + "file_name.txt", "r")
read_lines = txt_file.readlines()
txt_file.close()

filename = read_lines[0][ : len(read_lines[0]) - 1]
if len(read_lines) > 1:
    export_func_list = read_lines[1]
    export_func_list = literal_eval(export_func_list)
else:
    export_func_list = []

func_to_func_str = func_to_func_str[0]
func_to_func_list = literal_eval(func_to_func_str)

filename = filename[:-1]
#get all the import functions from the elf header
import_fun_list_all = []

for index in range(0,len(func_to_func_list)):
    if func_to_func_list[index][0][0] == filename and len(func_to_func_list[index][1]) > 0:
        for func_name_index in range(1, len(func_to_func_list[index])):
            if func_to_func_list[index][func_name_index] != "stdin" and func_to_func_list[index][func_name_index] != "clock_gettime" and func_to_func_list[index][func_name_index] != "g_server_ip" and  func_to_func_list[index][func_name_index] != "pmortem_connect_and_send" and func_to_func_list[index][func_name_index] != "gIceRunning":
                import_fun_list_all.append(func_to_func_list[index][func_name_index])

import_func_list_tmp = []
import_func_list = []

if len(import_fun_list_all) == 0:
    for key in SSL_function:
        import_fun_list_all.append(key)

def match_import_and_export_func(func_index):
    for father_index in range(0, len(matrix[func_index])):
        if matrix[func_index][father_index] == 1:
            if function_Mark[father_index] in export_func_list:
                if function_Mark[father_index] not in import_func_list_tmp:
                    import_func_list_tmp.append(function_Mark[father_index])
            else:
                match_import_and_export_func(father_index)

bool_SSL_function = False
def find_func_ref_to_ssl_func(func_addr):
    global bool_SSL_function
    ssl_func_name = GetFunctionName(func_addr)

    for addr in XrefsFrom(func_addr, 0):
        if GetFunctionName(addr.to) == ssl_func_name:
            find_func_ref_to_ssl_func(addr.to)

        elif SSL_function.has_key(GetFunctionName(addr.to)) == True:
            bool_SSL_function = True

index = 0

is_last_lib = True

export_func_list = []
for index in range(0,len(func_to_func_list)):
    if func_to_func_list[index][0][1] == filename and len(func_to_func_list[index][1]) > 0:
        for func_name_index in range(1, len(func_to_func_list[index])):
            export_func_list.append(func_to_func_list[index][func_name_index])

function_mark = {}
for func in idautils.Functions():
    if get_func_name(func).find(".") >= 0:
        function_mark[get_func_name(func).replace(".", "")] = 0
    else:
        function_mark[get_func_name(func)] = 0

for key in function_mark:
    if key in import_fun_list_all:
        function_mark[key] = 1

while True:
    counter = len(function_mark)
    for key in function_mark:
        if function_mark[key] == 1:
            # print ('son---------', key)
            for addr in XrefsTo(idc.LocByName(key), 0):
            # idautils.CodeRef
                if get_func_name(addr.frm) in function_mark.keys():
                    if function_mark[get_func_name(addr.frm)] == 0:
                        # print 'father of ', key, '------', get_func_name(addr.frm)
                        function_mark[get_func_name(addr.frm)] = 1
                        counter = counter - 1
                if type(get_func_name(addr.frm)) != str:  # code
                    for x in XrefsTo(addr.frm, 0):
                        if type(get_func_name(x.frm)) == str:# idautils.CodeRef
                            if function_mark[get_func_name(x.frm)] == 0:
                                # print 'father of ', key, '------', get_func_name(x.frm)
                                function_mark[get_func_name(x.frm)] = 1
                                counter = counter - 1

    if counter == len(function_mark):
        break

function_Mark = []
for item in function_mark:
    # print type(item),item,function_mark[item]
   if (function_mark[item] == 1) & (type(item)==str):
        function_Mark.append(item)

n = len(function_Mark)

matrix = [[0 for j in range(n)] for i in range(n)]
for i in range(len(function_Mark)):
    for addr in XrefsTo(idc.LocByName(function_Mark[i]), 0):  # idautils
        if get_func_name(addr.frm) in function_Mark:
            matrix[i][function_Mark.index(get_func_name(addr.frm))] = 1
        else:
            for x in XrefsTo(addr.frm, 0):
                if type(get_func_name(x.frm)) == str:  # idautils.CodeRef
                    matrix[i][function_Mark.index(get_func_name(x.frm))] = 1
                elif (get_func_name(x.frm) == None):
                    for m in XrefsTo(x.frm):
                        if get_func_name(m.frm) in function_Mark:
                            matrix[i][function_Mark.index(get_func_name(m.frm))] = 1

n = len(function_Mark)
for i in range(n):
    if matrix[i][i] == 1:
        matrix[i][i] = 0
# Matrix 'T
matrix_t = [[0 for j in range(n)] for i in range(n)]
for i in range(n):
    for j in range(n):
        matrix_t[j][i] = matrix[i][j]

def Dfs_visit(matrix, node, visit, father, function_Mark):
    n = len(matrix)
    visit[node] = 1
    for i in range(n):  # for all nodes
        if matrix[i][node] == 1:  # search son in order
            if visit[i] == 1:  # &(i!=father[node])# son is grey && not point to father
                tmp = node
                circle_begain_index = node
                while tmp != i:
                    tmp = father[tmp]
                circle_end_index = tmp
                matrix[circle_end_index][circle_begain_index] = 0
                matrix_t[circle_begain_index][circle_end_index] = 0
            elif visit[i] == 0:  # son is white
                father[i] = node  # father[]: grey node
                Dfs_visit(matrix, i, visit, father, function_Mark)
    visit[node] = 2

visit = [0 for j in range(n)]
father = [-1 for j in range(n)]
for j in range(n):
    if sum(matrix[j]) == 0:
        if visit[j] == 0:
            Dfs_visit(matrix, j, visit, father, function_Mark)

for index in range(0,len(import_fun_list_all)):
    func_name = import_fun_list_all[index]
    if func_name in function_Mark:
        match_import_and_export_func(function_Mark.index(func_name))

func_to_func_list_new = []
for index in range(0, len(func_to_func_list)):
    func_to_func_list_new.append([])
for index in range(0, len(func_to_func_list)):
    if func_to_func_list[index][0][1] == filename:
        func_to_func_list_new[index].append(func_to_func_list[index][0])
        for fun_index in range(0, len(import_func_list_tmp)):
            func_to_func_list_new[index].append(import_func_list_tmp[fun_index])
    else:
        func_to_func_list_new[index] = func_to_func_list[index]

txt_file = open(result_path + "func_to_func_list.txt", "w")
txt_file.write(str(func_to_func_list_new))
txt_file.close()

idc.Exit(0)