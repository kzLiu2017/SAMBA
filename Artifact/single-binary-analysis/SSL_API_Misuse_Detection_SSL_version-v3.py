#!/usr/bin/env python
import idautils
import idc as idc
from idaapi import *
import time
import os
import sys
import binascii
import ida_nalt
import copy
from collections import Counter

ida_auto.auto_wait()
sys.setrecursionlimit(100000)
result_path = 'E:/result/ssl-file/20.04/'
folder = get_root_filename()
info = idaapi.get_inf_structure()
if info.procName == "ARM":
    machine = "arm"
elif (info.procName == "mipsl") | (info.procName == "mipsb"):
    machine = "mips"
elif info.procName == "metapc":
    machine = "X86-64"

# Find all functions' name and address
function_name = {}
for func in idautils.Functions():
    function_name[get_func_name(func)] = func

library_function = {
    'socket': 0,
    'fopen': 0,
}

if not os.path.exists(result_path + folder):
    os.makedirs(result_path + folder)
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
    'BIO_read': 0,
    'BIO_write': 0,
    'SSL_CTX_new': 0,
    'BIO_new': 0,
    'BIO_new_connect': 0,
    'exit': 0,
    '.exit': 0,
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
    '_exit': 0,
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
    'exit': 0,
    '.exit': 0,
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
    '_exit': 0,
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

# print('**********************************have these functions')
for key in function_name:
    if key in necessary_SSL_function:
        necessary_SSL_function[key] = 1

# print('\n******************************************fliter_initial')
function_mark = {}
for func in idautils.Functions():
    function_mark[get_func_name(func)] = 0

for key in function_mark:
    if key in SSL_function:
        function_mark[key] = 1

while True:
    counter = len(function_mark)
    for key in function_mark:
        if key.find("exit")>=0:
            continue
        if function_mark[key] == 1:
            for addr in XrefsTo(idc.get_name_ea_simple(key), 0):
            # idautils.CodeRef
                if get_func_name(addr.frm) in function_mark.keys():
                    if function_mark[get_func_name(addr.frm)] == 0:
                        function_mark[get_func_name(addr.frm)] = 1
                        counter = counter - 1
                if type(get_func_name(addr.frm)) != str:  # code
                    for x in XrefsTo(addr.frm, 0):
                        if type(get_func_name(x.frm)) == str:# idautils.CodeRef
                            if function_mark[get_func_name(x.frm)] == 0:
                                function_mark[get_func_name(x.frm)] = 1
                                counter = counter - 1

    if counter == len(function_mark):
        break

function_Mark = []
for item in function_mark:
    if (function_mark[item] == 1) & (type(item)==str):
        if machine.find("X86-64") >= 0:
            if item in necessary_SSL_function:
                if item.find('.') >= 0:
                    function_Mark.append(item)
            else:
                function_Mark.append(item)
        else:
            function_Mark.append(item)

# print('\n*****************************************function address')
with open(result_path + folder + "/fun_address.txt", "w") as f:
    for i in range(len(function_Mark)):
        if function_Mark[i] not in SSL_function:
            func = idaapi.get_func(idc.get_name_ea_simple(function_Mark[i]))
            a = str(hex(func.start_ea))
            b = str(hex(func.end_ea))
            a = a[2:len(a) - 1]
            b = b[2:len(b) - 1]
            # f.write('python3 /Users/tomrush/Desktop/Symbolic\ Execution/s.py -f /Users/tomrush/Desktop/CODE/GU/davinci -s '+a+' -e '+b)
            f.write(a + " " + b)
            f.write('\n')
f.close()
# Matrix
n = len(function_Mark)

matrix = [[0 for j in range(n)] for i in range(n)]
for i in range(len(function_Mark)):
    for addr in XrefsTo(idc.get_name_ea_simple(function_Mark[i]), 0):  # idautils
        # print "addr",addr.frm
        # print ("name",get_func_name(addr.frm))
        if get_func_name(addr.frm) in function_Mark:
            matrix[i][function_Mark.index(get_func_name(addr.frm))] = 1
        else:
            for x in XrefsTo(addr.frm, 0):
                if get_func_name(x.frm) in function_Mark:
                    if type(get_func_name(x.frm)) == str:  # idautils.CodeRef
                        matrix[i][function_Mark.index(get_func_name(x.frm))] = 1
                    elif (get_func_name(x.frm) == None):
                        for m in XrefsTo(x.frm):
                            if get_func_name(m.frm) in function_Mark:
                                matrix[i][function_Mark.index(get_func_name(m.frm))] = 1
if '_start' in function_Mark:
    s_index = function_Mark.index('_start')
else:
    s_index = function_Mark.index('main')

for i in range(len(matrix[s_index])):
    if (matrix[s_index][i]==1) & (function_Mark[i]=='main'):
        matrix[s_index][i]=0
if 'main' in function_Mark:
    m_index=function_Mark.index('main')
    for i in range(len(matrix[m_index])):
        if (matrix[m_index][i] == 1) & (function_Mark[i] != '_start'):
            matrix[m_index][i]=0

j_i = 0
del_list = []

for i in range(len(function_Mark)):
    if sum(matrix[i]) == 0:
        if (function_Mark[i] != "_start") and (function_Mark[i] != "main") and (function_Mark[i] != "_ftext"):
            del_list.append(i)
            j_i = j_i + 1

while True:
    index = 0
    for i in del_list:
        del matrix[i - index]
        for j in range(len(matrix)):
            del matrix[j][i - index]
        del function_Mark[i - index]
        index = index + 1
    del_list = []
    for i in range(len(function_Mark)):
        if sum(matrix[i]) == 0:
            if (function_Mark[i] != "_start") and (function_Mark[i] != "main") and (function_Mark[i] != "_ftext"):
                del_list.append(i)
    if len(del_list) == 0:
        break
n = len(function_Mark)
# Matrix 'T
matrix_t = [[0 for j in range(n)] for i in range(n)]
for i in range(n):
    for j in range(n):
        matrix_t[j][i] = matrix[i][j]
# print('\n***************************************Breaking function Circle')

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

matrix_with_cycle = [[0 for j in range(n)] for i in range(n)]
matrix_with_cycle_t = [[0 for j in range(n)] for i in range(n)]
for j in range(n):
    if sum(matrix[j]) == 0:
        if visit[j] == 0:
            Dfs_visit(matrix, j, visit, father, function_Mark)
print('\n***************************************del leave')
count_which_del = []
for i in range(n):
    if (sum(matrix_t[i]) == 0) & (function_Mark[i] not in SSL_function.keys()):
        count_which_del.append(i)
mark = 1
while mark == 1:
    # delete
    for k in range(len(count_which_del)):
        i = count_which_del[k]
        del matrix[i]
        for j in range(len(matrix)):
            del matrix[j][i]
        del matrix_t[i]
        for j in range(len(matrix_t)):
            del matrix_t[j][i]
        # delete name list
        del function_Mark[i]
        # update index
        for m in range(len(count_which_del)):
            count_which_del[m] = count_which_del[m] - 1
    #recounting
    count_which_del = []
    for i in range(len(function_Mark)):
        if (sum(matrix_t[i]) == 0) & (function_Mark[i] not in SSL_function.keys()):
            count_which_del.append(i)
    if len(count_which_del) == 0:
        mark = 0

print('\n**************************************save file')
with open(result_path + folder + "/fun_name.txt", "w") as f:
    for i in range(len(function_Mark)):
        f.write(function_Mark[i])
        f.write('\n')
f.close()

with open(result_path + folder + "/matrix.txt", "w") as f:
    for i in range(len(matrix)):
        for j in range(len(matrix)):
            f.write(str(matrix[i][j]))
            f.write(' ')
        f.write('\n')
f.close()

print('\n***************************************build ALL_roads')
Func_name = function_Mark

# have circle or not
def Dfs_visit_block(block_matrix_t, node, visit, father, block_address, cycle_in_cfg):
    n = len(block_matrix_t)
    visit[node] = 1
    for i in range(n):  # for all nodes
        if block_matrix_t[i][node] == 1:  # search son in order
            if visit[i] == 1:  # &(i!=father[node])# son is grey && not point to father
                tmp = node
                circle_begin_index = node
                while tmp != i:
                    tmp = father[tmp]
                circle_end_index = tmp
                block_matrix_t[circle_end_index][circle_begin_index] = 0
                block_matrix[circle_begin_index][circle_end_index] = 0
                cycle_in_cfg.append([circle_begin_index, circle_end_index])
            elif visit[i] == 0:  # son is white
                father[i] = node  # father[]: grey node
                Dfs_visit_block(block_matrix_t, i, visit, father, block_address, cycle_in_cfg)
    visit[node] = 2

# dfs output all roads
def DFS_road_search(Block_matrix, Node, Road, SSL, func_road):
    SSL_func = SSL
    if sum(Block_matrix[Node]) == 0:  # have no sons
        if block_information[Node][0] != "None":
            Road = Road + block_information[Node]
            SSL_func = 1
        if SSL_func == 1:
            func_road.append(Road)
    else:  # have sons
        if block_information[Node][0] != "None":
            Road = Road + block_information[Node]
            SSL_func = 1
        son_set = []
        for i in range(len(Block_matrix)):
            if Block_matrix[Node][i] == 1:
                if [Node, i] in cycle_in_cfg:
                    cycle_in_cfg.remove([Node, i])
                    Block_matrix[Node][i] = 0
                son_set.append(i)
        while len(son_set) > 0:
            Road1=[]
            for item in Road:
                Road1.append(item)
            DFS_road_search(Block_matrix, son_set[0], Road1, SSL_func, func_road)
            del son_set[0]
        
def delete_block_lib(matrix, father_block):
    if sum(matrix[father_block]) == 1:
        for i in range(matrix):
            matrix[father_block][i] = 0
            delete_block_lib(matrix, i)

def Matrix_decrease(block_matrix, block_matrix_t, block_information):
    count_which_del = [] # ascending order list # store which function needed to be deleted
    cycle_block = False
    for i in range(len(block_matrix)):
        break_loop = False
        if (sum(block_matrix_t[i]) != 0) & (sum(block_matrix[i]) != 0):
            for k in cycle_in_cfg:
                if (i == k[0]) | (i == k[1]):
                    cycle_block = True
        if cycle_block == False:
            if (block_information[i][0] == "None") & (sum(block_matrix[i]) != 0):
                for k in range(len(block_matrix[i])):
                    for j in range(len(cycle_in_cfg)):
                        if (block_matrix[i][cycle_in_cfg[j][0]] == 1) | (block_matrix[i][cycle_in_cfg[j][1]] == 1) | (block_matrix_t[cycle_in_cfg[j][0]][i] == 1) | (block_matrix_t[cycle_in_cfg[j][1]][i] == 1):
                            break_loop = True
                            break
                    if break_loop == True:
                        break
                if break_loop == False:
                    count_which_del.append(i)
        else:
            cycle_block = False

    while len(count_which_del) >= 1:
        for k in range(len(count_which_del)):
            i = count_which_del[k]
            father_list = []
            son_list = []
            for j in range(len(block_matrix[i])):
                if block_matrix_t[i][j] == 1:
                    father_list.append(j)
                if block_matrix[i][j] == 1:
                    son_list.append(j)
            # delete 2 links,connect 1 links
            for m in range(len(father_list)):
                block_matrix_t[i][father_list[m]] = 0
                block_matrix[father_list[m]][i] = 0
            for n in range(len(son_list)):
                block_matrix_t[son_list[n]][i] = 0
                block_matrix[i][son_list[n]] = 0
            for father in father_list:
                for son in son_list:
                    if father != son:
                        block_matrix_t[son][father] = 1
                        block_matrix[father][son] = 1
        count_which_del = []
        for i in range(len(block_matrix)):
            break_loop = False
            if (sum(block_matrix_t[i]) != 0) & (sum(block_matrix[i]) != 0):
                for k in cycle_in_cfg:
                    if (i == k[0]) | (i == k[1]):
                        cycle_block = True
            if cycle_block == False:
                if (block_information[i][0] == "None") & (sum(block_matrix[i]) != 0):
                    for k in range(len(block_matrix[i])):
                        for j in range(len(cycle_in_cfg)):
                            if (block_matrix[i][cycle_in_cfg[j][0]] == 1) | (block_matrix[i][cycle_in_cfg[j][1]] == 1) | (block_matrix_t[cycle_in_cfg[j][0]][i] == 1) | (block_matrix_t[cycle_in_cfg[j][1]][i] == 1):
                                break_loop = True
                                break
                        if break_loop == True:
                            break
                    if break_loop == False:
                        count_which_del.append(i)
            else:
                cycle_block = False
    new_block = []
    if len(block_matrix) == 1:
        new_block.append(0)
    else:
        for i in range(len(block_matrix)):
            if (sum(block_matrix_t[i]) != 0) | (sum(block_matrix[i]) != 0):
                new_block.append(i)
    return new_block

# build all kinds of roads in every function

All_Road = [[] for i in range(len(Func_name))]
All_Road_Kinds = []
conut_in = 0

print("Building intra cfg for each function")
for nnn in range(len(Func_name)):
    name = Func_name[nnn]
    # print name, "--------------------------------------------------------------"
    if sum(matrix_t[nnn]) == 0:  # nnn is SSL funcion
        All_Road[nnn].append("None")
        continue

    #####################################  build block address
    block_address = []

    f = idaapi.FlowChart(idaapi.get_func(idc.get_name_ea_simple(name)))
    for block in f:
        block_address.append([block.start_ea, block.end_ea - 1])
    ##################################### store SSL function name
    #block_information stores the function and the addresses that called in this address
    block_information = [[] for i in range(len(block_address))]
    for i in range(len(block_address)):
        address = block_address[i][0]
        store_or_not = 0
        while address <= block_address[i][1]:
            # traverse the ref of all address
            for xref in list(CodeRefsFrom(address,1)):
                x_name = get_func_name(xref)
                if x_name == None:
                    for xref_sub in XrefsFrom(xref, 0):
                        x_name = get_func_name(xref_sub.to)
                        if (x_name in Func_name) & (x_name != name):
                            break
                elif x_name == name:
                    for xref_sub in DataRefsFrom(address):
                        if ((idc.print_insn_mnem(address) != "lea") & (idc.print_insn_mnem(address) != "mov")) & (machine == "X86-64"):
                            continue
                        elif (idc.print_insn_mnem(address) != "LDR") & (machine == "arm"):
                            continue
                        x_name = get_func_name(xref_sub)
                        if (x_name in Func_name) & (x_name != name):
                            break
                if (x_name in Func_name) & (x_name != name) & (x_name!="_start"):#test######
                    if machine == "mips":
                        if idc.print_insn_mnem(address) != "jalr":
                            block_information[i].append(x_name)
                    else:
                        block_information[i].append(x_name)
                    store_or_not = 1
                    #if machine.find('X86-64') != -1:
                    # if x_name in necessary_SSL_function:
                    if machine == "mips":
                        if idc.print_insn_mnem(address) != "la":
                            block_information[i].append(str(hex(address)))
                    else:
                        block_information[i].append(str(hex(address)))
            address = address + 1
        if store_or_not == 0:
            func = idaapi.get_func(idc.get_name_ea_simple(name))
            if block_address[i][0] == func.start_ea:
                block_information[i].append("func_start")
            elif (block_address[i][1] == func.end_ea - 1) & (machine == "mips"):
                block_information[i].append("end")
            elif ((block_address[i][1] == func.end_ea) & (machine == "X86-64")):
                block_information[i].append("end")
            else:
                block_information[i].append("None")
        else:
            if len(block_information[i]) == 0:
                block_information[i].append("None")
    ########################## build block matrix
    block_matrix = [[0 for j in range(len(block_address))] for i in range(len(block_address))]
    for block in f:
        for succ_block in block.succs():
            block_matrix[block.id][succ_block.id] = 1
    # Matrix 'T
    block_matrix_t = [[0 for j in range(len(block_address))] for i in range(len(block_address))]
    for i in range(len(block_address)):
        for j in range(len(block_address)):
            block_matrix_t[j][i] = block_matrix[i][j]
    visit = [0 for j in range(len(block_matrix_t))]
    father = [-1 for j in range(len(block_matrix_t))]
    matrix_with_cycle = block_matrix
    matrix_with_cycle_t = block_matrix_t
    cycle_in_cfg = []
    Dfs_visit_block(block_matrix_t, 0, visit, father, block_address, cycle_in_cfg)
    new_block = Matrix_decrease(block_matrix, block_matrix_t, block_information)
    for i in range(len(new_block)):
        for j in range(len(cycle_in_cfg)):
            if cycle_in_cfg[j][0] == new_block[i]:
                cycle_in_cfg[j][0] = i
            if cycle_in_cfg[j][1] == new_block[i]:
                cycle_in_cfg[j][1] = i
    new_block_matrix = [[0 for j in range(len(new_block))] for i in range(len(new_block))]
    new_block_matrix_t = [[0 for j in range(len(new_block))] for i in range(len(new_block))]
    for i in range(len(new_block)):
        for j in range(len(new_block)):
            new_block_matrix[i][j] = block_matrix[new_block[i]][new_block[j]]
            new_block_matrix_t[j][i] = block_matrix[new_block[i]][new_block[j]]
    block_matrix = copy.deepcopy(new_block_matrix)
    block_matrix_t = copy.deepcopy(new_block_matrix_t)
    new_block_information = []
    for i in range(len(new_block)):
        new_block_information.append(block_information[new_block[i]])
    block_information = copy.deepcopy(new_block_information)
    for cycle_edge in cycle_in_cfg:
        if cycle_edge[1] != cycle_edge[0]:
            block_matrix_t[cycle_edge[1]][cycle_edge[0]] = 1
            block_matrix[cycle_edge[0]][cycle_edge[1]] = 1
    ########################################  store one function's all kinds of roads
    road = []
    ssl = 0
    func_road = []
    DFS_road_search(block_matrix, 0, road, ssl, func_road)
    func_road_tmp = []
    for f_road_index in range(len(func_road)):
        while "func_start" in func_road[f_road_index]:
            func_road[f_road_index].remove("func_start")
        while "end" in func_road[f_road_index]:
            func_road[f_road_index].remove("end")
    for f_road_index in range(len(func_road)):
        if func_road[f_road_index] not in func_road_tmp:
            func_road_tmp.append(func_road[f_road_index])
    func_road = func_road_tmp
    # simplify in line
    # delete the same call sequences in a function
    func_road2 = [[] for i in range(len(func_road))]
    for i in range(len(func_road)):
        for j in range(len(func_road[i])):
            func_road2[i].append(func_road[i][j])
    for i in range(len(func_road)):
        for j in range(len(func_road[i])):
            if "0x" not in func_road[i][j]:
                for k in range(j + 1, len(func_road[i])):
                    if func_road[i][k] == func_road[i][j]:
                        for m in range(k+1, len(func_road[i])):
                            if "0x" in func_road[i][m]:
                                index = func_road2[i].index(func_road[i][k])
                                func_road2[i].insert(index+1, func_road[i][m])
                            else:
                                break
    func_road3 = [[] for i in range(len(func_road))]
    for i in range(len(func_road2)):
        for j in range(len(func_road2[i])):
            if func_road2[i][j] not in func_road3[i]:
                func_road3[i].append(func_road2[i][j])
    # simplify between line
    Func_road = []
    for i in range(len(func_road3)):
        if func_road3[i] not in Func_road:
            Func_road.append(func_road3[i])
    for road in range(len(Func_road)):
        if "exit" in Func_road[road]:
            Func_road[road].remove("exit")
        elif ".exit" in Func_road[road]:
            Func_road[road].remove(".exit")
    All_Road[nnn] = Func_road
    # store in file
    if not os.path.exists(result_path + folder + '/CFG/'):
        os.makedirs(result_path + folder + '/CFG/')
    output = open(result_path + folder + '/CFG/' + name + '_block_address.txt', 'a')
    for i in range(len(block_address)):
        for j in range(len(block_address[i])):
            output.write(str(block_address[i][j]))
            output.write(' ')
        output.write('\n')
    output.close()

    output = open(result_path + folder + '/CFG/' + name + '_block_information.txt', 'a')
    for i in range(len(block_information)):
        for j in range(len(block_information[i])):
            output.write(block_information[i][j])
            output.write(' ')
        output.write('\n')
    output.close()

    output = open(result_path + folder + '/CFG/' + name + '_block_matrix.txt', 'a')
    for i in range(len(block_matrix)):
        for j in range(len(block_matrix)):
            output.write(str(block_matrix[i][j]))
            output.write(' ')
        output.write('\n')
    output.close()

    output = open(result_path + folder + '/CFG/' + name + '_CFG_Road.txt', 'a')
    for i in range(len(Func_road)):
        for j in range(len(Func_road[i])):
            output.write(Func_road[i][j])
            output.write(' ')
        output.write('\n')
    output.close()

print('\n************************************build roads in line')
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
        for j in range(len(matrix_t)):
            if (matrix_t[i][j] == 1) & (Func_name[j] in SSL_function):
                out_degree = out_degree + 1
        if (sum(matrix_t[i]) == out_degree) & (out_degree != 0):
            down_to_up_list[i] = 1

DFS_SSL = []
#the DFS_SSL is the ssl function and the function that only call the ssl function
for i in range(len(down_to_up_list)):
    if down_to_up_list[i] == 1:
        DFS_SSL.append(Func_name[i])

def DFS_road_read3():
    Final_roads = []
    matrix_new = copy.deepcopy(matrix)
    matrix_new_t = copy.deepcopy(matrix_t)
    All_Road_new = copy.deepcopy(All_Road)
    while True:
        for i in range(len(matrix_new)):
            if sum(matrix_new_t[i]) == 0:
                for j in range(len(matrix_new_t)):
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
                                delete_address = False
                                for n in All_Road_new[j][m]: # every function in single road
                                    if n == Func_name[i]: 
                                        for k in range(len(All_Road_new[i])): # all road of child
                                            for p in All_Road_new[i][k]:
                                                single_road_list[k].append(p)
                                        delete_address = True
                                    elif (n.find("0x")>=0) & (delete_address == True):
                                        continue
                                    elif (n.find("0x")<0):
                                        for single_road_tmp in single_road_list:
                                            single_road_tmp.append(n)
                                        if delete_address == True:
                                            delete_address = False
                                    elif (n.find("0x")>=0) & (delete_address == False):
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
add = 0
print('\n******************************************Middle result')
if "_start" in Func_name:
    c = Func_name.index("_start")
else:
    c = Func_name.index("main")

# store middle result
output = open(result_path + folder + '/Road_middle.txt', 'a')
for j in range(len(All_Road[c])):
    for k in range(len(All_Road[c][j])):
        output.write(All_Road[c][j][k])
        output.write(' ')
    output.write('\n')
output.close()
print('\n******************************************Final result')
Final_roads = []
Test_target = []
if "_start" in Func_name:
    Test_target.append("_start")
elif "main" in Func_name:
    Test_target.append("main")

Final_roads = DFS_road_read3()

#DFS_road_read2(Test_target, Final_roads, SSL_function, 1)
All_Road[c] = []
Final_roads = Final_roads[Func_name.index(Test_target[0])]
for i in range(len(Final_roads)):
    for j in range(len(Final_roads[i])):
        if "." in Final_roads[i][j]:
            Final_roads[i][j] = Final_roads[i][j].replace(".", "")
final_road_new = []
for road in Final_roads:
    road_new_tmp = []
    for road_ele in road:
        if "0x" not in road_ele:
            road_new_tmp.append(road_ele)
    final_road_new.append(road_new_tmp)
filter_road_list = []
final_road_result = []
for i in range(len(final_road_new)):
    if (final_road_new[i] not in filter_road_list):
        final_road_result.append(Final_roads[i])
        filter_road_list.append(final_road_new[i])
Final_roads = []
for i in final_road_result:
    if "exit" not in i:
        Final_roads.append(i)
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

output = open(result_path + folder + '/Road_final.txt', 'a')
for j in range(len(All_Road[c])):
    for k in range(len(All_Road[c][j])):
        output.write(All_Road[c][j][k])
        output.write(' ')
    output.write('\n')
output.close()
# print('\n****************************************** parement')
parement = {}
parement_value_mark = 0

def parament_analysis(target_fun):
    global parement, parement_value_mark
    call_addr=[]
    father_fun_name = []
    if machine.find('X86-64') >= 0:
        target_fun = "." + target_fun
    for addr in XrefsTo(idc.get_name_ea_simple(target_fun)):  # idautils
        if get_func_name(addr.frm) in SSL_function:
            for addr_new in XrefsTo(idc.get_name_ea_simple(get_func_name(addr.frm))):
                if get_func_name(addr_new.frm) in function_Mark:
                    father_fun_name.append(get_func_name(addr_new.frm))
                    call_addr.append(addr_new.frm)
                else:
                    for x in XrefsTo(addr_new.frm, 0):
                        if type(get_func_name(x.frm)) == str:
                            n = idc.get_name_ea_simple(get_func_name(x.frm))
                            for y in XrefsTo(n, 0):
                                    father_fun_name.append(get_func_name(y.frm))
                                    call_addr.append(y.frm)
        else:
            if get_func_name(addr.frm) in function_Mark:
                father_fun_name.append(get_func_name(addr.frm))
                call_addr.append(addr.frm)
            else:
                for x in XrefsTo(addr.frm, 0):
                    if type(get_func_name(x.frm)) == str:
                        n = idc.get_name_ea_simple(get_func_name(x.frm))
                        for y in XrefsTo(n, 0):
                                father_fun_name.append(get_func_name(y.frm))
                                call_addr.append(y.frm)
    if machine.find('X86-64') != -1:
        for ii in range(len(father_fun_name)):
            addr = call_addr[ii]
            judge = 0
            while judge == 0:
                addr = addr - 1
                if addr < idc.get_name_ea_simple(father_fun_name[ii]):
                    break
                if ('SSL_CTX_set_verify' in target_fun)|('SSL_set_verify' in target_fun):
                    if idc.print_operand(addr, 0) == 'esi':
                        if idc.print_insn_mnem(addr) == "xor":
                            if idc.print_operand(addr, 0) == idc.print_operand(addr, 1):
                                judge = 1
                                parement[str(hex(call_addr[ii]))] = "0"
                                parement_value_mark = 1
                        else:
                            value_parement = idc.print_operand(addr, 1)
                            judge = 1
                            parement[str(hex(call_addr[ii]))] = value_parement
                            parement_value_mark = 1
                else:
                    if idc.print_operand(addr, 0) == 'esi':
                        value_parement = idc.print_operand(addr, 1)
                        if value_parement == "20000h":
                            judge = 1
                            parement[str(hex(call_addr[ii]))] = value_parement
                            parement_value_mark = 1
                        elif value_parement == "2000000h":
                            judge = 1
                            parement[str(hex(call_addr[ii]))] = value_parement
                            parement_value_mark = 1
    elif machine.find('arm')!= -1:
        for ii in range(len(father_fun_name)):
            addr = call_addr[ii]
            mark = 0
            judge = 0
            while judge == 0:
                addr = addr - 4
                if addr < idc.get_name_ea_simple(father_fun_name[ii]):
                    break
                if idc.print_operand(addr, 0) == "R1":
                    value_parement = idc.print_operand(addr, 1)
                    if (value_parement[1:] == '1') | (value_parement[1:] == '0'):
                        parement_value_mark = 1
                        judge = 1
                        parement[str(hex(call_addr[ii]))] = value_parement[1:]
    else:#mips
        for ii in range(len(father_fun_name)):
            addr = call_addr[ii] + 8
            mark = 0
            judge = 0
            while judge == 0:
                addr = addr - 4
                if addr < idc.get_name_ea_simple(father_fun_name[ii]):
                    break
                if idc.print_operand(addr, 0) == "$a1":
                    value_parement = idc.print_operand(addr, 1)
                    if (value_parement == '1') | (value_parement == '0'):
                        parement_value_mark = 1
                        judge = 1
                        parement[str(hex(call_addr[ii]))] = int(value_parement)
                    elif value_parement == '$zero':
                        parement_value_mark = 1
                        judge = 1
                        parement[str(hex(call_addr[ii]))] = '0'
target_fun='None'

if ('SSL_CTX_set_verify' in Func_name) | ('.SSL_CTX_set_verify' in Func_name):
    parament_analysis('SSL_CTX_set_verify')
elif ('SSL_set_verify' in Func_name) | ('.SSL_set_verify' in Func_name):
    parament_analysis('SSL_set_verify')
if ('SSL_CTX_ctrl' in Func_name) | ('.SSL_CTX_ctrl' in Func_name):
    parament_analysis('SSL_CTX_ctrl')
if ('SSL_CTX_set_options' in Func_name) | ('.SSL_CTX_set_options' in Func_name):
    parament_analysis('SSL_CTX_set_options')
if ('SSL_set_options' in Func_name) | ('.SSL_set_options' in Func_name):
    parament_analysis('SSL_set_options')

def parameter_analysis_min_version(addr):
    addr = addr.replace('L', '')
    addr = addr.replace('0x', '')
    addr = int(addr, 16)
    if machine.find('X86-64')!= -1:
        judge = 0
        while judge == 0:
            addr = addr - 1
            if idc.print_operand(addr, 0) == 'edx':
                value_parement = idc.print_operand(addr, 1)
                return value_parement
    else:
        mark = 0
        judge = 0
        while judge == 0:
            addr = addr - 4
            if idc.print_operand(addr, 0) == "R2":
                value_parement = idc.print_operand(addr, 1)
                return value_parement

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
        if 'SSL_CTX_ctrl'in All_Road[c][i]:
            n=All_Road[c][i].index("SSL_CTX_ctrl") + 1
            if All_Road[c][i][n] in parement:
                if parement[All_Road[c][i][n]] == '7Bh':
                    pm_value = parameter_analysis_min_version(All_Road[c][i][n])
                    if pm_value == "0x300" | pm_value == '':#set_min SSL3.0
                        Method[i] = 6
                    else:
                        Method[i] = 6.5 # higher than ssl3.0
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
            if "SSL_CTX_set_options" in function_mark:
                output.write("SSL_CTX_set_options")
                for addr in XrefsTo(idc.get_name_ea_simple("SSL_CTX_set_options"), 0):
                    output.write(str(addr.frm))
            if "SSL_set_options" in function_mark:
                output.write("SSL_set_options")
                for addr in XrefsTo(idc.get_name_ea_simple("SSL_set_options"), 0):
                    output.write(str(addr.frm))
                    # output.write(idc.get_name_ea_simple(addr.frm))
            output.write('\n')
            output.close()

output = open(result_path + folder + '/Report_verify.txt', 'a')
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


output = open(result_path + folder + '/Report_method.txt', 'a')
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


#ida_pro.qexit(0)