import idautils
import idc as idc
from idaapi import *
import time
import os
import sys
import binascii
import ast

idc.Wait()
sys.setrecursionlimit(100000)
lib_file = GetInputFile()
info = idaapi.get_inf_structure()
if info.procName == "ARM":
    machine = "arm"
elif (info.procName == "mipsl") | (info.procName == "mipsb"):
    machine = "mips"
elif info.procName == "metapc":
    machine = "X86-64"
function_name = {}
for func in idautils.Functions():
    function_name[get_func_name(func)] = func
result_path = os.getcwd()
result_path = result_path[:result_path.find("squashfs-root/") + 14]
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
read_leaf_func = open(result_path + lib_file +'_leaf_func_list.txt', 'r')

leaf_func_list_all = read_leaf_func.readlines()
leaf_func_list = []

for line in leaf_func_list_all:
    line = line.replace("\'", "")
    line = line.replace(" ", "")
    line = line[1:-1]
    line = line.split(',')
    for i in line:
        leaf_func_list.append(i)

leaf_func_dict = {}
for func in leaf_func_list:
    leaf_func_dict.update({func : 0})

for key in function_name:
    if key in leaf_func_dict:
        leaf_func_dict[key] = 1

function_mark = {}
for func in idautils.Functions():
    function_mark[get_func_name(func)] = 0

print('**********************************have these functions')

for key in function_mark:
    if key in leaf_func_list:
        function_mark[key] = 1

print('\n******************************************fliter white ')

while True:
    counter = len(function_mark)
    for key in function_mark:
        if function_mark[key] == 1:
            if len(list(CodeRefsTo(idc.get_name_ea_simple(key), 0))) == 0:
                for addr in DataRefsTo(idc.get_name_ea_simple(key)):
                # idautils.CodeRef
                    if get_func_name(addr) in function_mark.keys():
                        if function_mark[get_func_name(addr)] == 0:
                            function_mark[get_func_name(addr)] = 1
                            counter = counter - 1
            else:
                for addr in CodeRefsTo(idc.get_name_ea_simple(key), 0):
                # idautils.CodeRef
                    if get_func_name(addr) in function_mark.keys():
                        if function_mark[get_func_name(addr)] == 0:
                            function_mark[get_func_name(addr)] = 1
                            counter = counter - 1
    if counter == len(function_mark):
        break

function_Mark = []
for item in function_mark:
   if (function_mark[item] == 1) & (type(item)==str):
        function_Mark.append(item)

n = len(function_Mark)
matrix = [[0 for j in range(n)] for i in range(n)]
for i in range(len(function_Mark)):
    for addr in XrefsTo(idc.get_name_ea_simple(function_Mark[i]), 0):  # idautils
        if get_func_name(addr.frm) in function_Mark:
            matrix[i][function_Mark.index(get_func_name(addr.frm))] = 1
        else:
            for x in XrefsTo(addr.frm, 0):
                if (type(get_func_name(x.frm)) == str) & (get_func_name(x.frm) in function_Mark):  # idautils.CodeRef
                    matrix[i][function_Mark.index(get_func_name(x.frm))] = 1
                elif (get_func_name(x.frm) == None):
                    for m in XrefsTo(x.frm):
                        if get_func_name(m.frm) in function_Mark:
                            matrix[i][function_Mark.index(get_func_name(m.frm))] = 1

func_delete_list = []
export_func_list = []

matrix_t = [[0 for j in range(n)] for i in range(n)]
for i in range(0, len(matrix)):
    for j in range(0, len(matrix[i])):
        matrix_t[j][i] = matrix[i][j]

for i in range(0, len(matrix)):
    if sum(matrix[i]) == 0:
        if function_Mark[i] in leaf_func_list:
            func_delete_list.append(i)
        elif function_Mark[i].find("sub_") >= 0:
            func_delete_list.append(i)
        else:
            export_func_list.append(i)

function_Mark_backup = []
for i in function_Mark:
    function_Mark_backup.append(i)

while True:
    index = 0
    for i in func_delete_list:
        del matrix[i - index]
        for j in range(len(matrix)):
            del matrix[j][i - index]
        del function_Mark[i - index]
        index = index + 1
    func_delete_list = []
    for i in range(len(function_Mark)):
        if sum(matrix[i]) == 0:
            export_bool = False
            for j in export_func_list:
                if function_Mark[i] in function_Mark_backup[j]:
                    export_bool = True
                    break
            if export_bool == False:
                func_delete_list.append(i)
    if len(func_delete_list) == 0:
        break
n = len(function_Mark)
matrix_t = [[0 for j in range(n)] for i in range(n)]
for i in range(n):
    for j in range(n):
        matrix_t[j][i] = matrix[i][j]

print('\n***************************************Breaking function Circle')
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

print('\n***************************************del leave')
count_which_del = []
for i in range(n):
    if (sum(matrix_t[i]) == 0) & (function_Mark[i] not in leaf_func_list):
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
    count_which_del = []
    for i in range(len(function_Mark)):
        if (sum(matrix_t[i]) == 0) & (function_Mark[i] not in leaf_func_list):
            count_which_del.append(i)

    if len(count_which_del) == 0:
        mark = 0


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
    count_which_del = []  # ascending order list # store which function needed to be deleted
    cycle_block = False
    for i in range(len(block_matrix)):
        if (sum(block_matrix_t[i]) != 0) & (sum(block_matrix[i]) != 0):
            for k in cycle_in_cfg:
                if (i == k[0]) | (i == k[1]):
                    cycle_block = True
        if cycle_block == False:
            if (block_information[i][0] == "None") & (sum(block_matrix[i]) != 0):
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
                    block_matrix_t[son][father] = 1
                    block_matrix[father][son] = 1

        count_which_del = []
        for i in range(len(block_matrix)):
            block_matrix[i][i] = 0
            block_matrix_t[i][i] = 0
            if (sum(block_matrix_t[i]) != 0) & (sum(block_matrix[i]) != 0):
                if block_information[i][0] == "None":
                    count_which_del.append(i)

# build all kinds of roads in every function

All_Road = [[] for i in range(len(Func_name))]
All_Road_Kinds = []
conut_in = 0
write_all_road = open(result_path + lib_file +'_all_road.txt', 'a+')

for nnn in range(len(Func_name)):
    name = Func_name[nnn]
    # print name, "--------------------------------------------------------------"
    if sum(matrix_t[nnn]) == 0:  # nnn is SSL funcion
        All_Road[nnn].append("None")
        continue
    # the father function of nnn is more than 1
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
            for xref in XrefsFrom(address, 0):
                x_name = get_func_name(xref.to)
                if x_name == None:
                    for xref_sub in XrefsFrom(xref.to, 0):
                        x_name = get_func_name(xref_sub.to)
                if (x_name in Func_name) & (x_name != name) & (x_name!="_start"):
                    if machine == "mips":
                        if (idc.print_insn_mnem(address) != "jalr") & (idc.print_insn_mnem(address) != "jr"):
                            if (idc.print_insn_mnem(address) != "la") | (idc.print_operand(address, 1).find("loc") < 0):
                                block_information[i].append(x_name)
                        elif (idc.print_insn_mnem(address) == "jalr") | (idc.print_insn_mnem(address) == "jr"):
                            if (idc.print_insn_mnem(address) != "la") & (idc.print_operand(address, 1).find("loc") < 0):
                                block_information[i].append(x_name)
                    else:
                        block_information[i].append(x_name)
                    store_or_not = 1
                    #if machine.find('X86-64') != -1:
                    if x_name in necessary_SSL_function:
                        if machine == "mips":
                            if idc.print_insn_mnem(address) != "la":
                                block_information[i].append(str(hex(address)))
                        else:
                            block_information[i].append(str(hex(address)))
            address = address + 1
        if store_or_not == 0:
            func = idaapi.get_func(idc.get_name_ea_simple(name))
            if block_address[i][0] == func.start_ea:
                block_information[i].append("start")
            elif (block_address[i][1] == func.end_ea - 1) & (machine == "mips"):
                block_information[i].append("end")
            elif ((block_address[i][1] == func.end_ea) & (machine == "X86-64")):
                block_information[i].append("end")
            else:
                block_information[i].append("None")
        else:
            if len(block_information[i]) == 0:
                block_information[i].append("None")
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
    cycle_in_cfg = []
    Dfs_visit_block(block_matrix_t, 0, visit, father, block_address, cycle_in_cfg)
    Matrix_decrease(block_matrix, block_matrix_t, block_information)
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
        while "start" in func_road[f_road_index]:
            func_road[f_road_index].remove("start")
        while "end" in func_road[f_road_index]:
            func_road[f_road_index].remove("end")
    for f_road_index in range(len(func_road)):
        if func_road[f_road_index] not in func_road_tmp:
            func_road_tmp.append(func_road[f_road_index])
    func_road = func_road_tmp
    func_road2 = [[] for i in range(len(func_road))]
    for i in range(len(func_road)):
        for j in range(len(func_road[i])):
            func_road2[i].append(func_road[i][j])
    for i in range(len(func_road)):
        for j in range(len(func_road[i])):
            if "0x" not in func_road[i][j]:
                for k in range(j+1, len(func_road[i])):
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
    # store
    All_Road[nnn] = Func_road
for name_index in range(len(function_Mark)):
    write_all_road.write("func_name: " + function_Mark[name_index])
    write_all_road.write("\n")
    write_all_road.write("call_graph: ")
    line = matrix[name_index]
    for i in line:
        write_all_road.write(str(i))
        write_all_road.write(",")
    write_all_road.write("\n")
    if len(All_Road[name_index]) == 0:
        write_all_road.write("")
        write_all_road.write("\n")
    else:
        if str(All_Road[name_index]) == "[\'None\']":
            write_all_road.write("None")
            write_all_road.write("\n")
        elif len(All_Road[name_index]) == 0:
            write_all_road.write("[]")
            write_all_road.write("\n")
        else:
            for x in range(len(All_Road[name_index])):
                if len(All_Road[name_index][x]) == 0:
                    write_all_road.write("[]")
                    write_all_road.write(",")
                else:
                    for n in range(len(All_Road[name_index][x])):
                        if len(All_Road[name_index][x][n]) == 0:
                            write_all_road.write("[]")
                            write_all_road.write(",")
                        else:
                            write_all_road.write(All_Road[name_index][x][n])
                            write_all_road.write(",")
                write_all_road.write("next_list,")
            write_all_road.write("\n")
write_all_road.close()

write_leaf_func = open(result_path + lib_file +'_export_func_list.txt', 'w')
write_func_list = open(result_path + lib_file +'_func_list.txt', 'w')
write_func_name = open(result_path + lib_file +'_func_name.txt', 'w')
export_func_list_name = []
for i in export_func_list:
    export_func_list_name.append(function_Mark_backup[i])
write_leaf_func.write(str(export_func_list_name))

write_func_list.write(str(function_Mark))
write_func_name.write(str(Func_name))
write_leaf_func.close()
#write_call_graph.close()
write_func_list.close()
write_all_road.close()
write_func_name.close()

idc.Exit(0)