#!/usr/bin/env python
import idautils
import idc as idc
from idaapi import *
import time
import os

# idc.Wait()
start = time.clock()
start1 = time.time()

firmware = 'DIR-868-stunnel'  # 'TP_Link-cwmp2'
target_parament_func = 'SSL_CTX_set_verify'
target_parament_func_father = []
for addr in XrefsTo(idc.LocByName(target_parament_func), 0):
    if type(get_func_name(addr.frm)) ==str:
        target_parament_func_father.append(get_func_name(addr.frm))
        print 'father of ', target_parament_func, '------', get_func_name(addr.frm)
path_filename = '/Users/kkzzz/Desktop/ida_analysis_result/' + firmware
if not os.path.exists(path_filename):
    os.mkdir(path_filename)
target_parament_func_calladdress = [[] for i in range(len(target_parament_func_father))]
path = '/Users/kkzzz/Desktop/ida_analysis_result/' + firmware + '/RD'
if not os.path.exists(path):
    os.mkdir(path)

SSL_function = {

    'TLSv1_client_method': 0,
    'TLSv1_1_client_method': 0,
    'TLSv1_2_client_method': 0,
    'SSLv2_client_method': 0,
    'SSLv3_client_method': 0,
    'SSLv23_client_method': 0,
    'SSLv23_server_method': 0,
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
    'SSL_CTX_load_verify_locations': 0,
    'SSL_set_fd': 0,
    'SSL_set_shutdown': 0,
    'SSL_set_options': 0,
    'SSL_CTX_set_options': 0,
    'SSL_connect': 0,
    'SSL_get_peer_certificate': 0,
    'SSL_get_verify_result': 0,
    'SSL_get_version': 0,
    'SSL_write': 0,
    'SSL_read': 0,
    'SSL_shutdown': 0,
    'SSL_free': 0,
    'SSL_CTX_free': 0,
    'SSL_CTX_ctrl': 0,
    'SSL_accept': 0,
    'SSL_get_error': 0,
    'SSL_library_init': 0,
    'SSL_load_error_strings': 0,
}

print('\n******************************************filter_initial')
# for all functions (is or include) functions in SSL_function,mark it.--->mark_size=1
function_mark = {}
for func in idautils.Functions():
    function_mark[get_func_name(func)] = 0

for key in function_mark:
    if key in SSL_function:
        function_mark[key] = 1
        print(key)
print('\n******************************************filter white ')
# filter the function (whose mark_size=0),keep the function (whose mark_size=0).then
k = 1
while k:
    counter = len(function_mark)
    for key in function_mark:
        if function_mark[key] == 1:
            for addr in XrefsTo(idc.LocByName(key), 0):  # idautils.CodeRef
                if get_func_name(addr.frm) in function_mark.keys():
                    if function_mark[get_func_name(addr.frm)] == 0:
                        function_mark[get_func_name(addr.frm)] = 1
                        counter = counter - 1
    if counter == len(function_mark):
        k = 0
function_Mark = []
for item in function_mark:
    # print type(item),item,function_mark[item]
    if function_mark[item] == 1:
        function_Mark.append(item)


# have circle or not
def Dfs_visit_block(block_matrix_t, node, visit, father, block_address):
    n = len(block_matrix_t)
    visit[node] = 1
    for i in range(n):  # for all nodes
        if block_matrix_t[i][node] == 1:  # search son in order
            if visit[i] == 1:  # &(i!=father[node])# son is grey && not point to father
                tmp = node
                circle_begain_index = node
                # print('cycle:')
                while tmp != i:
                    # print(hex(block_address[tmp][0]), hex(block_address[tmp][1]), '->')
                    tmp = father[tmp]
                # print(hex(block_address[tmp][0]), hex(block_address[tmp][1]), '/n')
                circle_end_index = tmp
                block_matrix_t[circle_end_index][circle_begain_index] = 0
                block_matrix[circle_begain_index][circle_end_index] = 0
            elif visit[i] == 0:  # son is white
                father[i] = node  # father[]: grey node
                Dfs_visit_block(block_matrix_t, i, visit, father, block_address)
    visit[node] = 2


# dfs output all roads
def DFS_road_search(Block_matrix, Node, Road, SSL, All_Road):#SSL=0,NODE=0
    SSL_func = SSL
    a = str()
    if sum(Block_matrix[Node]) == 0:  # have no sons, leaf node
        if block_information[Node][0] != "None":#this block call SSL
            Road.append(str(hex(block_address[Node][1])))
            SSL_func = 1
        else:#this block dont call SSL
            Road.append(str(hex(block_address[Node][1])))
        
        if SSL_func == 1:
            All_Road.append(Road)
            print '000000',Road
    else:  # have sons
        if block_information[Node][0] != "None":#this block call SSL
            Road.append(str(hex(block_address[Node][1])))
            SSL_func = 1
        else:#this block dont call SSL
            Road.append(str(hex(block_address[Node][1])))
        
        son_set = []
        for i in range(len(Block_matrix)):
            if Block_matrix[Node][i] == 1:
                son_set.append(i)
        
        while len(son_set) > 0:
            Road1=[]
            for iteem in Road:
                Road1.append(iteem)
            print 'in    ',Road1#,hex(block_address[son_set[0]][1])
            DFS_road_search(Block_matrix, son_set[0], Road1, SSL_func, All_Road)
            print 'out   ',Road
            del son_set[0]
        


print('\n******************************************target_parament_func analyze')
# build all kinds of roads in target_parament_func_father[]
target_parament_block=[[] for i in range(len(target_parament_func_father))]
for nnn in range(len(target_parament_func_father)):# for all func which call tafet_func
    name = target_parament_func_father[nnn]
    print "analyse", name, "------------------------------"
    #####################################  build block address
    block_address = []
    f = idaapi.FlowChart(idaapi.get_func(idc.LocByName(name)))
    for block in f:
        block_address.append([block.start_ea, block.end_ea - 4])
    # print block_address
    ##################################### store which block call white_func
    block_information = [[] for i in range(len(block_address))]
    
    for i in range(len(block_address)):
        address = block_address[i][0]
        store_or_not = 0
        while address <= block_address[i][1]:
            if idc.GetOpnd(address, 0) in function_Mark:
                block_information[i].append(idc.GetOpnd(address, 0))
                store_or_not = 1
                if idc.GetOpnd(address, 0) == target_parament_func:
                    target_parament_func_calladdress[nnn].append(address)
                    target_parament_block[nnn].append(str(hex(block_address[i][1])))#target_func be called block end address
            second_option = idc.GetOpnd(address, 1)  # LDR R3,=white_func;
            second_option = second_option[1:]
            if second_option in function_Mark:
                block_information[i].append(second_option)
                store_or_not = 1
                if second_option == target_parament_func:
                    target_parament_func_calladdress[nnn].append(address)#target fun be called address
                    target_parament_block[nnn].append(str(hex(block_address[i][1])))#target_func be called block end address
            address = address + 1
        if store_or_not == 0:
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
    Dfs_visit_block(block_matrix_t, 0, visit, father, block_address)  # del circle
    ########################################  store all roads which call white_func
    ssl = 0
    road = []
    func_road = []
    DFS_road_search(block_matrix, 0, road, ssl, func_road)


    # select which road contain target_parament_func
    Func_road = [[] for i in range(len(target_parament_block[nnn]))]
    for i in range(len(target_parament_block[nnn])):
        for j in range(len(func_road)):
            if target_parament_block[nnn][i] in func_road[j]:
                a=func_road[j][0:func_road[j].index(target_parament_block[nnn][i])]
                if a not in Func_road[i]:
                    Func_road[i].append(a)  # func_road[i][0:j+1]
    
    
    # store in file
    path1 = '/Users/kkzzz/Desktop/ida_analysis_result/' + firmware + '/RD/' + target_parament_func
    if not os.path.exists(path1):
        os.mkdir(path1)

    output = open(
        '/Users/kkzzz/Desktop/ida_analysis_result/' + firmware + '/RD/' + target_parament_func + '/' + name + '_block_address''.txt',
        'w+')
    for i in range(len(block_address)):
        for j in range(len(block_address[i])):
            output.write(str(block_address[i][j]))
            output.write(' ')
        output.write('\n')
    output.close()

    output = open(
        '/Users/kkzzz/Desktop/ida_analysis_result/' + firmware + '/RD/' + target_parament_func + '/' + name + '_block_information''.txt',
        'w+')
    for i in range(len(block_information)):
        for j in range(len(block_information[i])):
            output.write(block_information[i][j])
            output.write(' ')
        output.write('\n')
    output.close()

    output = open(
        '/Users/kkzzz/Desktop/ida_analysis_result/' + firmware + '/RD/' + target_parament_func + '/' + name + '_block_matrix''.txt',
        'w+')
    for i in range(len(block_matrix)):
        for j in range(len(block_matrix)):
            output.write(str(block_matrix[i][j]))
            output.write(' ')
        output.write('\n')
    output.close()

    output = open('/Users/kkzzz/Desktop/ida_analysis_result/' + firmware + '/RD/' + target_parament_func + '/' + name + '_CFG_Road''.txt','w+')

    # target_parament_func_father[nnn] start&end address
    func = idaapi.get_func(idc.LocByName(name))
    # target_parament_func be called address
    for i in range(len(target_parament_func_calladdress[nnn])):
        print len(target_parament_func_calladdress[nnn])
        for j in range(len(Func_road[i])):
            output.write(str(hex(func.startEA))+','+str(hex(func.endEA-4)))
            output.write(',')
            output.write(str(hex(target_parament_func_calladdress[nnn][i])))
            for k in range(len(Func_road[i][j])):
                output.write(',')
                output.write(Func_road[i][j][k])
            output.write('\n')
    output.close()

end = time.clock()
print('Running time: %s Seconds' % (end - start))
end1 = time.time()
print('Running time: %s Seconds' % (end1 - start1))
with open("/Users/kkzzz/Desktop/ida_analysis_result/" + firmware + '/RD/' + target_parament_func + "/time.txt", "w") as f:
    f.write(str(end - start))
    f.write('\n')
    f.write(str(end1 - start1))
f.close()

# idc.Exit(0)
