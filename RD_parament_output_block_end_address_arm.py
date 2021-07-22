#!/usr/bin/env python
import idautils
import idc as idc
from idaapi import *
import time
import os

# idc.Wait()
start = time.clock()
start1 = time.time()

firmware ='R7900-sbin+curl'  # 'DIR-868-genuuid'#'R8500-sbin+curl'  # 'TP_Link-cwmp2'
target_parament_func = 'SSL_CTX_set_verify'
target_parament_func_father = []
for addr in XrefsTo(idc.LocByName(target_parament_func), 0):
    if type(get_func_name(addr.frm)) ==str:
        target_parament_func_father.append(get_func_name(addr.frm))
        print 'father of ', target_parament_func, '------', get_func_name(addr.frm)
path_filename = "C:/Users/lenovo/Desktop/cfg/" + firmware
if not os.path.exists(path_filename):
    os.mkdir(path_filename)
target_parament_func_calladdress = [[] for i in range(len(target_parament_func_father))]
path = "C:/Users/lenovo/Desktop/cfg/" + firmware + '/RD'
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
def DFS_road_search(Block_matrix, Node, Road, All_Road, matrix_mark):#NODE=0
    #print(Node)
    #print(sum(Block_matrix[Node]))
    if (sum(Block_matrix[Node]) == 0) & (matrix_mark[Node]==1):  # have no sons, leaf node
        Road.append(str(hex(block_address[Node][1])))
        #print('$$$')
        All_Road.append(Road)
    else:  # have sons
        Road.append(str(hex(block_address[Node][1])))
        #print(Road)
        son_set = []
        for i in range(len(Block_matrix)):
            if Block_matrix[Node][i] == 1:
                son_set.append(i)
        
        while len(son_set) > 0:
            Road1=[]
            for iteem in Road:
                Road1.append(iteem)
            #print 'in    ',Road1#,hex(block_address[son_set[0]][1])
            DFS_road_search(Block_matrix, son_set[0], Road1, All_Road, matrix_mark)
            #print 'out   ',Road
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
    block_information = 0
    verify_addr=0
    judge=1
    i = 0
    while judge:
        address = block_address[i][0]
        while address <= block_address[i][1]:
            if idc.GetOpnd(address, 0) =='SSL_CTX_set_verify':
                block_information=i
                verify_addr=address
                judge=0
                break
            address=address+4
        i = i+1
    print(block_information)
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
    matrix_mark=[0 for j in range(len(block_address))]
    matrix_mark[block_information]=1
    mark_list=[]
    mark_list.append(block_information)
    while len(mark_list)!=0:
        for i in range(len(matrix_mark)):
            if(block_matrix_t[mark_list[0]][i])==1:
                print('far',i)
                matrix_mark[i]=1
                if i not in mark_list:
                    mark_list.append(i)
        del mark_list[0]
    print(matrix_mark)
    for i in range(len(matrix_mark)):
        if matrix_mark[i]!=1:
            for j in range(len(matrix_mark)):
                block_matrix[i][j]=0
        else:
            for j in range(len(matrix_mark)):
                if matrix_mark[j]!=1:
                    block_matrix[i][j]=0

    ssl = 0
    road = []
    func_road = []
    DFS_road_search(block_matrix, 0, road, func_road, matrix_mark)
    #for i in range(len(func_road)):
        #print(func_road[i])
    
    # store in file
    path1 = "C:/Users/lenovo/Desktop/cfg/" + firmware + '/RD/' + target_parament_func
    if not os.path.exists(path1):
        os.mkdir(path1)

    output = open("C:/Users/lenovo/Desktop/cfg/" + firmware + '/RD/' + target_parament_func + '/' + name + '_CFG_Road''.txt','w+')

    # target_parament_func_father[nnn] start&end address
    func = idaapi.get_func(idc.LocByName(name))
    # target_parament_func be called address
    for i in range(len(func_road)):
        output.write(str(hex(func.startEA)) + ',' + str(hex(func.endEA - 4)))
        output.write(',')
        output.write(str(hex(verify_addr)))
        for j in range(len(func_road[i])):
            output.write(',')
            output.write(func_road[i][j])
        output.write('\n')
    output.close()

end = time.clock()
print('Running time: %s Seconds' % (end - start))
end1 = time.time()
print('Running time: %s Seconds' % (end1 - start1))
with open("C:/Users/lenovo/Desktop/cfg/" + firmware + '/RD/' + target_parament_func + "/time.txt", "w") as f:
    f.write(str(end - start))
    f.write('\n')
    f.write(str(end1 - start1))
f.close()

# idc.Exit(0)
