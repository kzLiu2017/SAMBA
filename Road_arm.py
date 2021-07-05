#!/usr/bin/env python
import idautils
import idc as idc
from idaapi import *
import time

idc.Wait()
start = time.clock()
start1 = time.time()
folder=str(idc.ARGV[1])
folder=folder[33:]
#folder = 'R6400-usr+sbin+httpd'#'DIR-868-email'  # 'TP_Link-cwmp2'

# Find all functions' name and address
function_name = {}
for func in idautils.Functions():
    function_name[get_func_name(func)] = func

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
necessary_SSL_function = {  #
    'TLSv1_client_method': 0,
    'TLSv1_1_client_method': 0,
    'TLSv1_2_client_method': 0,
    'SSLv2_client_method': 0,
    'SSLv3_client_method': 0,
    'SSLv23_client_method': 0,
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
    'SSL_set_options': 0,
    'SSL_CTX_set_options': 0,
    'SSL_connect': 0,
    'SSL_get_peer_certificate': 0,
    'SSL_get_verify_result': 0,
    'SSL_write': 0,
    'SSL_read': 0,
    'SSL_shutdown': 0,
    'SSL_free': 0,
    'SSL_CTX_free': 0
}

print('**********************************have these functions')
for key in function_name:
    if key in necessary_SSL_function:
        necessary_SSL_function[key] = 1
        print(key)

print('\n***************************do not have these functions')
for key in necessary_SSL_function:
    if necessary_SSL_function.get(key) == 0:
        print(key)

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
    print type(item),item,function_mark[item]
    if (function_mark[item] == 1) & (type(item)==str):
        function_Mark.append(item)

for item in function_Mark:
    print(item)

print('\n*****************************************function address')
with open("/Users/tomrush/Desktop/result/" + folder + "/fun_address.txt", "w") as f:
    for i in range(len(function_Mark)):
        if function_Mark[i] not in SSL_function:
            func = idaapi.get_func(idc.LocByName(function_Mark[i]))
            # print func
            a = str(hex(func.startEA))
            b = str(hex(func.endEA))
            a = a[2:len(a) - 1]
            b = b[2:len(b) - 1]
            # f.write('python3 /Users/tomrush/Desktop/Symbolic\ Execution/s.py -f /Users/tomrush/Desktop/CODE/GU/davinci -s '+a+' -e '+b)
            f.write(a + " " + b)
            f.write('\n')
f.close()

print('\n*****************************************Matrix')
# Matrix
n = len(function_Mark)
matrix = [[0 for j in range(n)] for i in range(n)]
for i in range(len(function_Mark)):
    # print("function_Mark[i]",function_Mark[i])
    for addr in XrefsTo(idc.LocByName(function_Mark[i]), 0):  # idautils.
        # print "addr",addr.frm
        # print ("name",get_func_name(addr.frm))
        if get_func_name(addr.frm) in function_Mark:
            matrix[i][function_Mark.index(get_func_name(addr.frm))] = 1
j_i = 0
for i in range(len(function_Mark)):
    if sum(matrix[i]) == 0:
        j_i = j_i + 1
print(j_i, "functions don't have father_func")

# Matrix 'T
matrix_t = [[0 for j in range(n)] for i in range(n)]
for i in range(n):
    for j in range(n):
        matrix_t[j][i] = matrix[i][j]

print('\n***************************************No circle')


def Dfs_visit(matrix, node, visit, father, function_Mark):
    n = len(matrix)
    visit[node] = 1
    for i in range(n):  # for all nodes
        if matrix[i][node] == 1:  # search son in order
            if visit[i] == 1:  # &(i!=father[node])# son is grey && not point to father
                tmp = node
                circle_begain_index = node
                print('cycle:')
                while tmp != i:
                    print(function_Mark[tmp], '->')
                    tmp = father[tmp]
                print(function_Mark[tmp], '/n')
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
    if (sum(matrix_t[i]) == 0) & (function_Mark[i] not in SSL_function.keys()):
        count_which_del.append(i)
# print(count_which_del)
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
    # zai tong ji
    count_which_del = []
    for i in range(len(function_Mark)):
        if (sum(matrix_t[i]) == 0) & (function_Mark[i] not in SSL_function.keys()):
            count_which_del.append(i)
    # tong ji jie guo,
    if len(count_which_del) == 0:
        mark = 0

print('\n**************************************save file')
with open("/Users/tomrush/Desktop/result/" + folder + "/fun_name.txt", "w") as f:
    for i in range(len(function_Mark)):
        f.write(function_Mark[i])
        f.write('\n')
f.close()

with open("/Users/tomrush/Desktop/result/" + folder + "/martix.txt", "w") as f:
    for i in range(len(matrix)):
        for j in range(len(matrix)):
            f.write(str(matrix[i][j]))
            f.write(' ')
        f.write('\n')
f.close()

print('\n***************************************build ALL_roads')
Func_name = function_Mark


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
def DFS_road_search(Block_matrix, Node, Road, SSL, All_Road):
    SSL_func = SSL
    if sum(Block_matrix[Node]) == 0:  # have no sons
        if block_information[Node][0] != "None":
            Road = Road + block_information[Node]
            SSL_func = 1
        if SSL_func == 1:
            All_Road.append(Road)
    else:  # have sons
        if block_information[Node][0] != "None":
            Road = Road + block_information[Node]
            SSL_func = 1
            
        son_set = []
        for i in range(len(Block_matrix)):
            if Block_matrix[Node][i] == 1:
                son_set.append(i)
                
        while len(son_set) > 0:
            Road1=[]
            for iteem in Road:
                Road1.append(iteem)
            DFS_road_search(Block_matrix, son_set[0], Road1, SSL_func, All_Road)
            del son_set[0]


# matrix decrease
'''
def Matrix_decrease(block_matrix, block_matrix_t, block_information):
    count_which_del = []  # ascending order list # store which function needed to be deleted
    for i in range(len(block_matrix)):
        if (sum(block_matrix_t[i]) == 1) & (sum(block_matrix[i]) >= 1):
            if block_information[i][0] == "None":
                count_which_del.append(i)
    print ("count_which_del^^^^^^^^^^^^^^^^^^^^^^^^^^", count_which_del)
    while len(count_which_del) >= 1:
        for k in range(len(count_which_del)):
            i = count_which_del[k]
            a = sum(block_matrix_t[i])
            son = block_matrix[i].index(1)
            for j in range(a):
                father = block_matrix_t[i].index(1)
                # delete 2 links,connect 1 links
                block_matrix_t[i][father] = 0
                block_matrix_t[son][father] = 1
                block_matrix_t[son][i] = 0
                block_matrix[father][i] = 0
                block_matrix[father][son] = 1
                block_matrix[i][son] = 0
        count_which_del = []
        for i in range(len(block_matrix)):
            if (sum(block_matrix_t[i]) == 1) & (sum(block_matrix[i]) >= 1):
                if block_information[i][0] == "None":
                    count_which_del.append(i)
        print ("count_which_del", count_which_del)
'''


def Matrix_decrease(block_matrix, block_matrix_t, block_information):
    count_which_del = []  # ascending order list # store which function needed to be deleted
    for i in range(len(block_matrix)):
        if (sum(block_matrix_t[i]) == 1) & (sum(block_matrix[i]) == 1):
            if block_information[i][0] == "None":
                count_which_del.append(i)
    while len(count_which_del) >= 1:
        for k in range(len(count_which_del)):
            i = count_which_del[k]
            father = block_matrix_t[i].index(1)
            son = block_matrix[i].index(1)
            # delete 2 links,connect 1 links
            block_matrix_t[i][father] = 0
            block_matrix_t[son][father] = 1
            block_matrix_t[son][i] = 0
            block_matrix[father][i] = 0
            block_matrix[father][son] = 1
            block_matrix[i][son] = 0
        count_which_del = []
        for i in range(len(block_matrix)):
            if (sum(block_matrix_t[i]) == 1) & (sum(block_matrix[i]) == 1):
                if block_information[i][0] == "None":
                    count_which_del.append(i)


# build all kinds of roads in every function
All_Road = [[] for i in range(len(Func_name))]
All_Road_Kinds = []
for nnn in range(len(Func_name)):
    name = Func_name[nnn]
    print name, "--------------------------------------------------------------"
    if sum(matrix_t[nnn]) == 0:  # SSL
        All_Road[nnn].append("None")
        continue
    elif sum(matrix_t[nnn]) == 1:  # outdegree==1
        c = []
        c.append(Func_name[matrix_t[nnn].index(1)])
        All_Road[nnn].append(c)
        continue

    #####################################  build block address
    block_address = []

    f = idaapi.FlowChart(idaapi.get_func(idc.LocByName(name)))
    for block in f:
        block_address.append([block.start_ea, block.end_ea - 4])
    # print block_address
    ##################################### store SSL function name
    block_information = [[] for i in range(len(block_address))]
    for i in range(len(block_address)):
        address = block_address[i][0]
        store_or_not = 0
        while address <= block_address[i][1]:
            if idc.GetOpnd(address, 0) in Func_name:
                block_information[i].append(idc.GetOpnd(address, 0))
                store_or_not = 1
                if idc.GetOpnd(address, 0)=="SSL_CTX_set_verify":
                    block_information[i].append(str(hex(address)))

            second_option = idc.GetOpnd(address, 1)  # LDR R3,=sub_204E0;
            second_option = second_option[1:]
            if second_option in Func_name:
                block_information[i].append(second_option)
                store_or_not = 1
            address = address + 4
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
    Dfs_visit_block(block_matrix_t, 0, visit, father, block_address)
    Matrix_decrease(block_matrix, block_matrix_t, block_information)
    ########################################  store one function's all kinds of roads
    road = []
    ssl = 0
    func_road = []
    DFS_road_search(block_matrix, 0, road, ssl, func_road)

    # simplify in line
    func_road2 = [[] for i in range(len(func_road))]
    for i in range(len(func_road)):
        for j in range(len(func_road[i])):
            if func_road[i][j] not in func_road2[i]:
                func_road2[i].append(func_road[i][j])
    # simplify between line
    Func_road = []
    for i in range(len(func_road2)):
        if func_road2[i] not in Func_road:
            Func_road.append(func_road2[i])

    # store
    All_Road[nnn] = Func_road
    # store in file
    output = open('/Users/tomrush/Desktop/result/' + folder + '/CFG/' + name + '_block_address''.txt', 'w+')
    for i in range(len(block_address)):
        for j in range(len(block_address[i])):
            output.write(str(block_address[i][j]))
            output.write(' ')
        output.write('\n')
    output.close()

    output = open('/Users/tomrush/Desktop/result/' + folder + '/CFG/' + name + '_block_information''.txt', 'w+')
    for i in range(len(block_information)):
        for j in range(len(block_information[i])):
            output.write(block_information[i][j])
            output.write(' ')
        output.write('\n')
    output.close()

    output = open('/Users/tomrush/Desktop/result/' + folder + '/CFG/' + name + '_block_matrix''.txt', 'w+')
    for i in range(len(block_matrix)):
        for j in range(len(block_matrix)):
            output.write(str(block_matrix[i][j]))
            output.write(' ')
        output.write('\n')
    output.close()

    output = open('/Users/tomrush/Desktop/result/' + folder + '/CFG/' + name + '_CFG_Road''.txt', 'w+')
    for i in range(len(Func_road)):
        for j in range(len(Func_road[i])):
            output.write(Func_road[i][j])
            output.write(' ')
        output.write('\n')
    output.close()

print('\n************************************build roads in line')
down_to_up_list = [0 for j in range(len(Func_name))]
for i in range(len(Func_name)):
    if Func_name[i] in SSL_function:
        down_to_up_list[i] = 1
        print Func_name[i]

for i in range(len(Func_name)):
    if Func_name[i] not in SSL_function:
        out_degree = 0
        for j in range(len(matrix_t)):
            if (matrix_t[i][j] == 1) & (Func_name[j] in SSL_function):
                out_degree = out_degree + 1
        if (sum(matrix_t[i]) == out_degree) & (out_degree != 0):
            down_to_up_list[i] = 1
            print Func_name[i]

DFS_SSL = []
for i in range(len(down_to_up_list)):
    if down_to_up_list[i] == 1:
        DFS_SSL.append(Func_name[i])


def DFS_road_read(matrix, matrix_t, Test_target, Final_roads, SSL_judge, inline):
    global add
    # find first not SSL func
    entrance = -1
    for a in range(len(Test_target)):
        if ('$' not in Test_target[a]) &('0x' not in Test_target[a])& (Test_target[a] not in SSL_judge):
            entrance = a
            break
    if entrance == -1:  # ALL SSL
        if inline == 1:
            # simplify in line
            Test_target1 = []
            for k in range(len(Test_target)):
                if Test_target[k] not in Test_target1:
                    Test_target1.append(Test_target[k])

            # simplify between line
            if Test_target1 not in Final_roads:
                Final_roads.append(Test_target1)
                add = add + 1
                print add
        elif inline == 2:
            # simplify between line
            if Test_target not in Final_roads:
                Final_roads.append(Test_target)
                add = add + 1
                print add
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
            if down_to_up_list[func_index] != 0:
                Test_target_new[entrance] = '$' + Test_target_new[entrance] + '_[midroad_' + str(road_count + 1) + ']'
                # update target_new
                for j in range(len(All_Road[func_index][road_count])):
                    h = len(All_Road[func_index][road_count]) - j - 1
                    Test_target_new.insert(entrance + 1, All_Road[func_index][road_count][h])
            else:
                del Test_target_new[entrance]
                # update target_new
                for j in range(len(All_Road[func_index][road_count])):
                    h = len(All_Road[func_index][road_count]) - j - 1
                    Test_target_new.insert(entrance, All_Road[func_index][road_count][h])
        
            # go on DFS
            DFS_road_read(matrix, matrix_t, Test_target_new, Final_roads, SSL_judge, inline)
            road_count = road_count - 1
def DFS_road_read2(matrix, matrix_t, Test_target, Final_roads, SSL_judge, inline):
    global add
    # find first not SSL func
    entrance = -1
    for a in range(len(Test_target)):
        if ('$' not in Test_target[a]) &('0x' not in Test_target[a])& (Test_target[a] not in SSL_judge):
            entrance = a
            break
    if entrance == -1:  # ALL SSL
        if inline == 1:
            # simplify in line
            Test_target1 = []
            for k in range(len(Test_target)):
                if Test_target[k] not in Test_target1:
                    Test_target1.append(Test_target[k])

            # simplify between line
            if Test_target1 not in Final_roads:
                Final_roads.append(Test_target1)
                add = add + 1
                print add
        elif inline == 2:
            # simplify between line
            if Test_target not in Final_roads:
                Final_roads.append(Test_target)
                add = add + 1
                print add
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

            Test_target_new[entrance] = '$' + Test_target_new[entrance] + '_[Midroad_' + str(road_count + 1) + ']'
            # update target_new
            for j in range(len(All_Road[func_index][road_count])):
                h = len(All_Road[func_index][road_count]) - j - 1
                Test_target_new.insert(entrance + 1, All_Road[func_index][road_count][h])
            # go on DFS
            DFS_road_read2(matrix, matrix_t, Test_target_new, Final_roads, SSL_judge, inline)
            road_count = road_count - 1

change_mark = 0
add = 0
while change_mark == 0:
    mark1 = sum(down_to_up_list)
    for i in range(len(Func_name)):  # for all func
        if down_to_up_list[i] == 0:  # for not ready
            # judge this fun's all son-fun were ready
            all_road_sum = 0
            for j in range(len(All_Road[i])):
                one_road_sum = 0 
                address_count=0
                for k in range(len(All_Road[i][j])):
                    if '0x' in All_Road[i][j][k]:
                        address_count=address_count+1
                    else:
                        one_road_sum = one_road_sum + down_to_up_list[Func_name.index(All_Road[i][j][k])]
                if one_road_sum == len(All_Road[i][j])-address_count:  # one road all ssl
                    all_road_sum = all_road_sum + 1
            # this fun's all son-fun were ready
            if all_road_sum == len(All_Road[i]):
                # compute this func's all roads
                Final_roads = []
                Test_target = []
                Test_target.append(Func_name[i])
                print "----------------", i, Func_name[i], sum(down_to_up_list), "--------------------"
                DFS_road_read(matrix, matrix_t, Test_target, Final_roads, DFS_SSL, 3)  # 1
                add = 0
                # store all roads in All_roads
                All_Road[i] = []
                for k in range(len(Final_roads)):
                    All_Road[i].append(Final_roads[k])
                # store in file
                output = open('/Users/tomrush/Desktop/result/' + folder + '/ROAD_func_middle/' + Func_name[i] + '.txt',
                              'w+')
                for j in range(len(All_Road[i])):
                    for k in range(len(All_Road[i][j])):
                        output.write(All_Road[i][j][k])
                        output.write(' ')
                    output.write('\n')
                output.close()
                # update
                down_to_up_list[i] = 1
    # no more change in 2 round of while
    mark2 = sum(down_to_up_list)
    if mark2 == mark1:
        change_mark = 1

print('\n******************************************Middle result')
if "_start" in Func_name:
    c = Func_name.index("_start")
else:
    c = Func_name.index("start")

for i in range(len(All_Road[c])):
    print i, All_Road[c][i]
# store middle result
output = open('/Users/tomrush/Desktop/result/' + folder + '/Road_middle.txt', 'w+')
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
else:
    Test_target.append("start")
DFS_road_read2(matrix, matrix_t, Test_target, Final_roads, SSL_function, 3)

All_Road[c] = []
for k in range(len(Final_roads)):
    if "SSL_connect" in Final_roads[k]:  # filter not connect
        if ("SSL_read" in Final_roads[k]) | ("SSL_write" in Final_roads[k]):
            All_Road[c].append(Final_roads[k])

for i in range(len(All_Road[c])):
    print i, All_Road[c][i]

# store final result
output = open('/Users/tomrush/Desktop/result/' + folder + '/Road_final.txt', 'w+')
for j in range(len(All_Road[c])):
    for k in range(len(All_Road[c][j])):
        output.write(All_Road[c][j][k])
        output.write(' ')
    output.write('\n')
output.close()

print('\n****************************************** parement')
father_fun_name = []
for xref in XrefsTo(idc.LocByName('SSL_CTX_set_verify'), 0):
    if type(get_func_name(xref.frm)) == str:
        father_fun_name.append(get_func_name(xref.frm))
print(father_fun_name)

parement = {}
parement_value_mark=0
for ii in range(len(father_fun_name)):
    func = idaapi.get_func(idc.LocByName(father_fun_name[ii]))
    for i in range((func.endEA - func.startEA) / 4):
        address = func.startEA + i * 4
        # print(address)
        if (idc.GetMnem(address) == "BL") & (idc.GetOpnd(address, 0) == "SSL_CTX_set_verify"):
            parement_addr = address - 8
            value_parement = idc.GetOpnd(parement_addr, 1)
            if value_parement[0]=='#':
                parement[str(hex(address))] = value_parement[1:]
                parement_value_mark=1
print(parement)

print('\n****************************************** report')
# match 1000+roads (Final_roads)
Method = [0 for j in range(len(All_Road[c]))]
Verify = [0 for j in range(len(All_Road[c]))]
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

    if 'SSL_CTX_set_verify' not in All_Road[c][i]:
        if ('SSL_get_peer_certificate' in All_Road[c][i]) & ('SSL_get_verify_result' in All_Road[c][i]):
            Verify[i] = 1
        elif ('SSL_get_peer_certificate' not in All_Road[c][i]) & ('SSL_get_verify_result' in All_Road[c][i]):
            Verify[i] = 2
        elif ('SSL_get_peer_certificate' in All_Road[c][i]) & ('SSL_get_verify_result' not in All_Road[c][i]):
            Verify[i] = 3
        elif ('SSL_get_peer_certificate' not in All_Road[c][i]) & ('SSL_get_verify_result' not in All_Road[c][i]):
            Verify[i] = 4
    else:#'SSL_set_verify' in All_Road[c][i]
        if parement_value_mark==1:
            n=All_Road[c][i].index("SSL_CTX_set_verify")+1
            #print parement[All_Road[c][i][n]]
            if parement[All_Road[c][i][n]]=='0':
                if ('SSL_get_peer_certificate' in All_Road[c][i]) & ('SSL_get_verify_result' in All_Road[c][i]):
                    Verify[i] = 5
                elif ('SSL_get_peer_certificate' not in All_Road[c][i]) & ('SSL_get_verify_result' in All_Road[c][i]):
                    Verify[i] = 6
                elif ('SSL_get_peer_certificate' in All_Road[c][i]) & ('SSL_get_verify_result' not in All_Road[c][i]):
                    Verify[i] = 7
                elif ('SSL_get_peer_certificate' not in All_Road[c][i]) & ('SSL_get_verify_result' not in All_Road[c][i]):
                    Verify[i] = 8
            else:
                Verify[i] = 9#correct
        else:
            output = open('/Users/tomrush/Desktop/result/RD_need.txt', 'a') 
            output.write(folder)
            output.write('\n')
            output.close()
            
output = open('/Users/tomrush/Desktop/result/' + folder + '/Report_verify.txt', 'w+')
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

output.close()   


output = open('/Users/tomrush/Desktop/result/' + folder + '/Report_method.txt', 'w+')
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
output.close()      
        
            
            

end = time.clock()
print('Running time: %s Seconds' % (end - start))
end1 = time.time()
print('Running time: %s Seconds' % (end1 - start1))

with open("/Users/tomrush/Desktop/result/" + folder + "/time.txt", "w") as f:
    f.write(str(end - start))
    f.write('\n')
    f.write(str(end1 - start1))
f.close()

idc.Exit(0)
