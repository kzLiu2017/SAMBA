# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
import numpy as np
from graphviz import Digraph

#import os
#os.environ["PATH"] += os.pathsep + '/usr/local/Cellar/graphviz/2.47.1/bin'

firmare='DIR-868-stunnel'
fun_name = []
with open('/Users/tomrush/Desktop/result/' + firmare + '/fun_name.txt', 'r') as f:
    for line in f:
        fun_name.append(line.strip('\n').split(','))

# 读取矩阵,每行为1的位置处代表的函数是该行函数的父函数
matrix = np.loadtxt('/Users/tomrush/Desktop/result/' + firmare + '/martix.txt')  # 最普通的loadtxt
j_i = 0
for i in range(len(matrix)):
    if sum(matrix[i]) == 0:
        j_i = j_i + 1
print('Totally have ', j_i , "functions don't have father_func\n")
n = len(matrix[0])

# 转置
# 读取行,每行为1的位置处代表的函数是该行函数的子函数
matrix_t = np.zeros((n, n))
for i in range(n):
    for j in range(n):
        matrix_t[j][i] = matrix[i][j]
j_ii = 0
for i in range(len(matrix_t)):
    if sum(matrix_t[i]) == 0:
        j_ii = j_ii + 1
print('Totally have ', j_ii, " functions don't have son_func\n")

# 可视化
draw = []
for i in range(n):
    draw.append(Digraph('G', filename='/Users/tomrush/Desktop/result/' + firmare + '/CallGraph/'+str(i), format='jpg'))

for j in range(n):  # 对m每一行遍历
    if sum(matrix[j]) == 0:  # 该行j函数为顶点(没有父函数)
        g = draw[j]
        son_list = []  # 待扩展子函数list
        already_list = np.zeros(n)  # 已扩展子函数(没扩展为0,已扩展为1)
        if sum(matrix_t[j]) == 0:  # 该行j函数没有子函数
            g.edge(fun_name[j][0], 'None')
            g.view()
            # print("Don't have son_func", j)
        else:  # 该行j函数有子函数
            for i in range(n):
                if matrix_t[j][i] == 1:  # 遍历j函数的子函数i
                    g.edge(fun_name[j][0], fun_name[i][0])  # 画图:连接父函数j和子函数i
                    if (sum(matrix_t[i]) != 0) & (already_list[i] == 0):  # 如果函数i有子函数,添加函数i到列表里
                        son_list.append(i)
                        # print('ADD子函数', i)
            while len(son_list) != 0:
                for i in range(n):
                    if matrix_t[son_list[0]][i] == 1:  # 遍历son_list[0]函数的子函数i
                        g.edge(fun_name[son_list[0]][0], fun_name[i][0])  # 画图:连接父函数son_list[0]和子函数i
                        if sum(matrix_t[i]) != 0:  # 如果函数i有子函数
                            if (i not in son_list) & (already_list[i] == 0):  # 且函数i不在列表里,从未被扩展过,再添加函数i到列表里
                                son_list.append(i)
                                # print('添加子函数', i)
                # print('删除', son_list[0])
                already_list[son_list[0]] = 1
                del son_list[0]
            g.view()
            # print("Have son_func", j)
