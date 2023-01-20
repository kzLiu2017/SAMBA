#!/usr/bin/env python
import idautils
import idc as idc
from idaapi import *
import time
import os
import sys
from queue import Queue
import binascii
import ida_nalt

sys.setrecursionlimit(100000)
start = time.process_time()
start1 = time.time()
file_path = 'E:/binary/gnutls/'
folder = get_root_filename()
machine = ""
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

if not os.path.exists('E:/result/gnutls/' + folder):
    os.makedirs('E:/result/gnutls/' + folder)

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
    'SSL_get_peer_certificate': 0,
    'SSL_get_verify_result': 0,
    'SSL_write': 0,
    'SSL_read': 0,
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
    '.SSL_get_peer_certificate': 0,
    '.SSL_get_verify_result': 0,
    '.SSL_write': 0,
    '.SSL_read': 0,

    '_TLSv1_client_method': 0,
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
    '_SSL_get_peer_certificate': 0,
    '_SSL_get_verify_result': 0,
    '_SSL_write': 0,
    '_SSL_read': 0,
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
    'SSL_CTX_load_verify_locations': 0,
    'SSL_set_fd': 0,
    'SSL_set_options': 0,
    'SSL_CTX_set_options': 0,
    'SSL_CTX_set_min_proto_version': 0,
    'SSL_CTX_ctrl': 0,
    'SSL_connect': 0,
    'SSL_get_peer_certificate': 0,
    'SSL_get_verify_result': 0,
    'SSL_write': 0,
    'SSL_read': 0,
    'SSL_shutdown': 0,
    'SSL_free': 0,
    'SSL_CTX_free': 0
}

seg_mapping = {idc.get_segm_name(x): (idc.get_segm_start(x), idc.get_segm_end(x)) for x in idautils.Segments()}
text_start, text_stop = seg_mapping[".text"]

print('**********************************have these functions')
for key in function_name:
    if key in necessary_SSL_function:
        necessary_SSL_function[key] = 1

print('\n******************************************fliter_initial')
# for all functions (is or include) functions in SSL_function,mark it.--->mark_size=1
function_mark = {}
for func in idautils.Functions():
    function_mark[get_func_name(func)] = 0

for key in function_mark:
    if key in SSL_function:
        function_mark[key] = 1

print('\n******************************************fliter white ')
# filter the function (whose mark_size=0),keep the function (whose mark_size=0).then
k = 1

while k:
    counter = len(function_mark)
    for key in function_mark:
        if function_mark[key] == 1:
            # print 'son---------', key
            for addr in XrefsTo(idc.get_name_ea_simple(key), 0):
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
        k = 0

function_Mark = []
for item in function_mark:
    # print type(item),item,function_mark[item]
    if (function_mark[item] == 1) & (type(item) == str):
        function_Mark.append(item)

X86_SSL_func_list = []

if machine == "X86-64":
    for key in necessary_SSL_function.keys():
        if necessary_SSL_function[key] == 1:
            for addr in XrefsTo(idc.get_name_ea_simple(key), 0):
                for addr0 in XrefsTo(addr.frm, 0):
                    X86_SSL_func_list.append(get_func_name(addr0.frm))

output = open('E:/result/gnutls/' + folder + '/Report_verify.txt', 'w+')

addr_list = []

visited_block = []
jmp_list = ["bnze", "beqz", "test"]
jump = {'bnez': 1, 'beqz': 0, 'jz': 1, 'jnz': 0, 'js': 0, 'jns': 0}
propagation_list = ["move"]
flag = 0

jmp_list_arm = ["CMP"]
jump_arm = {'BEQ': 0, 'BNE': 1}
propagation_list_arm = ["MOV", "MOVNE", "STR", "LDR"]

def traver_block_arm(cur_block, block_start, block_end, spoting):
    current_addr = block_start
    if block_start in visited_block:
        return
    visited_block.append(block_start)
    while current_addr < block_end:
        if idc.print_insn_mnem(current_addr) == "BL":
            call_func_name = idc.print_operand(current_addr, 0)
            if (call_func_name in SSL_function) & ("SSL_get_verify_result" not in call_func_name):
                global flag
                flag = 1
                return
        elif (idc.print_insn_mnem(current_addr) in propagation_list_arm) & (idc.print_operand(current_addr, 1) in spoting):
            spoting.append(idc.print_operand(addr_down, 0))
        elif (idc.print_insn_mnem(current_addr) in propagation_list_arm) & (idc.print_operand(current_addr, 0) in spoting) & (idc.print_operand(current_addr, 1) not in spoting):
            spoting.remove(idc.print_operand(addr_down, 0))
        elif (idc.print_insn_mnem(current_addr) in jmp_list_arm):
            spoting_new = spoting
            if idc.print_operand(current_addr, 0) not in spoting:
                for succ in cur_block.succs():
                    traver_block_arm(succ, succ.start_ea, succ.end_ea, spoting_new)
            else:
                current_addr = idc.next_head(current_addr)
                if idc.print_insn_mnem(current_addr) in jump_arm:
                    if jump_arm[idc.print_insn_mnem(current_addr)]:
                        for succ in cur_block.succs():
                            if succ.start_ea == idc.next_head(current_addr):
                                traver_block_arm(succ, succ.start_ea, succ.end_ea, spoting_new)
                    else:
                        for succ in cur_block.succs():
                            if succ.start_ea != idc.next_head(current_addr):
                                traver_block_arm(succ, succ.start_ea, succ.end_ea, spoting_new)
        current_addr = idc.next_head(current_addr)


def traver_block_x86(cur_block, block_start, block_end, spoting):
    current_addr = block_start
    if block_start in visited_block:
        return
    visited_block.append(block_start)
    while current_addr < block_end:
        if idc.print_insn_mnem(current_addr) == "call":
            call_func_name = idc.print_operand(current_addr, 0)
            if (call_func_name in SSL_function) & ("SSL_get_verify_result" not in call_func_name):
                global flag
                flag = 1
                return
        elif (idc.print_insn_mnem(current_addr) in propagation_list) & (idc.print_operand(current_addr, 1) in spoting):
            spoting.append(idc.print_operand(addr_down, 0))
        elif (idc.print_insn_mnem(current_addr) in propagation_list) & (idc.print_operand(current_addr, 0) in spoting) & (idc.print_operand(current_addr, 1) not in spoting):
            spoting.remove(idc.print_operand(addr_down, 0))
        elif (idc.print_insn_mnem(current_addr) in jmp_list):
            spoting_new = spoting
            if idc.print_operand(current_addr, 0) not in spoting:
                for succ in cur_block.succs():
                    traver_block_x86(succ, succ.start_ea, succ.end_ea, spoting_new)
            else:
                current_addr = idc.next_head(current_addr)
                if idc.print_insn_mnem(current_addr) in jump:
                    if jump[idc.print_insn_mnem(current_addr)]:
                        for succ in cur_block.succs():
                            if succ.start_ea == idc.next_head(current_addr):
                                traver_block_x86(succ, succ.start_ea, succ.end_ea, spoting_new)
                    else:
                        for succ in cur_block.succs():
                            if succ.start_ea != idc.next_head(current_addr):
                                traver_block_x86(succ, succ.start_ea, succ.end_ea, spoting_new)
        current_addr = idc.next_head(current_addr)


if 'SSL_get_verify_result' in function_mark:
    if machine != "X86-64":
        for addr in XrefsTo(idc.get_name_ea_simple('SSL_get_verify_result')):
            if get_func_name(addr.frm) in function_Mark:
                name = addr.frm
                addr_list.append(name)
                for addr in XrefsTo(name, 0):
                    name = idc.get_func_attr(addr.frm, FUNCATTR_START)
                for addr in XrefsTo(name, 0):
                    name = addr.frm
                target_addr = name
                addr_list.sort()
    else:
        for addr in XrefsTo(idc.get_name_ea_simple('SSL_get_verify_result')):
            for x in XrefsTo(addr.frm, 0):
                for j in XrefsTo(x.frm, 0):
                    for k in XrefsTo(j.frm, 0):
                        if (j.frm >= text_start) & (j.frm <= text_stop):
                            name = j.frm
                            addr_list.append(name)
                        elif (k.frm >= text_start) & (k.frm <= text_stop):  # idautils.CodeRef
                            name = k.frm
                            addr_list.append(name)
                        elif (get_func_name(k.frm) == None):
                            for m in XrefsTo(k.frm):
                                if get_func_name(m.frm) in function_Mark:
                                    name = m.frm
                                    addr_list.append(name)
            break

    for target_addr in addr_list:
        addr_down = idc.next_head(target_addr)
        f_blocks = idaapi.FlowChart(idaapi.get_func(target_addr), flags = idaapi.FC_PREDS)
        target_fun = idaapi.get_func(target_addr)
        cur_block = f_blocks[0]
        for block in f_blocks:
            if (block.start_ea <= target_addr) & (block.end_ea >= target_addr):
                cur_block = block
                break
        spoting = ['$v0', 'eax']
        if machine == "arm":
            traver_block_arm(cur_block, cur_block.start_ea, cur_block.end_ea, spoting)
        elif machine == "X86-64":
            traver_block_x86(cur_block, cur_block.start_ea, cur_block.end_ea, spoting)
        if flag == 1:
            print("uncorrect using SSL_get_verify_result")
        else:
            print("correct using SSL_get_verify_result")

        end = time.process_time()
        print('Running time: %s Seconds' % (end - start))
        end1 = time.time()
        print('Running time: %s Seconds' % (end1 - start1))

        with open("E:/result/gnutls/" + folder + "/time.txt", "w") as f:
            f.write(str(end - start))
            f.write('\n')
            f.write(str(end1 - start1))
        f.close()
output.close()
