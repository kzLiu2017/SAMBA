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
print(folder)
print(file_path + folder)
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
        print(key)

# print('\n***************************do not have these functions')
# for key in necessary_SSL_function:
#     if necessary_SSL_function.get(key) == 0:
#         print(key)

print('\n******************************************fliter_initial')
# for all functions (is or include) functions in SSL_function,mark it.--->mark_size=1
function_mark = {}
for func in idautils.Functions():
    function_mark[get_func_name(func)] = 0

for key in function_mark:
    if key in SSL_function:
        function_mark[key] = 1
        # print(key)

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
    print(necessary_SSL_function)
    for key in necessary_SSL_function.keys():
        if necessary_SSL_function[key] == 1:
            for addr in XrefsTo(idc.get_name_ea_simple(key), 0):
                for addr0 in XrefsTo(addr.frm, 0):
                    X86_SSL_func_list.append(get_func_name(addr0.frm))

output = open('E:/result/gnutls/' + folder + '/Report_verify.txt', 'w+')

addr_list = []
addr_list_verify = []

visited_block = []
jmp_list = ["bnze", "beqz", "test"]
jump = {'bnez': 1, 'beqz': 0, 'jz': 1, 'jnz': 0, 'js': 0, 'jns': 0}
propagation_list = ["move"]
flag = 0

jmp_list_arm_0 = ["CMP"]
jmp_list_arm_1 = ["SUBS"]
# beq : cmp fail jump, bne opposite
jump_arm = {'BEQ': 0, 'BNE': 1}
propagation_list_arm = ["MOV", "MOVNE", "STR", "LDR"]
propagation_list_x86 = ["mov"]

def traver_block_arm(cur_block, block_start, block_end, spoting):
    global flag
    flag = 0
    current_addr = block_start
    if block_start in visited_block:
        return
    visited_block.append(block_start)
    while current_addr < block_end:
        print(hex(current_addr))
        if len(spoting) == 0:
            if (idc.print_insn_mnem(current_addr) == "BL") and ("SSL_get_peer_certificate" in idc.print_operand(current_addr, 0)):
                spoting = ['R0']
            elif idc.print_insn_mnem(current_addr) in jump_arm.keys():
                for succ in cur_block.succs():
                    traver_block_arm(succ, succ.start_ea, succ.end_ea, spoting)
        else:
            if (idc.print_insn_mnem(current_addr) in propagation_list_arm) & (idc.print_operand(current_addr, 1) in spoting):
                spoting.append(idc.print_operand(current_addr, 0))
            elif (idc.print_insn_mnem(current_addr) in propagation_list_arm) & (idc.print_operand(current_addr, 0) in spoting) & (idc.print_operand(current_addr, 1) not in spoting):
                print(current_addr)
                spoting.remove(idc.print_operand(current_addr, 0))
            elif (idc.print_insn_mnem(current_addr) in jmp_list_arm_0):
                spoting_new = spoting
                if idc.print_operand(current_addr, 0) not in spoting:
                    for succ in cur_block.succs():
                        traver_block_arm(succ, succ.start_ea, succ.end_ea, spoting_new)
                else:
                    current_addr = idc.next_head(current_addr)
                    while (current_addr < block_end):
                        if idc.print_insn_mnem(current_addr) in jump_arm:
                            print(hex(current_addr), idc.print_insn_mnem(current_addr))
                            flag = 1
                            if jump_arm[idc.print_insn_mnem(current_addr)]:
                                for succ in cur_block.succs():
                                    if succ.start_ea == idc.next_head(current_addr):
                                        print("succ",succ)
                                        return succ
                            elif jump_arm[idc.print_insn_mnem(current_addr)] == 0:
                                for succ in cur_block.succs():
                                    if succ.start_ea != idc.next_head(current_addr):
                                        print("succ",succ)
                                        return succ
                        current_addr = idc.next_head(current_addr)

            elif (idc.print_insn_mnem(current_addr) in jmp_list_arm_1):
                spoting_new = spoting
                if idc.print_operand(current_addr, 1) not in spoting:
                    for succ in cur_block.succs():
                        traver_block_arm(succ, succ.start_ea, succ.end_ea, spoting_new)
                else:
                    current_addr = idc.next_head(current_addr)
                    if idc.print_insn_mnem(current_addr) in jump_arm:
                        print("addr:",hex(current_addr))
                        flag = 1
                        if jump_arm[idc.print_insn_mnem(current_addr)]:
                            for succ in cur_block.succs():
                                if succ.start_ea != idc.next_head(current_addr):
                                    return succ
                        else:
                            for succ in cur_block.succs():
                                if succ.start_ea == idc.next_head(current_addr):
                                    return succ
        current_addr = idc.next_head(current_addr)

def traver_second_API_arm(cur_block, spoting, block_set):
    block_start = cur_block.start_ea
    block_end = cur_block.end_ea
    current_addr = block_start
    block_set.append(cur_block.start_ea)
    while current_addr < block_end:
        print("spoting", spoting, hex(current_addr))
        if len(spoting) == 0:
            if (idc.print_insn_mnem(current_addr) == "BL") and ("SSL_get_verify_result" in idc.print_operand(current_addr, 0)):
                spoting = ['R0']
            elif idc.print_insn_mnem(current_addr) in jump_arm.keys():
                for succ in cur_block.succs():
                    sys.exit()
                    if succ.start_ea not in block_set:
                        return_value = traver_second_API_arm(succ, spoting, block_set)
                        block_set.remove(succ.start_ea)
                        if return_value == 1:
                            print(hex(current_addr))
                            return 1
        else:
            print(hex(current_addr), idc.print_insn_mnem(current_addr) in propagation_list_arm), (idc.print_operand(current_addr, 1) in spoting)
            print((idc.print_insn_mnem(current_addr) in jmp_list_arm_1))
            if (idc.print_insn_mnem(current_addr) in propagation_list_arm) & (idc.print_operand(current_addr, 1) in spoting):
                spoting.append(idc.print_operand(current_addr, 0))
            elif (idc.print_insn_mnem(current_addr) in propagation_list_arm) & (idc.print_operand(current_addr, 0) in spoting) & (idc.print_operand(current_addr, 1) not in spoting):
                spoting.remove(idc.print_operand(current_addr, 0))
            elif (idc.print_insn_mnem(current_addr) in jmp_list_arm_1):
                spoting_new = spoting
                if idc.print_operand(current_addr, 1) not in spoting:
                    for succ in cur_block.succs():
                        if succ.start_ea not in block_set:
                            return_value = traver_second_API_arm(succ, spoting_new, block_set)
                            block_set.remove(succ.start_ea)
                            if return_value == 1:
                                print(hex(current_addr))
                                return 1
                else:
                    print("addr:",hex(current_addr))
                    return 1
            elif (idc.print_insn_mnem(current_addr) in jmp_list_arm_0):
                print(idc.print_operand(current_addr, 0) not in spoting)
                spoting_new = spoting
                if idc.print_operand(current_addr, 0) not in spoting:
                    for succ in cur_block.succs():
                        if succ.start_ea not in block_set:
                            return_value = traver_second_API_arm(succ, spoting_new, block_set)
                            block_set.remove(succ.start_ea)
                            if return_value == 1:
                                print(hex(current_addr))
                                return 1
                else:
                    print(hex(current_addr))
                    return 1
        current_addr = idc.next_head(current_addr)

def traver_block_x86(cur_block, block_start, block_end, spoting):
    global flag
    flag = 0
    current_addr = block_start
    if block_start in visited_block:
        return
    visited_block.append(block_start)
    while current_addr < block_end:
        if len(spoting) == 0:
            if (idc.print_insn_mnem(current_addr) == "call") and ("SSL_get_peer_certificate" in idc.print_operand(current_addr, 0)):
                spoting = ['rax']
            elif idc.print_insn_mnem(current_addr) in jump.keys():
                for succ in cur_block.succs():
                    traver_block_x86(succ, succ.start_ea, succ.end_ea, spoting)
        else:
            if (idc.print_insn_mnem(current_addr) in propagation_list_x86) & (idc.print_operand(current_addr, 1) in spoting):
                spoting.append(idc.print_operand(current_addr, 0))
            elif (idc.print_insn_mnem(current_addr) in propagation_list_x86) & (idc.print_operand(current_addr, 0) in spoting) & (idc.print_operand(current_addr, 1) not in spoting):
                print(current_addr)
                spoting.remove(idc.print_operand(current_addr, 0))
            elif (idc.print_insn_mnem(current_addr) in jmp_list):
                spoting_new = spoting
                if idc.print_operand(current_addr, 0) not in spoting:
                    for succ in cur_block.succs():
                        traver_block_x86(succ, succ.start_ea, succ.end_ea, spoting_new)
                else:
                    current_addr = idc.next_head(current_addr)
                    if idc.print_insn_mnem(current_addr) in jump:
                        flag = 1
                        if jump[idc.print_insn_mnem(current_addr)]:
                            for succ in cur_block.succs():
                                if succ.start_ea == idc.next_head(current_addr):
                                    return succ
                        else:
                            for succ in cur_block.succs():
                                if succ.start_ea != idc.next_head(current_addr):
                                    return succ
            elif (idc.print_insn_mnem(current_addr) in jmp_list):
                spoting_new = spoting
                if idc.print_operand(current_addr, 1) not in spoting:
                    for succ in cur_block.succs():
                        traver_block_x86(succ, succ.start_ea, succ.end_ea, spoting_new)
                else:
                    current_addr = idc.next_head(current_addr)
                    if idc.print_insn_mnem(current_addr) in jump:
                        flag = 1
                        if jump[idc.print_insn_mnem(current_addr)]:
                            for succ in cur_block.succs():
                                if succ.start_ea != idc.next_head(current_addr):
                                    return succ
                        else:
                            for succ in cur_block.succs():
                                if succ.start_ea == idc.next_head(current_addr):
                                    return succ
        current_addr = idc.next_head(current_addr)

def traver_second_API_x86(cur_block, spoting, block_set):
    block_start = cur_block.start_ea
    block_end = cur_block.end_ea
    current_addr = block_start
    block_set.append(cur_block.start_ea)
    while current_addr < block_end:
        print("spoting", spoting, hex(current_addr))
        if len(spoting) == 0:
            if (idc.print_insn_mnem(current_addr) == "call") and ("SSL_get_verify_result" in idc.print_operand(current_addr, 0)):
                spoting = ['rax']
            elif idc.print_insn_mnem(current_addr) in jump.keys():
                for succ in cur_block.succs():
                    if succ.start_ea not in block_set:
                        return_value = traver_second_API_x86(succ, spoting, block_set)
                        block_set.remove(succ.start_ea)
                        if return_value == 1:
                                return 1
        else:
            if (idc.print_insn_mnem(current_addr) in propagation_list_x86) & (idc.print_operand(current_addr, 1) in spoting):
                spoting.append(idc.print_operand(current_addr, 0))
            elif (idc.print_insn_mnem(current_addr) in propagation_list_x86) & (idc.print_operand(current_addr, 0) in spoting) & (idc.print_operand(current_addr, 1) not in spoting):
                spoting.remove(idc.print_operand(current_addr, 0))
            elif (idc.print_insn_mnem(current_addr) in jmp_list):
                spoting_new = spoting
                if idc.print_operand(current_addr, 1) not in spoting:
                    for succ in cur_block.succs():
                        if succ.start_ea not in block_set:
                            return_value = traver_second_API_x86(succ, spoting_new, block_set)
                            block_set.remove(succ.start_ea)
                            if return_value == 1:
                                return 1
                else:
                    return 1
            elif (idc.print_insn_mnem(current_addr) in jmp_list_arm_0):
                print(idc.print_operand(current_addr, 0) not in spoting)
                spoting_new = spoting
                if idc.print_operand(current_addr, 0) not in spoting:
                    for succ in cur_block.succs():
                        if succ.start_ea not in block_set:
                            return_value = traver_second_API_x86(succ, spoting_new, block_set)
                            block_set.remove(succ.start_ea)
                            if return_value == 1:
                                return 1
                else:
                    return 1
        current_addr = idc.next_head(current_addr)

if ('SSL_get_verify_result' in function_mark) and ('SSL_get_peer_certificate' in function_mark):
    if machine != "X86-64":
        for addr in XrefsTo(idc.get_name_ea_simple('SSL_get_peer_certificate')):
            print(get_func_name(addr.frm), get_func_name(addr.frm) in function_Mark)
            if get_func_name(addr.frm) in function_Mark:
                name = addr.frm
                addr_list.append(name)
                for addr in XrefsTo(name, 0):
                    name = idc.get_func_attr(addr.frm, FUNCATTR_START)
                for addr in XrefsTo(name, 0):
                    name = addr.frm
                target_addr = name
                addr_list.sort()
        for addr in XrefsTo(idc.get_name_ea_simple('SSL_get_verify_result')):
            print(get_func_name(addr.frm), get_func_name(addr.frm) in function_Mark)
            if get_func_name(addr.frm) in function_Mark:
                name = addr.frm
                addr_list_verify.append(name)
                for addr in XrefsTo(name, 0):
                    name = idc.get_func_attr(addr.frm, FUNCATTR_START)
                for addr in XrefsTo(name, 0):
                    name = addr.frm
                target_addr = name
                addr_list_verify.sort()
    else:
        for addr in XrefsTo(idc.get_name_ea_simple('SSL_get_peer_certificate')):
            for x in XrefsTo(addr.frm, 0):
                for j in XrefsTo(x.frm, 0):
                    for k in XrefsTo(j.frm, 0):
                        print(hex(addr.frm),hex(x.frm),hex(j.frm),hex(k.frm))
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
        for addr in XrefsTo(idc.get_name_ea_simple('SSL_get_verify_result')):
            for x in XrefsTo(addr.frm, 0):
                for j in XrefsTo(x.frm, 0):
                    for k in XrefsTo(j.frm, 0):
                        print(hex(addr.frm),hex(x.frm),hex(j.frm),hex(k.frm))
                        if (j.frm >= text_start) & (j.frm <= text_stop):
                            name = j.frm
                            addr_list_verify.append(name)
                        elif (k.frm >= text_start) & (k.frm <= text_stop):  # idautils.CodeRef
                            name = k.frm
                            addr_list_verify.append(name)
                        elif (get_func_name(k.frm) == None):
                            for m in XrefsTo(k.frm):
                                if get_func_name(m.frm) in function_Mark:
                                    name = m.frm
                                    addr_list_verify.append(name)
            break

    for target_addr in addr_list:
        addr_down = idc.next_head(target_addr)
        # 得到控制流图
        f_blocks = idaapi.FlowChart(idaapi.get_func(target_addr), flags = idaapi.FC_PREDS)
        target_fun = idaapi.get_func(target_addr)
        cur_block = f_blocks[0]
        for block in f_blocks:
            print(hex(block.start_ea), hex(block.end_ea), hex(target_addr))
            if (block.start_ea <= target_addr) & (block.end_ea >= target_addr):
                cur_block = block
                break
        spoting = []
        print("traver block", hex(cur_block.start_ea), hex(cur_block.end_ea))
        if machine == "arm":
            spoting = []
            succ = traver_block_arm(cur_block, cur_block.start_ea, cur_block.end_ea, spoting)
        elif machine == "X86-64":
            print("X86-64")
            spoting = []
            succ = traver_block_x86(cur_block, cur_block.start_ea, cur_block.end_ea, spoting)
        print("flag",flag, hex(succ.start_ea))
        if flag == 1:
            flag = 0
            spoting = []
            block_set = []
            for target_addr_verify in addr_list_verify:
                print(hex(target_addr_verify))
                addr_down = idc.next_head(target_addr_verify)
                f_blocks = idaapi.FlowChart(idaapi.get_func(target_addr_verify), flags = idaapi.FC_PREDS)
                target_fun = idaapi.get_func(target_addr_verify)
                cur_block = f_blocks[0]
                for block in f_blocks:
                    if (block.start_ea <= target_addr_verify) & (block.end_ea >= target_addr_verify):
                        cur_block = block
                        break
                if machine == "arm":
                    flag = traver_second_API_arm(cur_block, spoting, block_set)
                elif machine == "X86-64":
                    flag = traver_second_API_x86(cur_block, spoting, block_set)
                print("flag",flag)
                if flag == 1:
                    print("correct using SSL_get_peer_certificate and SSL_get_verify_result")
                else:
                    print("uncorrect using SSL_get_peer_certificate and SSL_get_verify_result")

        end = time.process_time()
        print('Running time: %s Seconds' % (end - start))
        end1 = time.time()
        print('Running time: %s Seconds' % (end1 - start1))

        with open("E:/result/gnutls/" + folder + "/time.txt", "w") as f:
            f.write(str(end - start))
            f.write('\n')
            f.write(str(end1 - start1))
        f.close()
print(folder)
output.close()