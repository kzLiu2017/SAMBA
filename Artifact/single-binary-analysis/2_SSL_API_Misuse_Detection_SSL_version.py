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
    'gnutls_check_version': 0,
    'gnutls_global_init': 0,
    'gnutls_certificate_allocate_credentials':0,
    'gnutls_certificate_set_x509_trust_file': 0,
    'gnutls_certificate_set_x509_trust_dir': 0,
    'gnutls_certificate_set_x509_crl_file': 0,
    'gnutls_certificate_set_x509_system_trust': 0,
    'gnutls_certificate_set_x509_trust': 0,
    'gnutls_init': 0,
    'gnutls_server_name_set': 0,
    'gnutls_set_default_priority': 0,
    'gnutls_set_default_priority_append': 0,
    'gnutls_priority_init': 0,
    'gnutls_priority_set': 0,
    'gnutls_priority_set_direct': 0,
    'gnutls_priority_deinit': 0,
    'gnutls_credentials_set': 0,
    'gnutls_transport_set_int': 0,
    'gnutls_transport_set_int2': 0,
    'gnutls_handshake_set_timeout':0,
    'gnutls_handshake': 0,
    'gnutls_session_set_verify_cert': 0,
    'gnutls_session_set_verify_cert2': 0,
    'gnutls_certificate_verify_peers2': 0,
    'gnutls_x509_crt_check_hostname': 0,
    'gnutls_x509_crt_check_hostname2': 0,
    'gnutls_certificate_verify_peers3': 0,
    'gnutls_certificate_set_verify_function': 0,
    'gnutls_record_send': 0,
    'gnutls_record_recv': 0,
    'gnutls_error_is_fatal': 0,
    'gnutls_bye': 0,
    'gnutls_deinit': 0,
    'gnutls_certificate_free_credentials': 0,
    'gnutls_global_deinit': 0,
    'gnutls_certificate_type_get': 0,
    'gnutls_session_get_verify_cert_status': 0,
    'gnutls_certificate_verification_status_print': 0,
    'gnutls_certificate_get_peers': 0,
}
necessary_SSL_function = {  #
    'gnutls_global_init': 0,
    'gnutls_certificate_allocate_credentials':0,
    'gnutls_certificate_set_x509_trust_file': 0,
    'gnutls_certificate_set_x509_trust_dir': 0,
    'gnutls_certificate_set_x509_crl_file': 0,
    'gnutls_certificate_set_x509_system_trust': 0,
    'gnutls_certificate_set_x509_trust': 0,
    'gnutls_init': 0,
    'gnutls_server_name_set': 0,
    'gnutls_set_default_priority': 0,
    'gnutls_set_default_priority_append': 0,
    'gnutls_priority_init': 0,
    'gnutls_priority_set': 0,
    'gnutls_priority_set_direct': 0,
    'gnutls_priority_deinit': 0,
    'gnutls_credentials_set': 0,
    'gnutls_transport_set_int': 0,
    'gnutls_transport_set_int2': 0,
    'gnutls_handshake': 0,
    'gnutls_session_set_verify_cert': 0,
    'gnutls_session_set_verify_cert2': 0,
    'gnutls_certificate_verify_peers2': 0,
    'gnutls_certificate_verify_peers3': 0,
    'gnutls_record_send': 0,
    'gnutls_record_recv': 0,
    'gnutls_bye': 0,
    'gnutls_deinit': 0,
    'gnutls_certificate_free_credentials': 0,
    'gnutls_global_deinit': 0,
    'gnutls_certificate_type_get': 0,
    'gnutls_session_get_verify_cert_status': 0,
    'gnutls_certificate_get_peers': 0,
}

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

while True:
    counter = len(function_mark)
    for key in function_mark:
        if function_mark[key] == 1:
            # print 'son---------', key
            for addr in XrefsTo(idc.get_name_ea_simple(key), 0):
                if get_func_name(addr.frm) in function_mark.keys():
                    if function_mark[get_func_name(addr.frm)] == 0:
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
    if (function_mark[item] == 1) & (type(item) == str):
        function_Mark.append(item)

if 'gnutls_handshake' in function_mark:
    print(" Roads use tls handshake")
else:
    print(" Roads not use tls handshake")

if ('gnutls_session_set_verify_cert' not in function_mark) & ('gnutls_session_set_verify_cert2' not in function_mark) & ('gnutls_certificate_verify_peers2' not in function_mark) & ('gnutls_certificate_verify_peers3' not in function_mark) :
    print('###')
    output = open('E:/result/gnutls/' + folder + '/Report_verify.txt', 'w+')
    output.write('Roads do not use gnutls_session_set_verify_cert | gnutls_session_set_verify_cert2 | gnutls_certificate_verify_peers2 | gnutls_certificate_verify_peers3')
    output.close()

    print('\n**************************************save file')
    with open("E:/result/gnutls/" + folder + "/fun_name.txt", "w") as f:
        for i in function_Mark:
            f.write(i)
            f.write('\n')
    f.close()
else:
    output = open('E:/result/gnutls/' + folder + '/Report_verify.txt', 'w+')
    if 'gnutls_session_set_verify_cert' in function_mark:
        output.write("Correct" + " Roads use gnutls_session_set_verify_cert")
        output.write('\n')
    if 'gnutls_session_set_verify_cert2' in function_mark:
        output.write("correct" + " Roads use gnutls_session_set_verify_cert2")
        output.write('\n')
    if 'gnutls_certificate_verify_peers2' in function_mark:
        name = idc.get_name_ea_simple('gnutls_certificate_verify_peers2')
        for addr in XrefsTo(name, 0):
            name = addr.frm
        for addr in XrefsTo(name, 0):
            name = idc.get_func_attr(addr.frm, FUNCATTR_START)
        for addr in XrefsTo(name, 0):
            name = addr.frm
        target_addr = name

        must_name = idc.get_name_ea_simple('gnutls_handshake')
        for addr in XrefsTo(must_name, 0):
            must_name = addr.frm
        for addr in XrefsTo(must_name, 0):
            must_name = idc.get_func_attr(addr.frm, FUNCATTR_START)

        addr_up = idc.prev_head(target_addr)
        addr_down = idc.next_head(target_addr)
        f_blocks = idaapi.FlowChart(idaapi.get_func(target_addr), flags=idaapi.FC_PREDS)

        cur_block = f_blocks[0]
        for block in f_blocks:
            if (block.start_ea < target_addr) & (block.end_ea > target_addr):
                cur_block = block
                break

        spoting = []
        while addr_up >= cur_block.start_ea:
            if (idc.print_insn_mnem(addr_up) == "lea") & (idc.print_operand(addr_up, 0) == "rsi"):
                spoting.append(idc.print_operand(addr_up, 1))
                break
            else:
                addr_up = idc.prev_head(addr_up)

        flag_1 = 0
        while addr_down <= cur_block.end_ea:
            if (idc.print_insn_mnem(addr_down) == "test") & (idc.print_operand(addr_down, 0) == "eax"):
                flag_1 = 1
                jump = {'jz': 1, 'jnz': 0, 'js': 0, 'jns': 0}
                jump_addr = idc.next_head(addr_down)
                target_block2 = f_blocks[0]
                if jump[idc.print_insn_mnem(jump_addr)]:
                    for succ in cur_block.succs():
                        if succ.start_ea == int("0x"+idc.print_operand(jump_addr, 0)[4:], 16):
                            target_block2 = succ
                else:
                    for succ in cur_block.succs():
                        if succ.start_ea != int("0x"+idc.print_operand(jump_addr, 0)[4:], 16):
                            target_block2 = succ
                cur_addr2 = target_block2.start_ea

                result_flag = 0
                result_flag2 = 0
                while (cur_addr2 <= target_block2.end_ea) & (result_flag2 == 0):
                    if spoting.count(idc.print_operand(cur_addr2, 1)) >= 1:
                        if idc.print_insn_mnem(cur_addr2) == "mov":
                            if idc.print_operand(cur_addr2, 0) == "eax":
                                spoting.append("rax")
                            spoting.append(idc.print_operand(cur_addr2, 0))
                        if (idc.print_insn_mnem(cur_addr2) == "test") & \
                                (spoting.count(idc.print_operand(cur_addr2, 0)) >= 1):
                            result_flag = 1
                            target_block3 = target_block2
                            jump_addr = idc.next_head(cur_addr2)
                            if jump[idc.print_insn_mnem(jump_addr)]:
                                for succ in cur_block.succs():
                                    if succ.start_ea != int("0x"+idc.print_operand(jump_addr, 0)[4:], 16):
                                        target_block3 = succ
                            else:
                                for succ in cur_block.succs():
                                    if succ.start_ea == int("0x"+idc.print_operand(jump_addr, 0)[4:], 16):
                                        target_block3 = succ

                            block_list = Queue(0)
                            block_list.put(target_block3)
                            while (not block_list.empty()) & (result_flag2 == 0):
                                tmp = block_list.get()
                                for succ in tmp.succs():
                                    block_list.put(succ)
                                    cur = succ.start_ea
                                    while cur <= succ.end_ea:
                                        if idc.print_insn_mnem(cur) == "call":
                                            if idc.print_operand(cur, 0) == 'gnutls_handshake':
                                                result_flag2 = 1
                                                break
                                        cur = idc.next_head(cur)
                            break
                    cur_addr2 = idc.next_head(cur_addr2)

                if result_flag2 == 1:
                    output.write("Uncorrect1" + " Roads use gnutls_certificate_verify_peers2")
                    output.write('\n')
                else:
                    output.write("correct" + " Roads use gnutls_certificate_verify_peers2")
                    output.write('\n')
                break
            else:
                addr_down = idc.next_head(addr_down)

        if flag_1 == 0:
            output.write("Uncorrect" + " Roads use gnutls_certificate_verify_peers2")
            output.write('\n')



        end = time.process_time()
        print('Running time: %s Seconds' % (end - start))
        end1 = time.time()
        print('Running time: %s Seconds' % (end1 - start1))

        with open("E:/result/gnutls/" + folder + "/time.txt", "w") as f:
            f.write(str(end - start))
            f.write('\n')
            f.write(str(end1 - start1))
        f.close()

    if 'gnutls_certificate_verify_peers3' in function_mark:
        name = idc.get_name_ea_simple('gnutls_certificate_verify_peers2')

    output.close()