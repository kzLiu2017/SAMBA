import idautils
import idc as idc
from idaapi import *
import os
import sys
import binascii
import ida_nalt

parement = {}
parement_value_mark = 0
ida_auto.auto_wait()

info = idaapi.get_inf_structure()
if info.procName == "ARM":
    machine = "arm"
elif (info.procName == "mipsl") | (info.procName == "mipsb"):
    machine = "mips"
elif info.procName == "metapc":
    machine = "X86-64"

folder = get_root_filename()
result_path = os.getcwd()
result_path = result_path[:result_path.find("squashfs-root/") + 14]

final_road_file = open(result_path + "Road_final.txt", "r")

def parament_analysis(target_fun):
    global parement, parement_value_mark
    call_addr=[]
    father_fun_name = []
    #if (target_fun=='SSL_CTX_set_verify')|(target_fun=='SSL_set_verify'):
    if machine.find('X86-64') >= 0:
        target_fun = "." + target_fun
    for addr in XrefsTo(idc.get_name_ea_simple(target_fun)):  # idautils
        father_fun_name.append(get_func_name(addr.frm))
        call_addr.append(addr.frm)
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
                                parement[str(call_addr[ii])] = "0"
                                parement_value_mark = 1
                        else:
                            value_parement = idc.print_operand(addr, 1)
                            judge = 1
                            parement[str(call_addr[ii])] = value_parement
                            parement_value_mark = 1
                else:
                    if idc.print_operand(addr, 0) == 'esi':
                        value_parement = idc.print_operand(addr, 1)
                        if value_parement == "20000h":
                            judge = 1
                            parement[str(call_addr[ii])] = value_parement
                            parement_value_mark = 1
                        elif value_parement == "2000000h":
                            judge = 1
                            parement[str(call_addr[ii])] = value_parement
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
                        parement[str(call_addr[ii])] = value_parement[1:]
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
                    if idc.print_insn_mnem(addr) == "la":
                        continue
                    if (value_parement == '1') | (value_parement == '0'):
                        parement_value_mark = 1
                        judge = 1
                        parement[str(call_addr[ii])] = int(value_parement)
                    elif value_parement == '$zero':
                        parement_value_mark = 1
                        judge = 1
                        parement[str(call_addr[ii])] = '0'
                    break

for func in idautils.Functions():
    if (get_func_name(func) == 'SSL_CTX_set_verify') | (get_func_name(func) == '.SSL_CTX_set_verify'):
        parament_analysis('SSL_CTX_set_verify')

paremeter_file = open(result_path + "parameter_result.txt", "w")
for key in parement:
    paremeter_file.write(key)
    paremeter_file.write(" ")
    paremeter_file.write(str(parement[key]))
idc.Exit(0)