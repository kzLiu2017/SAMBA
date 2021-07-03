import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angr.knowledge_plugins.key_definitions.undefined import Undefined
import time
import sys


project = ""
target_func_addr = "" # Odd addresses because ARM Thumb mode 
call_to_func=[]
register=[]
nummbers=[]
H=[]
Func=[]
# Some standard options for the CFG
start_address = 0
end_address = 0
region_a=[]
bin_cfg = ""
# Getting the func object from the addres
target_func = ""
stop_find_preblock = False
block_sequence = []

def RD(call_to_func, register):
    # Starting the ReachingDefinition analysis
    rd = project.analyses.ReachingDefinitions(subject = target_func, track_tmps = True, func_graph = target_func.graph,cc = target_func.calling_convention, observation_points = [("insn", call_to_func[0], 0)])
        # VEX offset is just how the VEX IR refers to registers
    reg_vex_offset = project.arch.registers.get(register[0], None)[0]
    Reg_defs = rd.one_result.register_definitions.get_objects_by_offset(reg_vex_offset)
    return Reg_defs

def find_branch_ins(block_addr):
    global stop_find_preblock
    preblcok = bin_cfg.get_predecessors(cfgnode = bin_cfg.get_any_node(block_addr, anyaddr = True), excluding_fakeret = False)
    if preblcok == []:
        return True
    for bl in preblcok:
        print("*******analyse preblcok***********")
        print("bl", bl)
        # If there is if instruction in the block, which means conditional jumps
        if bl.block.vex._pp_str().find('if') >= 0:
            #get the last but one instruction in the block
            print("********try to find if in vex***********")
            insns = bl.block.capstone.insns
            opt = insns[len(insns) - 2]
            for reg in register:
                print("***********try to find reg****************")
                if opt.insn.op_str.find(reg) >= 0:
                    print("the insn is", opt)
                    # get the value by the address
                    vex_str = bl.block.vex._pp_str()
                    vex_str = vex_str[vex_str.find("if"):]
                    addr = vex_str[vex_str.find("PUT(pc) = ") + 10:]
                    addr = addr[:addr.find(";")]
                    addr = int(addr, 16)
                    if addr == block_addr:
                        print("the value is 1")
                    else:
                        print("the value is 0")
                    stop_find_preblock = False
                else:
                    find_branch_ins(bl.addr)
        else:
            find_branch_ins(bl.addr)

def value_of_Branch_arm(reg_defs):
    for reg_def in reg_defs:
        if bin_cfg.get_any_node(reg_def.codeloc.block_addr, anyaddr = True) != bin_cfg.model.get_any_node(call_to_func[0], anyaddr = True):
            break_loop = False
            block_addr = call_to_func[0]
            global stop_find_preblock
            if stop_find_preblock == False:
                stop_find_preblock = find_branch_ins(block_addr)

def solve_mem_and_stack_arm(Reg_defs):
    bool_follow = False
    reg_def = Reg_defs.pop()
    for data in reg_def.data:
        if type(data) == Undefined:
            bool_follow = True
    if bool_follow == True:
        ins_addr = reg_def.codeloc.ins_addr
        node = bin_cfg.get_any_node(ins_addr, anyaddr = True)
        index = 0
        for insn in node.block.capstone.insns:
            if insn.address == ins_addr:
                if insn.mnemonic == "ldr":
                    find_str_op = False
                    stack_addr = insn.op_str[insn.op_str.find(", ") + 2:]
                    # find if there is the str insn that we want in the block
                    while index >= 0:
                        if node.block.capstone.insns[index].insn.mnemonic == "str":
                            if node.block.capstone.insns[index].insn.op_str.find(stack_addr) >= 0:
                                return node.block.capstone.insns[index]
                        index = index - 1
                    # follow pre block to find target str insn
                    while True:
                        print("the node addres is ", node)
                        nodes = bin_cfg.get_predecessors(node, excluding_fakeret = False)
                        #if there only one pre block, just analyse the block and find target str insn
                        if len(nodes) == 1:
                            pre_node = nodes[0]
                            node = pre_node
                            for insn in pre_node.block.capstone.insns:
                                if insn.mnemonic == "str":
                                    if insn.op_str.find(stack_addr) >= 0:
                                        return insn
                        #if there are more than 1 pre block, compare the end address of the block with the address in the block_sequence
                        elif len(nodes) > 1:
                            pre_node = None
                            for node in nodes:
                                for insn in node.block.capstone.insns:
                                    if insn.address == block_sequence[0]:
                                        pre_node = node
                                        node = pre_node
                                        block_sequence.pop(0)
                            if pre_node != None:
                                for insn in pre_node.block.capstone.insns:
                                    if insn.mnemonic == "str":
                                        if insn.op_str.find(stack_addr) >= 0:
                                            return insn
                else:
                    return None
            index = index + 1
                        # pre_node = None
                        # for addr in block_sequence:
                        #     for node in nodes:
                        #         if addr == node.addr:
                        #             pre_node = node[0]
                        # print("traverse the predecessors", pre_node)
                        # for insn in pre_node.block.capstone.insns:
                        #     if insn.mnemonic == "str":
                        #         if insn.op_str.find(stack_addr) >= 0:
                        #             return insn


def read_sequence_from_file(api_sequence_file, index):
    s_file = open(api_sequence_file)
    lines = s_file.readlines()
    sq_line = lines[index]
    index_value = 0
    global start_address, target_func_addr, end_address, call_to_func
    while sq_line.find(',') >= 0:
        # the first one is function start address, the second one is the end address and the third one is the api called address
        if index_value == 0:
            start_address = int(sq_line[:sq_line.find(',')], 16)
            target_func_addr = start_address
            sq_line = sq_line[sq_line.find(',') + 1:]
            index_value = index_value + 1
            continue
        elif index_value == 1:
            end_address = int(sq_line[:sq_line.find(',')], 16)
            sq_line = sq_line[sq_line.find(',') + 1:]
            index_value = index_value + 1
            continue
        elif index_value == 2:
            call_to_func.append(int(sq_line[:sq_line.find(',')], 16))
            sq_line = sq_line[sq_line.find(',') + 1:]
            index_value = index_value + 1
            continue
        block_sequence.append(int(sq_line[:sq_line.find(',')], 16))
        sq_line = sq_line[sq_line.find(',') + 1:]
    fun_addr=(start_address, end_address)
    region_a.append(fun_addr)

def preprocessing():
    # there are three paramenters when run this script, the first one is the binary filename, the second one is the configure file and the last one is the line number
    global project, bin_cfg, target_func
    blob_path = str(sys.argv[1])
    print("Creating angr Project")
    project = angr.Project(blob_path)
    filename = sys.argv[2]
    if str(project.arch).find("AMD64") >= 0:
        register.append("esi")#the register that need to follow
        H.append("+esi")
    elif str(project.arch).find("ARM") >= 0:
        register.append("r1")#the register that need to follow
        H.append("+r1")
    index = int(sys.argv[3])
    read_sequence_from_file(filename, index)
    
    print("Creating binary CFG")
    bin_cfg = project.analyses.CFGFast(regions = region_a, cross_references=True, force_complete_scan=True,normalize=True)
    # Getting the func object from the addres
    target_func = bin_cfg.functions.get_by_addr(target_func_addr)

def main():
    preprocessing()
    lenth=len(call_to_func)
    print("lenth",lenth)
    index = 0
    while lenth!=0:
        # read_sequence_from_file(index)
        index = index + 1
        print(call_to_func,"call_to_func")
        print(register,"register")
        reg_defs=RD(call_to_func,register)
        # if bool_Branch == True:
        #     break
        for reg_def in reg_defs:
            current_def = reg_def
        if str(project.arch).find("AMD64") >= 0:
            for d in current_def.data:
                if str(d) == '<Undefined>':
                    print('<Undefined>')
                    del register[0]
                    del call_to_func[0]
                    addr = current_def.codeloc.ins_addr
                    block = project.factory.block(addr,4)
                    for ins in block.capstone.insns:
                        instruct = ins.mnemonic
                        opt = ins.op_str
                    if instruct == "mov":
                        reg_64 = opt[opt.find(", ") + 2:]
                        if len(reg_64) > 3:
                            return
                        else:
                            register.append(reg_64)
                            call_to_func.append(addr)
                else:
                    print("the value is ", d)
                    return
        elif str(project.arch).find("ARM") >= 0:
            value_of_Branch_arm(reg_defs)
            stack_insn = solve_mem_and_stack_arm(reg_defs)
            if stack_insn == None:
                if len(current_def.tags)==0:
                    for d in current_def.data:
                        if(str(d)=='<Undefined>'):
                            print('Undefined')
                            del register[0]
                            del call_to_func[0]
                            print(hex(current_def.codeloc.ins_addr))
                            addr = current_def.codeloc.ins_addr
                            block = project.factory.block(addr,4)
                            for ins in block.capstone.insns:
                                instruct=ins.mnemonic
                                opt=ins.op_str
                            
                            if instruct=="mov":
                                if opt[4]=="r":
                                    print(opt[4:6])
                                    register.append(opt[4:6])
                                    call_to_func.append(addr)
                                    del H[0]
                                    H.append("+"+opt[4:6])
                                if opt[4]=="#":
                                    print(hex(opt[9:len(opt)]))
                                    nummbers.append(int(opt[9:len(opt)]))
                            
                            if (instruct=="add")|(instruct=="adds"):
                                if opt[4]=="r":
                                    print(opt[4:6])
                                    register.append(opt[4:6])
                                    call_to_func.append(addr)
                                    del H[0]
                                    H.append("+"+opt[4:6])
                                if opt[8]=="#":
                                    print(hex(opt[9:len(opt)]))
                                    nummbers.append(int(opt[9:len(opt)]))
                                else:
                                    print(opt[9:len(opt)])
                                    register.append(opt[9:len(opt)])
                                    call_to_func.append(addr)   
                                    H.append("+"+opt[9:len(opt)])
                                    
                            if (instruct=="subs")|(instruct=="sub"):
                                if opt[4]=="r":
                                    print(opt[4:6])
                                    register.append(opt[4:6])
                                    call_to_func.append(addr)
                                    del H[0]
                                    H.append("+"+opt[4:6])
                                if opt[8]=="#":
                                    print((-1)*int(opt[9:len(opt)]))
                                    nummbers.append((-1)*int(opt[9:len(opt)]))
                                else:
                                    print(opt[9:len(opt)])
                                    register.append(opt[9:len(opt)])
                                    call_to_func.append(addr)   
                                    H.append("-"+opt[9:len(opt)])
                        else:
                            del register[0]
                            del H[0]
                            for d in current_def.data:
                                nummbers.append(d)
                else: 
                    for h in current_def.tags:
                        Func.append(register[0]+' is function:'+str(hex(h.function))+" 's return value")
                        del register[0]
            else:
                del register[0]
                del call_to_func[0]
                register.append(stack_insn.insn.op_str[0 : stack_insn.insn.op_str.find(',')])
                call_to_func.append(stack_insn.insn.address)
            lenth=len(register)

    for h in H:
        print(h)
    print(sum(nummbers))
    for f in Func:
        print(f)

if __name__ == '__main__':
    main()