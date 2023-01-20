import angr 
import angr.analyses.reaching_definitions.dep_graph as dep_graph

path = "XXX"
target_func_addr = address
call_to_memcpy = address 
register = “XXX”


print("Creating angr Project")
project = angr.Project(path)

bin_cfg = project.analyses.CFG(resolve_indirect_jumps=True, cross_references=True, force_complete_scan=False, normalize=True, symbols=True)

target_func = bin_cfg.functions.get_by_addr(target_func_addr)
rd = project.analyses.ReachingDefinitions(subject=target_func, func_graph=target_func.graph, cc = target_func.calling_convention, observation_points= [("insn", call_to_memcpy, 0)], dep_graph = dep_graph.DepGraph())
reg_vex_offset = project.arch.registers.get(register, None)[0]
reg_defs = rd.one_result.register_definitions.get_objects_by_offset(reg_vex_offset)
print(reg_defs)