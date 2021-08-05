import os
import time
import sys
# first traverse the elf to find the imported libraries, then store the imported functions in the import_func_list, then traverse all the exported functions and match these with the imported functions and store this infomation in the dictionary

SSL_API_List = []
func_list = []
import_func_name = ""
ida_script = "F:/git_project/SSL_API_Misuse_Detection/find_func_ref_in_lib.py"

lib_to_lib_list = [] # 定义全局变量用来存储函数4的结果[{a:[b,c,d]}]
all_lib_list = [] # 所有需要被分析的lib文件
export_func_list = [] # 所有库函数的export函数
func_to_func_list = [] # 函数5的返回值
func_to_func_list_in_one_file = [] # 函数6的返回值

# 定义全局变量来存储函数5的结果
# 函数1:遍历elf找到所有的lib 参数文件名和路径find_lib_and_import_funcs
# 函数2:遍历elf找到所有的import的函数 参数文件名和路径find_lib_and_import_funcs
# 函数3:遍历elf找到所有的export的函数 参数文件名和路径
# 函数4:找到单个文件内的import函数和export函数的对应关系
# 函数5:找到所有lib之间的调用关系 find_lib_and_import_funcs
# 函数6：找到import函数对应到哪个lib（这个用list存，第一个数据是import的文件名，第二个数据是import的函数名，第三个数据是export的文件名，第四个数据是export的函数名， 第五个参数是在export文件中，export函数最终调用的其他库的导出函数，如果不是SSL API会设置为空，如果是SSL API会填写SSL API） 参数是前继lib文件名，当前分析lib文件名，前继节点的所有import函数，当前lib的所有export函数，
# 用一个list存储需要分析的文件名
# 函数7:去除所有和ssl无关的库调用，参数是func_to_func_list, 首先遍历list找到所有第五个参数是sslAPI的list，然后把带分析的函数名添加到list中

#lib_list存储的是当前文件调用的所有lib
file_name = "test"
file_path = os.getcwd()
all_lib_list.append(file_name)
return_list = []

def remove_no_ssl(func_list):
    if len(func_list) > 0:
        if func_list[0] == 1:
            func_list = []
            for func_to_func in func_to_func_list:
                if func_to_func[4] == "TLSv1_2_client_method":
                    func_list.append([func_to_func[0], func_to_func[1]])
                    return_list.append(func_to_func)
        if len(func_list) > 0:
            new_func_list = []
            for func in func_list:
                for func_to_func in func_to_func_list:
                    if func_to_func[1] == []:
                        return_list.append(func_to_func)
                    elif func_to_func[2] == func[0] and func_to_func[3] == func[1]:
                        return_list.append(func_to_func)
                        new_func_list.append([func_to_func[0], func_to_func[1]])
            remove_no_ssl(new_func_list)
    return return_list

def match_import_and_export_func_in_one_file():
    # 通过IDA分析确定
    # return [['test', '', 'libtest.so', 'no_ssl_api', ''], ['test', '', 'libtest_1.so', 'no_ssl_api_1', ''], ['libtest.so', 'no_ssl_api', 'libtest_so.so', 'ssl_api', ''], ['libtest_1.so', 'no_ssl_api_1', 'libtest_so_1.so', 'ssl_api_1', 'TLSv1_2_client_method']]
    ida_script = "/Users/liukaizheng/Desktop/test_cross_file/SSL_API_Misuse_Detection-main/find_func_ref_in_lib.py"

    for file in all_lib_list:
        print(file)
        if file == "test":
            continue
        txt_file = open("file_name.txt", "w")
        txt_file.write(file)
        txt_file.write("\r\n")
        for export_fun in export_func_list:
            if export_fun.get(file, -1) != -1:
                txt_file.write(str(export_fun.get(file)))
        txt_file.close()
        file_name = os.popen("find ./ -name " + file).read()
        path = os.getcwd()
        file_name = file_name[2:file_name.rfind("\n")]
        command = "/Applications/IDA\\ Pro\\ 7.0/ida.app/Contents/MacOS/ida64 -S\"" + ida_script + " /" + file + "\" " + path + file_name
        os.system(command)

    # if file == "test_files/test":
    #     # 文件名、导出函数、导入函数
    #     return [[file], [], ["no_ssl_api", "no_ssl_api_1"]]
    # elif file == "libtest.so":
    #     return [[file], ["no_ssl_api"], ["ssl_api"]]
    # elif file == "libtest_1.so":
    #     return [[file], ["no_ssl_api_1"], ["ssl_api_1"]]
    # elif file == "libtest_so.so":
    #     return [[file], ["ssl_api"], ["TLSv1_2_client_method"]]
    # elif file == "libtest_so_1.so":
    #     return [[file], ["ssl_api"], ["TLSv1_2_client_method"]]

def match_import_func_and_export_func_between_different_libs(import_file, export_file, import_func_list, export_func_list):
    match_import_export = []
    for import_func in import_func_list:
        for export_func in export_func_list:
            if import_func == export_func:
                #if export_func == "ssl_api_1":
                #    match_import_export.append([import_file, import_func, export_file, export_func, "TLSv1_2_client_method"])
                #else:
                match_import_export.append([import_file, import_func, export_file, export_func, ""])

    return match_import_export

def find_export_func(file_name, path):
    lib_name_full = os.popen("find ./ -name " + file_name).read()
    sys_table = os.popen("objdump -tT " + lib_name_full).read()
    export_func_list_tmp = []
    while sys_table.find("\n") >= 0:
        line = sys_table[ : sys_table.find("\n")]
        sys_table = sys_table[sys_table.find("\n") + 1 : ]
        if line.find(" g ") >= 0:
            if line.find(" Base ") >= 0:
                if line.find(" .text") >= 0:
                    # export function in library
                    export_func = line[line.rfind(" ") + 1: ]
                    if import_func_list.count(export_func) > 0:
                        export_func_list_tmp.append(export_func)
    return export_func_list_tmp

def find_lib_and_import_funcs(file_name, path):
    file_name = os.popen("find ./ -name " + file_name).read()
    file_name = file_name[3:file_name.rfind("\n")]
    lib_list = []
    elf_header = os.popen("readelf -a " + os.path.join(path, file_name)).read()
    if elf_header.find("libssl"):
        last_shared_lib = elf_header.rfind("Shared library")
        start_shared_lib = elf_header.find("Shared library")
        last_pos = elf_header.find("\n", last_shared_lib)
        lib_section = elf_header[start_shared_lib : last_pos]
        lib_name_start = lib_section.find("[")
        while lib_name_start >= 0:
            lib_name_start = lib_name_start + 1
            lib_name_last = lib_section.find("]")
            lib_name = lib_section[lib_name_start : lib_name_last]
            lib_section = lib_section[lib_name_last + 1 : ]
            lib_name_start = lib_section.find("[")
            # print(lib_name)
            # delete standard libraries
            if lib_name.find("libssl.so") < 0 and lib_name.find("libcrypto.so") < 0 and lib_name.find("libz.so") and lib_name.find("libgcc") and lib_name.find("libc.so") and lib_name.find("libm.so"):
                lib_list.append(lib_name)
        # store the imported functions in the elf header
        import_func_list = []
        sys_table = os.popen("objdump -tT " + os.path.join(path, file_name)).read()
        while sys_table.find("\n") >= 0:
            line = sys_table[:sys_table.find("\n")]
            sys_table = sys_table[sys_table.find("\n") + 1:]
            # if line.find(" D ") >= 0:
            #     if line.find(" w ") >= 0:
            if line.find("*UND*") >= 0:
                # print(line)
                import_func = line[line.rfind(" ") + 1 : ]
                import_func_list.append(import_func)
    import_func_list = list(set(import_func_list))
    return import_func_list, lib_list

def match_import_and_export_func(lib_list, import_func_list):
    lib_func_dir = {}
    for lib_name in lib_list:
        lib_name_full = os.popen("find ./ -name " + lib_name).read()
        sys_table = os.popen("objdump -tT " + lib_name_full).read()
        export_func_list_tmp = []
        while sys_table.find("\n") >= 0:
            line = sys_table[ : sys_table.find("\n")]
            sys_table = sys_table[sys_table.find("\n") + 1 : ]
            if line.find(" g ") >= 0:
                if line.find(" Base ") >= 0:
                    if line.find(" .text") >= 0:
                        # export function in library
                        export_func = line[line.rfind(" ") + 1: ]
                        if import_func_list.count(export_func) > 0:
                            export_func_list_tmp.append(export_func)
        if len(export_func_list_tmp) > 0:
            lib_func_dir[lib_name] = list(set(export_func_list_tmp))
    return lib_func_dir

export_func_list = []

for file in all_lib_list:
    print(file)
    import_func_list, lib_list = find_lib_and_import_funcs(file, file_path)
    # export_func_list = find_export_func(file, file_path)
    func_list_dir = []
    func_list_dir.append({file : import_func_list})
    # func_to_func_list_in_one_file.append({file: match_import_and_export_func_in_one_file(import_func_list, export_func_list)})
    lib_to_lib_list.append({file : lib_list})
    all_lib_list.extend(lib_list)
    continue_loop = True
    for lib_to_lib in lib_to_lib_list:
        if lib_to_lib.get(file) != None:
            continue_loop = False
    if continue_loop == True:
        continue
    for lib_to_lib in lib_to_lib_list:
        if lib_to_lib.get(file):
            for lib in lib_to_lib.get(file):
                export_func_list.append({lib:find_export_func(lib, file_path)})
    for lib_to_lib in lib_to_lib_list:
        if lib_to_lib.get(file):
            for lib in lib_to_lib.get(file):
                for export_func_dir in export_func_list:
                    if export_func_dir.get(lib):
                        func_to_func_list = func_to_func_list + match_import_func_and_export_func_between_different_libs(file, lib, import_func_list, export_func_dir.get(lib))
                        # print(file, lib)
index = 0
for index in range(0, len(func_to_func_list)):
    if func_to_func_list[index][0].find(".so") < 0:
        func_to_func_list[index][1] = ""
index = 0
for index in range(0, len(func_to_func_list)):
    func_to_func_list[index][3] = "." + func_to_func_list[index][3]

txt_file = open("func_to_func_list.txt", "w")
txt_file.write(str(func_to_func_list))
txt_file.close()

func_to_func_list = match_import_and_export_func_in_one_file()

func_to_func_list = remove_no_ssl([1])
print(end)
# def main():
#     file_name = "test"
#     file_name = os.popen("find ./ -name " + file_name).read()
#     file_name = file_name[3:file_name.rfind("\n")]
#     # while path.find("\n"):
#     #     file_name = path[:path.find("\n")]
#     #     if file_name == "test":
#     #         break
#     #     path = path[path.find("\n") + 2:]
#     file_path = os.getcwd()
#     import_func_list, lib_list = find_lib_and_import_funcs(file_name, file_path)
#     lib_func_dir = match_import_and_export_func(lib_list, import_func_list)
#     filename_list = list(lib_func_dir.keys())
#     index = 0
#     filename = file_name
#     change_filename = False
#     for lib_name in lib_list:
#         if change_filename == True:
#             filename_old = filename
#     while index < len(filename_list):
#         filename_old = filename
#         filename = filename_list[index]
#         file_path = os.getcwd()
#         func_list = []
#         for func_name in lib_func_dir.get(filename):
#             # command = "D:/camera/ida/IDA7.0/ida.exe -A -S\"" + ida_script + " /"+ binary_file + "\" " + path + binary_file
#             # os.system(command)
#             # find_func_ref_to_ssl_func(func_name)
#             if filename == "libtest.so":
#                 func_list = ["ssl_api"]
#             elif filename == "libtest_1.so":
#                 func_list = ["ssl_api_1"]
#             if func_list:
#                 imfunc = []
#                 for imfunc_name in func_list:
#                     imfunc.append(imfunc_name)
#                 func_to_func_list.append({func_name:imfunc})
#                 if lib_func_dir.get(filename_old):
#                     index = 0
#                     for index in range(0, len(funclib_to_funclib_list)):
#                         for key in funclib_to_funclib_list[index].keys():
#                             if key == filename_old:
#                                 funclib_to_funclib_list[index] = {filename_old : funclib_to_funclib_list[index].get(filename_old).append(filename)}
#                     # funclib_to_funclib_list.update(lib_func_dir.get(filename_old).append(filename))
#                 else:
#                     funclib_to_funclib_list.append({filename_old : [filename]})
#         file_name = filename
#         file_name = os.popen("find ./ -name " + file_name).read()
#         file_name = file_name[3:]
#         import_func_list, lib_list = find_lib_and_import_funcs(file_name, file_path)
#         import_func_list = func_list
#         # lib_func_dir {libcurl.so:[test_api]}
#         so_function = []
#         for key in lib_func_dir.keys():
#             for func_to_func in func_to_func_list:
#                 for lib_func in lib_func_dir.get(key):
#                     for key_func in func_to_func.keys():
#                         if key_func == lib_func:
#                             so_function.append(key)
#         # funclib_to_funclib_list.append({filename_old : so_function})
#         lib_func_dir.update(match_import_and_export_func(lib_list, import_func_list))
#         filename_list = list(lib_func_dir.keys())
#         index = index + 1

# if __name__ == '__main__':
#     main()