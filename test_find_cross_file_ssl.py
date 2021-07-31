import os
import time
import sys
# first traverse the elf to find the imported libraries, then store the imported functions in the import_func_list, then traverse all the exported functions and match these with the imported functions and store this infomation in the dictionary

func_to_func_list = [] # store the func to func between different libraries
funclib_to_funclib_list = [] # store the lib to lib 

SSL_API_List = []
func_list = []
import_func_name = ""
ida_script = "F:/git_project/SSL_API_Misuse_Detection/find_func_ref_in_lib.py"


def find_lib_and_import_funcs(file_name, path):
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
            print(lib_name)
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
                import_func = line[line.rfind(" ") + 1 : ]
                import_func_list.append(import_func)
    return import_func_list, lib_list

def match_import_and_export_func(lib_list, import_func_list):
    lib_func_dir = {}
    for lib_name in lib_list:
        lib_name_full = os.popen("find ./ -name " + lib_name).read()
        sys_table = os.popen("objdump -tT " + lib_name_full).read()
        export_func_list = []
        while sys_table.find("\n") >= 0:
            line = sys_table[ : sys_table.find("\n")]
            sys_table = sys_table[sys_table.find("\n") + 1 : ]
            if line.find(" g ") >= 0:
                if line.find(" Base ") >= 0:
                    if line.find(" .text") >= 0:
                        # export function in library
                        export_func = line[line.rfind(" ") + 1: ]
                        if import_func_list.count(export_func) > 0:
                            export_func_list.append(export_func)
        if len(export_func_list) > 0:
            lib_func_dir[lib_name] = list(set(export_func_list))
    return lib_func_dir

def main():
    file_name = "test"
    path = os.popen("find ./ -name " + file_name).read()
    path = path[1:]
    while path.find("\n"):
        file_name = path[:path.find("\n")]
        if file_name.find("test_ssl") >= 0:
            break
        path = path[path.find("\n") + 2:]
    file_path = os.getcwd()
    import_func_list, lib_list = find_lib_and_import_funcs(file_name[1:], file_path)
    lib_func_dir = match_import_and_export_func(lib_list, import_func_list)
    for filenames in lib_func_dir:
        for filename in filenames:
            file_path = os.getcwd()
            func_list = []
            for func_name in lib_func_dir.keys():
                command = "D:/camera/ida/IDA7.0/ida.exe -A -S\"" + ida_script + " /"+ binary_file + "\" " + path + binary_file
                os.system(command)
                find_func_ref_to_ssl_func(func_name)
                if func_list:
                    imfunc = []
                    for imfunc_name in func_list:
                        imfunc.append(imfunc_name)
                    func_to_func_list.append({import_func_name:imfunc})
            import_func_list, lib_list = find_lib_and_import_funcs(file_name[1:], file_path)
            import_func_list = func_list
            # lib_func_dir {libcurl.so:[test_api]}
            so_function = []
            for key in lib_func_dir.keys():
                for func_to_func in func_to_func_list:
                    if func_to_func_list.get(func_to_func) == lib_func_dir.get(key)
                        so_function.append(key)
            funclib_to_funclib_list.append({filename : so_function})
        lib_func_dir.update(match_import_and_export_func(lib_list, import_func_list))

if __name__ == '__main__':
    main()


