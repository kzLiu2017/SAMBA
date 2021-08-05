import idautils
import idc as idc
from idaapi import *
import time
import sys
from ast import literal_eval

SSL_function = {
    '''
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
    '''
    '.TLSv1_client_method': 0,
    '.TLSv1_1_client_method': 0,
    '.TLSv1_2_client_method': 0,
    '.SSLv2_client_method': 0,
    '.SSLv3_client_method': 0,
    '.SSLv23_client_method': 0,
    '.SSLv23_server_method': 0,
    '.TLSv1_method': 0,
    '.TLSv1_1_method': 0,
    '.TLSv1_2_method': 0,
    '.SSLv2_method': 0,
    '.SSLv3_method': 0,
    '.SSLv23_method': 0,
    '.SSL_CTX_new': 0,
    '.SSL_new': 0,
    '.SSL_CTX_use_certificate_chain_file': 0,
    '.SSL_CTX_use_Private_key': 0,
    '.SSL_CTX_use_certificate_file': 0,
    '.SSL_CTX_use_PrivateKey_file': 0,
    '.SSL_CTX_check_private_key': 0,
    '.SSL_CTX_set_verify': 0,
    '.SSL_CTX_load_verify_locations': 0,
    '.SSL_CTX_set_default_verify_paths': 0,
    '.SSL_CTX_set_tmp_rsa_callback': 0,
    '.SSL_set_fd': 0,
    '.SSL_set_bio': 0,
    '.SSL_set_shutdown': 0,
    '.SSL_set_options': 0,
    '.SSL_CTX_set_options': 0,
    '.SSL_connect': 0,
    '.SSL_get_peer_certificate': 0,
    '.SSL_get_verify_result': 0,
    '.SSL_get_version': 0,
    '.SSL_write': 0,
    '.SSL_read': 0,
    '.SSL_shutdown': 0,
    '.SSL_free': 0,
    '.SSL_CTX_free': 0,
    '.SSL_CTX_ctrl': 0,
    '.SSL_accept': 0,
    '.SSL_get_error': 0,
    '.SSL_library_init': 0,
    '.SSL_load_error_strings': 0,

    '_TLSv1_client_method': 0,
    '_TLSv1_1_client_method': 0,
    '_TLSv1_2_client_method': 0,
    '_SSLv2_client_method': 0,
    '_SSLv3_client_method': 0,
    '_SSLv23_client_method': 0,
    '_SSLv23_server_method': 0,
    '_TLSv1_method': 0,
    '_TLSv1_1_method': 0,
    '_TLSv1_2_method': 0,
    '_SSLv2_method': 0,
    '_SSLv3_method': 0,
    '_SSLv23_method': 0,
    '_SSL_CTX_new': 0,
    '_SSL_new': 0,
    '_SSL_CTX_use_certificate_chain_file': 0,
    '_SSL_CTX_use_Private_key': 0,
    '_SSL_CTX_use_certificate_file': 0,
    '_SSL_CTX_use_PrivateKey_file': 0,
    '_SSL_CTX_check_private_key': 0,
    '_SSL_CTX_set_verify': 0,
    '_SSL_CTX_load_verify_locations': 0,
    '_SSL_set_fd': 0,
    '_SSL_set_shutdown': 0,
    '_SSL_set_options': 0,
    '_SSL_CTX_set_options': 0,
    '_SSL_connect': 0,
    '_SSL_get_peer_certificate': 0,
    '_SSL_get_verify_result': 0,
    '_SSL_get_version': 0,
    '_SSL_write': 0,
    '_SSL_read': 0,
    '_SSL_shutdown': 0,
    '_SSL_free': 0,
    '_SSL_CTX_free': 0,
    '_SSL_CTX_ctrl': 0,
    '_SSL_accept': 0,
    '_SSL_get_error': 0,
    '_SSL_library_init': 0,
    '_SSL_load_error_strings': 0,

}

log_file = open("log.txt", "w")

txt_file = open("../func_to_func_list.txt", "r")
func_to_func_str = txt_file.readlines()
txt_file.close()
txt_file = open("../file_name.txt", "r")
read_lines = txt_file.readlines()
txt_file.close()
filename = read_lines[0][ : len(read_lines[0]) - 2]
export_func_list = read_lines[1]
func_to_func_str = func_to_func_str[0]
func_to_func_list = literal_eval(func_to_func_str)
export_func_list = literal_eval(export_func_list)

# convert string to list
# while func_to_func_str.find("[") >= 0:
#     index = func_to_func_str.find("[[")
#     if index >= 0:
#         func_to_func_str = func_to_func_str[index + 1 : ]
#     rindex = func_to_func_str.find("]")
#     index = func_to_func_str.find("[")
#     func_to_func_s = func_to_func_str[index + 1 : rindex]
#     func_to_func_str = func_to_func_str[rindex + 3 : ]
#     func_list = []
#     while func_to_func_s.find(",") >= 0:
#         index = func_to_func_s.find(",")
#         func_list.append(func_to_func_s[1 : index - 1])
#         func_to_func_s = func_to_func_s[index + 2:]
#     func_list.append(func_to_func_s[1 : len(func_to_func_s) - 1])
#     func_to_func_list.append(func_list)
# print(func_to_func_list)
import_func_list_tmp = []
import_func_list = []

log_file.write("before match_import_and_export_func\n")

def match_import_and_export_func(func_addr):
    print(func_addr)
    print(export_func_list)
    print(len(list(XrefsTo(func_addr, 0))))

    for addr in XrefsTo(func_addr, 0):
        print(hex(addr.frm), GetFunctionName(addr.frm))
        if GetFunctionName(addr.frm) in export_func_list >= 0:
            print("append", addr.frm)
            import_func_list_tmp.append(GetFunctionName(addr.frm))
        elif len(list(XrefsTo(addr.frm, 0))) == 0:
            return
        else:
            match_import_and_export_func(addr.frm)
    # import_func_list_tmp.append("no_ssl_api")
        # if SSL_function.get(func_name, -1) != -1:
        #     SSL_API_List.append({import_func_name : func_name})
        # else:
        #     func_list.append({import_func_name : func_name})
# print("import func list", import_func_list)

log_file.write("before find_func_ref_to_ssl_func\n")

bool_SSL_function = False
def find_func_ref_to_ssl_func(func_addr):
    global bool_SSL_function
    ssl_func_name = GetFunctionName(func_addr)
    # print(ssl_func_name, hex(func_addr))

    # print(ssl_func_name)
    for addr in XrefsFrom(func_addr, 0):
        # print("addr.to  ", hex(addr.to), "func_addr   ", hex(func_addr))
        # print("GetFunctionName(addr.to) ", GetFunctionName(addr.to), "ssl_func_name  ", ssl_func_name, SSL_function.has_key(GetFunctionName(addr.to)))
        if GetFunctionName(addr.to) == ssl_func_name:
            find_func_ref_to_ssl_func(addr.to)

        elif SSL_function.has_key(GetFunctionName(addr.to)) == True:
            bool_SSL_function = True

index = 0

is_last_lib = True

# print(func_to_func_list)

for index in range(0, len(func_to_func_list)):
    # print(func_to_func_list[index][0], filename)
    if func_to_func_list[index][0] == filename and func_to_func_list[index][1] != "":
        is_last_lib = False
        func_name = func_to_func_list[index][1]
        #print("before match_import_and_export_func")
        match_import_and_export_func(idc.LocByName(func_name))
        #print("import_func_list_tmp", import_func_list_tmp)
        for import_func in import_func_list_tmp:
            if import_func in export_func_list:
                import_func_list.append(import_func)
        func_to_func_list[index][1] = import_func_list
        import_func_list = []
        import_func_list_tmp = []

if is_last_lib == True:
    index = 0
    for index in range(0, len(func_to_func_list)):
        if func_to_func_list[index][2] == filename:
            # print("index", index)
            # print("func_to_func_list", func_to_func_list[index][3], hex(idc.LocByName(func_to_func_list[index][3][1:])))
            find_func_ref_to_ssl_func(idc.LocByName(func_to_func_list[index][3][1:]))
            # print(bool_SSL_function)
            if bool_SSL_function == True:
                func_to_func_list[index][4] = "SSL"
                bool_SSL_function = False

print(func_to_func_list)

# txt_file = open("../func_to_func_list.txt", "w")
# txt_file.write(str(func_to_func_list))
# txt_file.close()

# idc.Exit(0)
# txt_file.close()

# file_func.write(file_func)