import idautils
import idc as idc
from idaapi import *
import time

SSL_function = {
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
}


file_ssl = open("file_ssl.txt", a)
file_func = open("file_func.txt", a)

func_name = sys.argv[1]

if len(XrefsTo(idc.LocByName(func_name), 0)) != 0:
    for addr in XrefsTo(idc.LocByName(func_name), 0):
        find_func_ref_to_ssl_func(GetFunctionName(addr))
else:
    if SSL_function.get(func_na3me, -1) != -1:
        SSL_API_List.append({import_func_name : func_name})
    else:
        func_list.append({import_func_name : func_name})
file_ssl.write(SSL_API_List)
file_func.write(file_func)