# SAMBA: Detecting SSL/TLS API Misuses in IoT Binary Applications

## Demos
Here is a example of analyzing the SSL/TLS API misuse in the IoT binary applications

### Intra-binary analysis

1. load the target binary with IDA Pro

![image](https://github.com/kzLiu2017/SAMBA/blob/main/load_binary.jpg)

2. Run the API call sequence analysis

![image](https://github.com/kzLiu2017/SAMBA/blob/main/run_script.jpg)

![image](https://github.com/kzLiu2017/SAMBA/blob/main/select_script.jpg)

3. SSL_get_peer_certificate and SSL_get_verify_result are used, so perform further return value analysis with "2_SSL_API_Misuse_Detection_SSL_version openssl-v2.py"


### Inter-binary analysis (conducted on a macOS laptop)

1. Uncompressing the firmware

2. configure all the python scripts in inter-bianry folder with correct pathes and set the value of file_name in test_find_cross_file_ssl_bdg_only.py to the target binary (i.e., relayd in the example firmware).

3. run the inter-binary analysis
```shell
  python3 test_find_cross_file_ssl_bdg_only.py
```
