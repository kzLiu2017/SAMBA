from __future__ import print_function

import ida_nalt
import idautils

nimps = ida_nalt.get_import_module_qty()

idaapi.autoWait()
result_path = os.getcwd()
result_path = result_path[:result_path.find("squashfs-root/") + 14]
import_file = open(result_path + 'import_func.txt', 'a+')
export_file = open(result_path + 'export_func.txt', 'a+')
import_file.write(GetInputFile())
import_file.write('\n')
export_file.write(GetInputFile())
export_file.write('\n')

export_list = list(idautils.Entries())
for export_func in export_list:
    if export_func[3] != "__errno_location":
        export_file.write(export_func[3])
        export_file.write(", ")
export_file.write('\n')


for i in range(nimps):
    name = ida_nalt.get_import_module_name(i)
    if not name:
        name = "<unnamed>"
    def imp_cb(ea, name, ordinal):
        if not name:
            print("%08x: ordinal #%d" % (ea, ordinal))
        else:
            if name != "__errno_location":
                import_file.write(name)
                import_file.write(", ")
        return True
    ida_nalt.enum_import_names(i, imp_cb)
import_file.write('\n')

import_file.close()
export_file.close()

idc.Exit(0)