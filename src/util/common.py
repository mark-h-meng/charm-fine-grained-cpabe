import sys,json
from charm.toolbox.pairinggroup import PairingGroup


def print_byte_array(arr):
    temp_int = 0
    for var in arr:
        temp_int += 1
        if temp_int % 16 == 0:
            print('{0:02x}'.format(var))
        else:
            print('{0:02x}'.format(var), end=" ")

def ct_to_dict(ct, group):
    if not isinstance(ct, dict):
        return None
    ct_serialized = {}
    try:
        for k in ct.keys():
            item = ct[k]
            if k in ['C', 'Cpp', 'C_tilde']:
                item_serialized = group.serialize(item).decode('utf-8')
                ct_serialized.update({k : item_serialized})
            elif isinstance(item, dict):
                sub_dict = {}
                for sub_k in item:
                    sub_item = item[sub_k]
                    sub_item_ser = group.serialize(sub_item).decode('utf-8')
                    sub_dict.update({ sub_k : sub_item_ser})
                ct_serialized.update({k : sub_dict})
            else:
                ct_serialized.update({k: item})
        return ct_serialized
    except:
        print("Unexpected error:", sys.exc_info()[0])

def dict_to_ct(ct_dict, group):
    if not isinstance(ct_dict, dict):
        return None
    recovered_ct = {}
    try:
        for k in ct_dict.keys():
            item = ct_dict[k]
            if k in ['C', 'Cpp', 'C_tilde']:
                item_deserialized = group.deserialize(item.encode('utf-8'))
                recovered_ct.update({k : item_deserialized})
            elif isinstance(item, dict):
                sub_dict = {}
                for sub_k in item:
                    sub_item = item[sub_k]
                    sub_item_des = group.deserialize(sub_item.encode('utf-8'))
                    sub_dict.update({sub_k: sub_item_des})
                recovered_ct.update({k: sub_dict})
            else:
                recovered_ct.update({k : item})
        return recovered_ct
    except:
        print("Unexpected error:", sys.exc_info()[0])

def read_pt_from_file(path):
    try:
        file = open(path, 'rb')
        file_pt = file.read()
        file.close()
        return file_pt
    except IOError:
        print("Could not read file:", path)
    except:
        print("Unexpected error:", sys.exc_info()[0])

def write_pt_to_file(pt, path):
    try:
        file = open(path, 'wb')
        file.write(bytes(pt))
        file.close()
    except IOError:
        print("Could not read file:", path)
    except:
        print("Unexpected error:", sys.exc_info()[0])

def write_ct_to_file(ct_file, ct_key, path, group=PairingGroup("SS512")):
    try:
        key_ct_serialized = ct_to_dict(ct_key, group)
        key_ct_printable = json.dumps(key_ct_serialized)
        outputFileObj = open(path, 'w')
        outputFileObj.write(ct_file)
        outputFileObj.write("\n")
        outputFileObj.write(key_ct_printable)
        outputFileObj.close()
    except IOError:
        print("Could not read file:", path)
    except:
        print("Unexpected error:", sys.exc_info()[0])

def read_ct_from_file(path, group=PairingGroup("SS512")):
    try:
        file = open(path, 'r')
        file_ct = file.readline()
        key_ct = eval(file.read())
        file.close()
        key_ct_recovered = dict_to_ct(key_ct, group)
        return file_ct, key_ct_recovered
    except IOError:
        print("Could not read file:", path)
    except:
        print("Unexpected error:", sys.exc_info()[0])


