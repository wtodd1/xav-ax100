
import hashlib
import struct
from Crypto.Cipher import AES

def get_isp_from_pack(data):
    header_fmt = '<6sIHII44x64s64s'
    header_len = struct.calcsize(header_fmt)
    header = struct.unpack(header_fmt, data[0:header_len])

    token = header[0]
    if token != b'GEMINI':
        return None

    total_size = header[1]
    if total_size != len(data):
        print('WARNING: Wrong size (expected {}, was {})'.format(total_size, len(data)))

    pack_header_offset = header[3]
    pack_header_len = header[4]

    file_header_fmt = '<24sII'
    file_header_len = struct.calcsize(file_header_fmt)
    file_count = pack_header_len // file_header_len

    for i in range(0, file_count):
        file_header_off = pack_header_offset + (i * pack_header_len)
        file_header = struct.unpack(
            file_header_fmt, data[file_header_off:file_header_off+file_header_len])
        file_name = file_header[0].decode('utf-8').rstrip('\0')
        file_size = file_header[1]
        file_offset = file_header[2]
        file_data = data[file_offset:file_offset+file_size]

        if file_name == 'CUST_UPDT.BIN':
            return file_data
            
    return None

def get_decryption_key(isp):
    return hashlib.md5(isp[0:32]).digest()

def get_image_from_isp(data):
    if len(data) < 32:
        print('ERROR: Not an isp file')
        return None

    header = struct.unpack('32s', data[0:32])[0]
    
    header_str = header.rstrip(b'\0')
    if header_str != b'Gemini_ISP_image':
        print('ERROR: Not an isp file')
        return None

    # check if it is encrypted
    encrypted = False
    scan_region = data[0x70:0x70+0x20]
    for b in scan_region:
        if b >= 0x80:
            encrypted = True

    out = data[32:]

    # decrypt if needed
    if encrypted:
        key = hashlib.md5(header).digest()
        out = AES.new(key, AES.MODE_CBC, b'\0' * 16).decrypt(out)

    # read u-boot image header
    header_fmt = '>IIIIIIIBBBB32s'
    header_len = struct.calcsize(header_fmt)
    header = struct.unpack(header_fmt, out[0:header_len])
    if header[0] != 0x27051956:
        print('ERROR: Not a u-boot image')
        return None

    image_data_size = header[3]
    out = out[0:header_len + image_data_size]
    
    return out

def get_script_from_image(data):
    # read u-boot image header
    header_fmt = '>IIIIIIIBBBB32s'
    header_len = struct.calcsize(header_fmt)
    header = struct.unpack(header_fmt, data[0:header_len])
    if header[0] != 0x27051956:
        print('ERROR: Not a u-boot image')
        return None

    # seek past 0 terminated image size list
    sizes = []
    pos = header_len
    while True:
        size = struct.unpack('>I', data[pos:pos+4])[0]
        pos += 4
        if size != 0:
            sizes.append(size)
        else:
            break
    
    if len(sizes) != 1:
        print('ERROR: Invalid script')
        return None
    
    return data[pos:pos+sizes[0]]
