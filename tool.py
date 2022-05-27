
import argparse
import hashlib
import os
import struct
import sys
import time
import zlib
from Crypto.Cipher import AES

from common import *

def cmd_extract_script(args):
    data = b''
    with open(args.input, 'rb') as f:
        data = f.read()
    
    # get CUST_UPDT.BIN from CUST_PACK.BIN
    isp = get_isp_from_pack(data)
    if isp == None:
        print('CUST_UPDT.BIN not found')
        sys.exit(1)

    image = get_image_from_isp(isp)
    if image == None:
        print('ERROR: Failed to extract u-boot image')
        sys.exit(1)
    
    # skip 
    script = get_script_from_image(image)
    if script == None:
        print('ERROR: Failed to extract script from u-boot image')
        sys.exit(1)

    with open(args.output, 'wb+') as f:
        f.write(script)

def cmd_extract(args):

    data = b''
    with open(args.input, 'rb') as f:
        data = f.read()

    header_fmt = '<6sIHII44x64s64s'
    header_len = struct.calcsize(header_fmt)
    header = struct.unpack(header_fmt, data[0:header_len])

    token = header[0]
    if token != b'GEMINI':
        print('Invalid input file')
        sys.exit(1)

    total_size = header[1]
    if total_size != len(data):
        print('WARNING: Wrong size (expected {}, was {})'.format(total_size, len(data)))

    pack_header_offset = header[3]
    pack_header_len = header[4]
    cust_ver = header[5].decode('utf-8').rstrip('\0')
    sdk_ver = header[6].decode('utf-8').rstrip('\0')

    file_header_fmt = '<24sII'
    file_header_len = struct.calcsize(file_header_fmt)
    file_count = pack_header_len // file_header_len

    os.makedirs(args.output, exist_ok=True)

    with open('{}/metadata'.format(args.output), 'w+') as meta:
        meta.write('firmware_version: {}\n'.format(cust_ver))
        meta.write('sdk_version: {}\n'.format(sdk_ver))
        meta.write('files:\n')

        for i in range(0, file_count):
            file_header_off = pack_header_offset + (i * pack_header_len)
            file_header = struct.unpack(
                file_header_fmt, data[file_header_off:file_header_off+file_header_len])
            file_name = file_header[0].decode('utf-8').rstrip('\0')
            file_size = file_header[1]
            file_offset = file_header[2]
            file_data = data[file_offset:file_offset+file_size]

            meta.write('  - name: {}\n'.format(file_name))

            with open('{}/{}'.format(args.output, file_name), 'wb+') as out_file:
                out_file.write(file_data)

def cmd_package(args):
    script = bytearray()
    script += struct.pack('>II', 0, 0)

    with open(args.input, 'rb') as f:
        script += f.read()

    # script header
    script[0:8] = struct.pack('>II', len(script) - 8, 0)

    # u-boot image header
    header = struct.pack('>IIIIIIIBBBB32s',
        0x27051956, # magic
        0, # crc
        int(time.time()), # timestamp
        len(script), # data size
        0, # load address
        0, # entry point
        zlib.crc32(script) & 0xFFFFFFFF, # data crc
        5, # os: linux
        2, # arch: arm
        6, # type: script
        0, # compression: none
        b'XAV-AX100'.ljust(32, b'\0'), # image name
    )
    header = bytearray(header)

    # write the header crc
    header_crc = zlib.crc32(header) & 0xFFFFFFFF
    header[4:8] = struct.pack('>I', header_crc)

    isp_file = bytearray()
    isp_file += b'Gemini_ISP_image'.ljust(32, b'\0')
    isp_file += header
    isp_file += script

    if len(isp_file) > 2048:
        print('WARNING: Init script too large')

    fw_version = b'1.02.10.00'
    sdk_version = b'20.1.0.2.0.0.2.0'

    pack_header_offset = 192

    pack_file = bytearray()
    pack_file += struct.pack('<6sIHII44x64s64s',
        b'GEMINI', # token
        0, # total_size
        1, # bin_header_len_k (not used as far as I can tell)
        pack_header_offset, # pack_header_offset
        32, # pack_header_len
        fw_version.ljust(64, b'\0'), # cust_ver
        sdk_version.ljust(64, b'\0'), # sdk_ver
    )

    pack_file.ljust(pack_header_offset, b'\0')

    pack_file += struct.pack('<24sII',
        b'CUST_UPDT.BIN'.ljust(24, b'\0'),
        len(isp_file), # size
        0x400, # offset
    )

    pack_file += b'\0' * (0x400 - len(pack_file))
    pack_file += isp_file

    pack_file[6:10] = struct.pack('>I', len(pack_file))

    with open(args.output, 'wb+') as f:
        f.write(pack_file)

def cmd_set_st16_ver(args):
    data = bytearray()
    with open(args.input, 'rb') as f:
        data += f.read()
    
    magic = struct.unpack('8s', data[0x18:0x20])[0]
    if magic != b'TECHWIN6':
        print('unsupported file')
        sys.exit(1)

    version = struct.pack('16s', args.ver.encode('utf-8').ljust(16, b'\0'))
    data[0x20:0x30] = version
    data[0x30:0x40] = version

    with open(args.output, 'wb+') as f:
        f.write(data)

parser = argparse.ArgumentParser(description='Sony XAV-AX100 firmware tool')
parser.set_defaults(func=lambda args: parser.print_help())
subparsers = parser.add_subparsers(title='commands')

cmd = subparsers.add_parser('extract', help='Extract CUST_PACK.BIN file')
cmd.set_defaults(func=cmd_extract)
cmd.add_argument('input')
cmd.add_argument('output')

cmd = subparsers.add_parser('extract_script', help='Extract u-boot init script from CUST_PACK.BIN file')
cmd.set_defaults(func=cmd_extract_script)
cmd.add_argument('input')
cmd.add_argument('output')

cmd = subparsers.add_parser('package', help='Create update package from u-boot script')
cmd.set_defaults(func=cmd_package)
cmd.add_argument('input')
cmd.add_argument('output')

cmd = subparsers.add_parser('set_st16_ver', help='Change st16mcu.bin firmware version')
cmd.set_defaults(func=cmd_set_st16_ver)
cmd.add_argument('input')
cmd.add_argument('output')
cmd.add_argument('--ver', required=True)

args = parser.parse_args()
args.func(args)
