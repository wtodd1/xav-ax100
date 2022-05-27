
import argparse
import hashlib
import os
import re
import struct
import sys
import zipfile

from Crypto.Cipher import AES

from common import *

parser = argparse.ArgumentParser(description='Extract files from XAV-AX100_v10207')
parser.add_argument('input')
parser.add_argument('output')
args = parser.parse_args()

def compute_sha256(file):
    with open(file, 'rb') as f:
        hash = hashlib.sha256()
        chunk = f.read(8192)
        while chunk:
            hash.update(chunk)
            chunk = f.read(8192)
    
    return hash.hexdigest()

if compute_sha256(args.input) != 'd7e5c6b6b903347aa206c949283064d8700f16385a4f351a3bc0a2dc9d899d05':
    print('ERROR: Wrong firmware image. Must be XAV-AX100_v10207.zip')
    sys.exit(1)

zip = zipfile.ZipFile(args.input)
pack = zip.read('update/CUST_PACK.BIN')
isp = get_isp_from_pack(pack)
if isp == None:
    print('ERROR: Failed to extract CUST_UPDT.BIN')
    sys.exit(1)

# make output directory
os.makedirs(args.output, exist_ok=True)

# write script file
with open('{}/init'.format(args.output), 'wb+') as f:
    image = get_image_from_isp(isp)
    if image == None:
        print('ERROR: Failed to extract init script image')
        sys.exit(1)

    script = get_script_from_image(image)
    if script == None:
        print('ERROR: Failed to extract init script')
        sys.exit(1)
    
    f.write(script)

key2 = None
# write second stage script
with open('{}/update'.format(args.output), 'wb+') as f:
    key = get_decryption_key(isp)
    data = isp[0x57ed800:0x57ed800+0x10400]
    data = AES.new(key, AES.MODE_CBC, b'\0' * 16).decrypt(data)

    script = get_script_from_image(data)
    if script == None:
        print('ERROR: Failed to extract update script')
        sys.exit(1)

    f.write(script)

    script = script.decode('utf-8')
    
    # extract 2nd decryption key
    key2 = struct.pack('<IIII',
        int(re.search('mw\.l \$\{isp_key_addr0\} (0x[a-f0-9]*)', script)[1], 16),
        int(re.search('mw\.l \$\{isp_key_addr1\} (0x[a-f0-9]*)', script)[1], 16),
        int(re.search('mw\.l \$\{isp_key_addr2\} (0x[a-f0-9]*)', script)[1], 16),
        int(re.search('mw\.l \$\{isp_key_addr3\} (0x[a-f0-9]*)', script)[1], 16))

if key2 == None:
    print('ERROR: Failed to derive 2nd decryption key')
    sys.exit(1)

def decrypt_region(isp, key, offset, length):
    out = bytearray()
    pos = 0
    while pos < length:
        chunk = length - pos
        if chunk > 0x100000:
            chunk = 0x100000
        data = isp[offset+pos:offset+pos+chunk]
        out += AES.new(key, AES.MODE_CBC, b'\0' * 16).decrypt(data)
        pos += chunk
    
    return out

regions = [
    ('uboot2', 0x4000, 0xd3000),
    ('ecos', 0xd7000, 0x3C0800),
    ('kernel', 0x497800, 0x2DD800),
    ('rootfs', 0x775000, 0x3B8000),
    ('spsdk', 0xb2d000, 0x2083000),
    ('spapp', 0x2bb0000, 0x206E000),
    ('pq', 0x4c1e000, 0xf000),
    ('logo', 0x4c2d000, 0x177400),
    ('tcon', 0x4da4400, 0x3c00),
    ('iop_car', 0x4da8000, 0x2c00),
    ('runtime_cfg', 0x4daac00, 0xc00),
    ('vi', 0x4dab800, 0x400),
    ('isp_logo', 0x4dabc00, 0x465400),
    ('pat_logo', 0x5211000, 0x1DC400),
    ('version_info', 0x57ed400, 0x400),
]

for r in regions:
    with open('{}/{}'.format(args.output, r[0]), 'wb+') as f:
        data = decrypt_region(isp, key2, r[1], r[2])
        f.write(data)
