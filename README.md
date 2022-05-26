
# Notes on Sony XAV-AX100 Firmware

## References

* https://github.com/superdavex/Sony-XAV-AX100
* http://oss.sony.net/Products/Linux/Audio/XAV-AX100.html

## tool.py

This script has a number of features for working with XAV-AX100 firmware updates.

### Extracting CUST_PACK.BIN

This command extracts the files and metadata from CUST_PACK.BIN

    python tool.py extract CUST_PACK.BIN out/

### Extracting CUST_UPDT.BIN

This command extracts the u-boot script image from CUST_UPDT.BIN, which is contained
within the CUST_PACK.BIN archive.

    python tool.py extract_isp CUST_UPDT.BIN init.img

### Packaging custom u-boot script

This command packages a custom u-boot script into a CUST_PACK.BIN file. This can be used
to execute arbitrary u-boot commands during a firwmare update.

    python tool.py package script CUST_PACK.BIN

### Custom u-boot script example

Here is an example u-boot script that dumps a nand partition:

    setexpr isp_ram_addr 0x2000000

    nand read 0x$isp_ram_addr env 0x80000
    fatwrite $isp_if $isp_dev $isp_ram_addr env 0x80000

    setenv isp_all_or_update_done 0x1

The last line is important for signaling a successful firmware update. Without it, the
stereo will not leave firmware update mode.

This script can be packaged into a CUST_PACK.BIN file as follows:

    python tool.py package script CUST_PACK.BIN

Then, prepare a usb drive with the following structure:

    update/CUST_PACK.BIN
    update/st16mcu.bin

The firwmare version must be greater than the current version of the stereo. The script
uses version '1.02.10.00', since the latest version released by Sony is '1.02.09.00'.
The firmware version of st16mcu.bin must match the version in CUST_PACK.BIN. The easiest
way to do this is to obtain the st16mcu.bin for your current firmware version, then edit
the version numbers using a hex editor.

Insert the usb stick into the stereo and trigger a firmware update. After the update,
the stereo should retain the old version number. There should be a new file called env
on the usb drive that contains the contents of the env nand partition.

## Update file format

### update/CUST_PACK.BIN

This file appears to be an archive file format that contains the files needed for firmware
update. During the update, u-boot looks for a file called 'CUST_UPDT.BIN' in this archive.

#### File Header

| field              | offset  | length  | note                                   |
|--------------------|---------|---------|----------------------------------------|
| token              | 0       | 6       | hard-coded to 'GEMINI'                 |
| total_size         | 6       | 4       | size of file                           |
| bin_header_len_k   | 10      | 2       | not sure, value of 1                   |
| pack_header_offset | 12      | 4       | offset to file index                   |
| pack_header_len    | 16      | 4       | length of file index                   |
| reserved           | 20      | 44      |                                        |
| cust_ver           | 64      | 64      | firmware version, '1.02.07.00'         |
| sdk_ver            | 64      | 64      | sdk version, '20.1.0.2.0.0.2.0'        |

#### File Index

The file index contains a series of entries in the following format:

| field              | offset  | length  | note                                   |
|--------------------|---------|---------|----------------------------------------|
| name               | 0       | 24      | file name, 'CUST_UPDT.BIN'             |
| size               | 24      | 4       | file size                              |
| offset             | 28      | 4       | offset to file data                    |

The number of entries is calculated as follows:

    file_count = pack_header_len / 32

### CUST_PACK.BIN/CUST_UPDT.BIN

This file contains a u-boot script image that is sourced by u-boot during an update. The
size seems to be limited to 2048 bytes, since u-boot only loads the first 2048 bytes from
the usb drive into ram before running the script. The file format is as follows:

| field              | offset  | length  | note                                    |
|--------------------|---------|---------|-----------------------------------------|
| magic              | 0       | 32      | 'Gemini_ISP_image', padded with 0s      |
| contents           | 32      | n       | u-boot script image                     |

### update/st16mcu.bin

This appears to be the firmware for another mcu on the board. The version numbers need to
match CUST_PACK.BIN for the stereo to begin the update.

    field               offset    length    note
    version1            32        16        version, '1.02.07.00'
    version2            48        16        version, '1.02.07.00'


## U-Boot RAM Map

    region      offset     length
    HW_BUF      0x1000000  0x7400000
    ECOS_RAM2   0x8400000  0x1000000
    SP_DISPLAY  0x9400000  0x0000000
    RTCFG       0x9400000  0x0100000
    BOOT_PARAM  0x9500000  0x0100000
    SYS_LOAD    0x9600000  0x0B00000
    INITRD      0xA100000  0x5500000
    CHUNK_MEM   0xF600000  0x0A00000
