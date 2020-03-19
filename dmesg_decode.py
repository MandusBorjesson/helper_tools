from struct import *
from collections import namedtuple
import argparse

parser = argparse.ArgumentParser(description='Decode dmesg hex dumps.',
                                 usage='python3 dmesg_decode.py --file dump.hex --start_string Booting')
parser.add_argument('--file', help='Input file to decode.')
parser.add_argument('--start_string', help='Start string to look for in log, note that the line with the start string will not be printed.')

args = parser.parse_args()

infile = args.file
if type(infile) is not str:
    parser.print_help()
    quit()

start_string = args.start_string #"Booting"
if type(start_string) is not str:
    parser.print_help()
    quit()

start_bytes = bytearray(start_string, 'utf-8')

entry = namedtuple('entry', 'ts_nsec len text_len dict_len facility flags level msg msg2')
entries = []

head_format = '<QHHHBB'
head_sz = calcsize(head_format)

with open(infile, "rb") as f:
    byte = f.read()

    # Find start string and discard it
    offset = byte.find(start_bytes)
    if offset is -1:
        quit("Start string not found, quitting...")
    offset = byte.find(0, offset)
    byte = byte[offset+1:]


    # Loop through file until we reach the end of it
    offset = 0
    while 1:
        if offset >= len(byte):
            quit()

        head = unpack(head_format, byte[offset:offset+head_sz])

        if offset + head[1] >= len(byte):
            quit()

        message = byte[ offset+head_sz : offset+head[1] ].decode("utf-8")

        message2 = message[head[2]:head[1]]
        message = message[:head[2]]

        new_entry = entry(
            head[0],
            head[1],
            head[2],
            head[3],
            head[4],
            (head[5] & 0xF8) >> 3,
            head[5] & 0x07,
            message,
            message2
            )

        print(' [%09.4f] %s %s' % (new_entry.ts_nsec/1000000000, message, (('/* %s */' % message2) if len(message2) > 4 else '')))

        offset = offset + new_entry.len

        entries.append(new_entry)
