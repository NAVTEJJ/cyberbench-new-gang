h = b'\x7fVLT'
print(f'magic len={len(h)}, bytes={list(h)}')
import struct, zlib
flag = b'cyberbench{b64_header_decode_strict_vs_ignore}'
crc = zlib.crc32(flag) & 0xFFFF
payload = h + struct.pack('>H', crc) + struct.pack('>H', len(flag)) + flag
print(f'payload total len={len(payload)}')
print(f'magic[0:4]={payload[:4]!r}')
print(f'crc[4:6]={payload[4:6].hex()}')
print(f'len[6:8]={struct.unpack(">H", payload[6:8])[0]}')
print(f'flag_start=8, flag={payload[8:].decode()}')
print(f'len(flag)={len(flag)}')
