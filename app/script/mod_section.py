import lief
from Crypto.Cipher import ChaCha20
import sys
def main(ifname:str, ofname:str):
    elf = lief.ELF.parse(ifname)
    rostart = -1
    roend = -1
    for sym in elf.symbols:
        if sym.name == "__rodata_region_start":
            rostart = sym.value
        if sym.name == "__rodata_region_end":
            roend = sym.value

    for sec in elf.sections:
        if sec.virtual_address == rostart:
            rostart = sec.offset
        if sec.virtual_address + sec.size == roend:
            roend = sec.offset + sec.size
    
    
    print(f"ro start: {hex(rostart)}")
    print(f"ro end: {hex(roend)}")
    
    for idx, seg in enumerate(elf.segments):
        if seg.file_offset <= rostart  and  roend <= seg.file_offset + len(seg.content):
            seg.flags |= seg.FLAGS.W
    elf.write(ofname)
    
    key = 'やりますねやりますね\x00\x00'.encode()
    cipher = ChaCha20.new(key=key, nonce=b"\x00" * 12)

    data = b""
    with open(ofname, "rb") as fp:
        data = fp.read()
    pt = data[rostart:roend]
    print(f"pt: {pt[:8].hex()}")
    ct = cipher.encrypt(pt)
    print(f"ct: {ct[:8].hex()}")
    
    data = data[:rostart] + ct + data[roend:]
    print(f"data size: {hex(roend - rostart)}")
    
    with open(ofname, "wb") as fp:
        fp.write(data)
    print(f"success generate {ofname}")
    

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(sys.argv)
        print(f'usage: {sys.argv[0]} <original elf> <output elf>')
        exit(-1)
    main(sys.argv[1], sys.argv[2])