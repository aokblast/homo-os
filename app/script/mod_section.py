import lief
from Crypto.Cipher import ChaCha20
import sys

def encrypt_section(ifname:str, ofname:str, sect_start:str, sect_end:str):
    elf = lief.ELF.parse(ifname)
    start_va = -1
    end_va = -1
    for sym in elf.symbols:
        if sym.name == sect_start:
            start_va = sym.value
        if sym.name == sect_end:
            end_va = sym.value

    for sec in elf.sections:
        if sec.virtual_address == start_va:
            start = sec.file_offset
        
        if sec.virtual_address + sec.size == end_va:
            end = sec.file_offset + sec.size
    
    

    print(f"start: {hex(start_va)} -> {hex(start)}")
    print(f"end:   {hex(end_va)  } -> {hex(end)}")
    
    for idx, seg in enumerate(elf.segments):
        if seg.file_offset <= start  and  end <= seg.file_offset + len(seg.content):
            seg.flags |= seg.FLAGS.W
    elf.write(ofname)
    
    key = 'やりますねやりますね\x00\x00'.encode()
    cipher = ChaCha20.new(key=key, nonce=b"\x00" * 12)

    data = b""
    with open(ofname, "rb") as fp:
        data = fp.read()
    pt = data[start:end]
    print(f"pt: {pt[:8].hex()}")
    ct = cipher.encrypt(pt)
    print(f"ct: {ct[:8].hex()}")
    
    data = data[:start] + ct + data[end:]
    print(f"data size: {hex(end - start)}")
    
    with open(ofname, "wb") as fp:
        fp.write(data)
    print(f"success generate {ofname}")
    

def main(ifname:str, ofname:str):
    '''
    encrypt rodata, datas(enclude __data_region_end)
    '''
    encrypt_section(ifname, ofname, "__rodata_region_start", "__rodata_region_end")
    encrypt_section(ifname, ofname, "__data_region_start", "__data_region_end")
    

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(sys.argv)
        print(f'usage: {sys.argv[0]} <original elf> <output elf>')
        exit(-1)
    main(sys.argv[1], sys.argv[2])