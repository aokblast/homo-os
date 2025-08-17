import lief
from Crypto.Cipher import ChaCha20
import sys

def resolve_offset_from_seg(elf: lief.Binary, addr:int, sec_name:str = None)->int:
    for sec in elf.sections:
        if not (sec_name is None):
            if sec.name != sec_name:
                continue
        
        if sec.virtual_address == addr:
            return sec.file_offset
            
        if sec.virtual_address + sec.size == addr:
            return sec.file_offset + sec.size
    
    else:
        raise ValueError(f"can not find addr {hex(addr)} from {sec_name}")
        
def encrypt_section(ifname:str, ofname:str, sect_start:str, sect_end:str, sec_name:str = None):
    elf = lief.ELF.parse(ifname)
    start_va = -1
    end_va = -1
    for sym in elf.symbols:
        if sym.name == sect_start:
            start_va = sym.value
        if sym.name == sect_end:
            end_va = sym.value

    start = resolve_offset_from_seg(elf, start_va, sec_name)
    end = resolve_offset_from_seg(elf, end_va, sec_name)
    
    print(f"start: {hex(start_va)} -> {hex(start)}")
    print(f"end:   {hex(end_va)  } -> {hex(end)}")
    
    for idx, seg in enumerate(elf.segments):
        if seg.file_offset <= start and end <= seg.file_offset + len(seg.content):
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
    encrypt rodata, datas(include homo fs data), 
    '''
    encrypt_section(ifname, ofname, "__rodata_region_start", "__rodata_region_end")
    encrypt_section(ofname, ofname, "__data_start", "__data_end", "datas")
    encrypt_section(ofname, ofname, "_http_resource_desc_homo_list_start", "_http_resource_desc_homo_list_end", "http_resource_desc_homo_area")
    

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(sys.argv)
        print(f'usage: {sys.argv[0]} <original elf> <output elf>')
        exit(-1)
    main(sys.argv[1], sys.argv[2])