import lief
from Crypto.Cipher import ChaCha20
import sys
def main(ifname:str, ofname:str):
    elf = lief.parse(ifname)
    rodata:lief.ELF.Section = elf.get_section("rodata")
    # ref: https://www.sco.com/developers/gabi/latest/ch4.sheader.html
    SHF_WRITE = 0x1
    rodata.flags  |= SHF_WRITE
    key = 'やりますねやりますね\x00\x00'.encode()
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(rodata.content)
    rodata.content = list(ciphertext)
    elf.write(ofname)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(sys.argv)
        print(f'usage: {sys.argv[0]} <original elf> <output elf>')
        exit(-1)
    main(sys.argv[1], sys.argv[2])