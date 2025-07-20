import lief
from Crypto.Cipher import ChaCha20

fname = "/workspaces/homo-os/build/zephyr/zephyr.elf"
elf = lief.parse(fname)
rodata:lief.ELF.Section = elf.get_section("rodata")
# ref: https://www.sco.com/developers/gabi/latest/ch4.sheader.html
SHF_WRITE = 0x1
rodata.flags  |= SHF_WRITE
key = 'やりますねやりますね\x00\x00'.encode()
cipher = ChaCha20.new(key=key)
ciphertext = cipher.encrypt(rodata.content)
rodata.content = list(ciphertext)
elf.write(fname)