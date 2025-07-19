import lief
fname = "/workspaces/homo-os/build/zephyr/zephyr.elf"
elf = lief.parse(fname)
rodata:lief.ELF.Section = elf.get_section("rodata")
# ref: https://www.sco.com/developers/gabi/latest/ch4.sheader.html
SHF_WRITE = 0x1
rodata.flags  |= SHF_WRITE
print(len(rodata.content))
elf.write(fname)