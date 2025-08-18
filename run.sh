export QEMU_MAC_ADDRESS=52:54:00:12:34:AD
qemu-system-arm -machine mps2-an385 -cpu cortex-m3 \
    -kernel /root/build/homo_final.elf \
    -netdev tap,id=mynet0,ifname=virbr0-nic,script=no \
    -net nic,macaddr=$QEMU_MAC_ADDRESS,model=lan9118,netdev=mynet0 \
    -display gtk -m 16M  -nographic -serial stdio \
    -monitor null -semihosting -semihosting-config enable=on,target=native