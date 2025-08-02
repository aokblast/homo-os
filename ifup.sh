#!/usr/bin/env bash

export VM_IP_ADDRESS=10.211.55.1
export VM_CIDR=24

ip tuntap add dev virbr0-nic mode tap
ip addr add $VM_IP_ADDRESS/$VM_CIDR dev virbr0-nic
ip link set dev virbr0-nic up