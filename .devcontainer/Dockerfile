FROM ubuntu:22.04
RUN apt update && apt install -y gcc-arm-none-eabi cmake qemu-system-arm make gdb-multiarch file wget python3.10-venv
RUN apt install -y device-tree-compiler python3-pip 

RUN python3 -m venv venv && bash -c "source venv/bin/activate && pip3 install west pyelftools"
RUN wget https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.17.1/zephyr-sdk-0.17.1_linux-x86_64.tar.xz
RUN tar xvf zephyr-sdk-0.17.1_linux-x86_64.tar.xz
RUN cd zephyr-sdk-0.17.1 && bash setup.sh -c
RUN apt install -y git