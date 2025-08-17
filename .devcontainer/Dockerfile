FROM node:bookworm-slim
RUN apt update && apt install -y gcc-arm-none-eabi cmake qemu-system-arm make gdb-multiarch file wget python3
RUN apt install -y device-tree-compiler python3-pip ninja-build git iproute2 curl python3.11-venv
RUN python3 -m venv venv && bash -c "source venv/bin/activate && pip3 install west lief pycryptodome pyelftools"
RUN git config --global --add safe.directory /workspaces/homo-os/deps/zephyr && \
    git config --global --add safe.directory /workspaces/homo-os/deps/modules/lib/picolibc && \
    git config --global --add safe.directory /workspaces/homo-os/deps/modules/hal/cmsis