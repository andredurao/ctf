FROM ubuntu

RUN apt update

RUN apt install -y gdb binutils radare2 git make gcc pkg-config

RUN r2pm init

RUN r2pm -i r2dec
