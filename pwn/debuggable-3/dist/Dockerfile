FROM ubuntu:25.04 as base

RUN apt-get update && apt-get install -y \
    gdb python3 git binutils file
RUN git clone https://github.com/hugsy/gef /app/gef

FROM pwn.red/jail

COPY --from=base / /srv

WORKDIR /srv/app

COPY run.py run
COPY flag.txt .
RUN mv flag.txt flag-$(md5sum flag.txt | awk '{print $1}').txt
COPY script /srv/home/ubuntu/.gdbinit

RUN chmod +x run

ENV JAIL_TMP_SIZE=1M JAIL_MEM=100M JAIL_PIDS=20 JAIL_SYSCALLS=ptrace JAIL_TIME=120