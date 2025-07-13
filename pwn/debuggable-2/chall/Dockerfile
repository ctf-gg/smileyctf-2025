FROM ubuntu:25.04 as base

RUN apt-get update && apt-get install -y \
    gdb python3

FROM pwn.red/jail

COPY --from=base / /srv

WORKDIR /srv/app

COPY run.py run
COPY flag.txt .
COPY script /srv/home/ubuntu/.gdbinit

RUN chmod +x run

ENV JAIL_MEM=50M JAIL_PIDS=20