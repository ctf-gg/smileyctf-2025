FROM ubuntu:25.04 as base

FROM pwn.red/jail

COPY --from=base / /srv

WORKDIR /srv/app

COPY chal run
COPY flag.txt .

RUN chmod +x run

ENV JAIL_TIME=300