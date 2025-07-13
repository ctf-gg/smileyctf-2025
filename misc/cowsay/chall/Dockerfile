FROM debian:bookworm-slim AS app

RUN apt-get update && apt-get install -y build-essential cmake

WORKDIR /app
COPY ./extern extern
COPY ./src src
COPY ./CMakeLists.txt CMakeLists.txt
COPY ./lib.lua ./lib.lua
COPY ./flag.txt ./flag.txt
RUN cmake . && cmake --build . --config Release --target luactf
RUN mv luactf run

FROM pwn.red/jail
COPY --from=app / /srv
ENV JAIL_TMP_SIZE=65536 JAIL_MEM=20M JAIL_PIDS=10 JAIL_TIME=300