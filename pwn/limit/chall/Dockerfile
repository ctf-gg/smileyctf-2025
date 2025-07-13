FROM pwn.red/jail
COPY  --from=ubuntu:24.04@sha256:dc17125eaac86538c57da886e494a34489122fb6a3ebb6411153d742594c2ddc / /srv

RUN mkdir /srv/app

COPY ./flag.txt /srv/app/flag.txt
COPY ./limit /srv/app/run

RUN chmod a+x /srv/app/run

ENV JAIL_PORT=5000 JAIL_TIME=60
