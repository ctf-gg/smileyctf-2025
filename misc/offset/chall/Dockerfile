FROM python:3.13-slim as app
COPY main.py /srv/app/run
RUN chmod +x /srv/app/run
COPY flag.txt /srv/app/
RUN python -c "import os; os.rename('/srv/app/flag.txt', f'/srv/app/flag_{os.urandom(16).hex()}.txt')"
RUN apt-get update
RUN apt-get install -y socat
ENTRYPOINT socat TCP-LISTEN:5000,fork,reuseaddr,bind=0.0.0.0 EXEC:"/srv/app/run"
