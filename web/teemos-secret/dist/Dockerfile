FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    wget \
    curl \
    gnupg \
    unzip \
    firefox-esr \
    && rm -rf /var/lib/apt/lists/*

ENV GECKODRIVER_VERSION=0.36.0
RUN wget -q "https://github.com/mozilla/geckodriver/releases/download/v$GECKODRIVER_VERSION/geckodriver-v$GECKODRIVER_VERSION-linux64.tar.gz" \
    && tar -xzf "geckodriver-v$GECKODRIVER_VERSION-linux64.tar.gz" -C /usr/local/bin \
    && rm "geckodriver-v$GECKODRIVER_VERSION-linux64.tar.gz"

WORKDIR /app

RUN pip install --no-cache-dir flask selenium pillow

COPY ./flag.txt /app/flag.txt
COPY ./server.py /app/server.py

EXPOSE 8801
ENTRYPOINT [ "python", "/app/server.py" ]