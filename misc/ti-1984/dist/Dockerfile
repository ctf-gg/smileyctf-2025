FROM mcr.microsoft.com/windows/servercore:ltsc2022

LABEL Description="Python" Vendor="Python Software Foundation" Version="3.10.0"

RUN powershell.exe -Command \
    $ErrorActionPreference = 'Stop'; \
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
    wget https://www.python.org/ftp/python/3.10.0/python-3.10.0.exe -OutFile c:\python-3.10.0.exe ; \
    Start-Process c:\python-3.10.0.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait ; \
    Remove-Item c:\python-3.10.0.exe -Force


RUN powershell.exe -Command \
    $ErrorActionPreference = 'Stop'; \
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
    wget https://curl.se/windows/dl-8.14.1_1/curl-8.14.1_1-win64-mingw.zip -OutFile c:\curl.zip ; \
    Expand-Archive c:\curl.zip -DestinationPath C:\curl ; \
    Remove-Item c:\curl.zip -Force

COPY requirements.txt /app/requirements.txt
COPY server.py /app/server.py
COPY flag.txt /app/flag.txt
COPY static /app/static/
COPY code_tmpl.py /app/code_tmpl.py
RUN move C:\curl\curl-8.14.1_1-win64-mingw\bin\curl.exe C:\app\curl.exe
WORKDIR /app
RUN ["python", "-c", "import os; os.rename('flag.txt', f'flag_{os.urandom(8).hex()}.txt')"]
RUN ["pip", "install", "-r", "requirements.txt"]
RUN net user /add chall
USER chall
EXPOSE 80
ENTRYPOINT ["python", "server.py"]