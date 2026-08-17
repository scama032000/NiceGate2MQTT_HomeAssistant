ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:latest
FROM $BUILD_FROM

RUN apk add --no-cache python3 py3-pip
RUN pip3 install paho-mqtt --break-system-packages

WORKDIR /app

COPY main.py /app/
COPY nice_driver.py /app/

COPY run.sh /etc/services.d/nice_gate/run

RUN chmod a+x /etc/services.d/nice_gate/run