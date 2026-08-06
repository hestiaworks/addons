FROM ghcr.io/home-assistant/base:latest

RUN apk add --no-cache android-tools openjdk17-jre-headless python3

COPY run.sh /run.sh
COPY server.py /app/server.py
COPY nspanel_updater.py /app/nspanel_updater.py
RUN chmod a+x /run.sh

CMD ["/run.sh"]
