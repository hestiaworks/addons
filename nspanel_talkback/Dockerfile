# Pinned by digest, not :latest, for the same reason the updater is: the
# add-on store rebuilds this image on every install, so an unpinned base
# means two users can install the same add-on version and get different
# images. The digest is an OCI index covering amd64 and arm64.
# Tag at time of pinning: 3.24-2026.08.0
FROM ghcr.io/home-assistant/base:3.24-2026.08.0@sha256:93ef607824e3f27e868f11b10938283a98bf880ed57bcf8eaa81c6c2d521f6f5

# py3-cryptography supplies AES-128-CFB, which Baichuan uses for every
# message after login and which Python's standard library has no answer for.
# It is an apk package in alpine v3.24/main, so no pip stage and no compiler.
RUN apk add --no-cache python3 py3-cryptography

ARG BUILD_VERSION
ENV NSPANEL_TALKBACK_VERSION=${BUILD_VERSION}

COPY run.sh /run.sh
COPY adpcm.py /app/adpcm.py
COPY baichuan.py /app/baichuan.py
COPY client.py /app/client.py
COPY server.py /app/server.py
RUN chmod a+x /run.sh

CMD ["/run.sh"]
