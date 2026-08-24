# Pinned by digest, not :latest. The add-on store rebuilds this image on every
# install, so an unpinned base means two users can install the same add-on
# version and get different images, and an upstream change can break installs
# with no commit here. The digest is an OCI index covering amd64 and arm64,
# which are the architectures config.yaml declares.
# Tag at time of pinning: 3.24-2026.08.0
FROM ghcr.io/home-assistant/base:3.24-2026.08.0@sha256:93ef607824e3f27e868f11b10938283a98bf880ed57bcf8eaa81c6c2d521f6f5

# adb installs the APK; keytool verifies its signer against the pinned
# certificate. Without either, the updater cannot verify what it installs.
RUN apk add --no-cache android-tools openjdk17-jre-headless python3

COPY run.sh /run.sh
COPY server.py /app/server.py
COPY nspanel_updater.py /app/nspanel_updater.py
RUN chmod a+x /run.sh

CMD ["/run.sh"]
