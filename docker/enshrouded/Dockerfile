FROM debian:bookworm-slim

ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      wget \
      tzdata \
      xz-utils \
      libfontconfig1 \
      libfreetype6 \
      libnss3 \
      libcurl4 \
      libkrb5-3 \
      libtcmalloc-minimal4 \
      libdbus-1-3 \
      libbz2-1.0 \
      libx11-6 \
      libxext6 \
      libxrandr2 \
      gnupg \
      software-properties-common \
      cabextract \
      unzip \
      procps \
      iproute2 \
      tini \
      file \
    && if [ "$TARGETARCH" = "amd64" ]; then \
         apt-get install -y --no-install-recommends \
           lib32gcc-s1 \
           lib32stdc++6 \
           libcurl4:i386 \
           libkrb5-3:i386 \
           libtcmalloc-minimal4:i386 \
           libdbus-1-3:i386 \
           wine64 \
           wine32; \
       else \
        apt-get install -y --no-install-recommends \
          wine64 \
          libc6:i386 \
          libstdc++6:i386 \
          libgcc-s1:i386 \
          libcurl4:i386 \
          libkrb5-3:i386 \
          libtcmalloc-minimal4:i386 \
          libdbus-1-3:i386 \
            libbz2-1.0:i386 \
            libx11-6:i386 \
            libxext6:i386 \
            libxrandr2:i386 \
            libnss3:i386 \
            libtinfo6:i386 \
            zlib1g:i386 \
            libcapstone4:i386 \
            libnuma1:i386 \
            liburing2:i386 \
            libasound2:i386 \
            qemu-user || true; \
         apt-get install -y --no-install-recommends box64 || echo "box64 install failed; arm64 remains experimental"; \
       fi \
    && rm -rf /var/lib/apt/lists/*

# SteamCMD
RUN mkdir -p /opt/steamcmd \
    && cd /opt/steamcmd \
    && curl -sqL "https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz" | tar -xz \
    && chmod +x /opt/steamcmd/steamcmd.sh

RUN useradd -m -d /home/steam -s /bin/bash steam \
    && mkdir -p /data \
    && chown -R steam:steam /data /opt/steamcmd

USER steam
WORKDIR /data
ENV GAME_PORT=15636 QUERY_PORT=15637 SAVE_DIR=/data/savegame UPDATE_ON_START=true TZ=Etc/UTC

COPY --chmod=755 entrypoint.sh /entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --retries=5 CMD bash -c "pgrep -f enshrouded_server || exit 1"

EXPOSE 15636/tcp 15636/udp 15637/tcp 15637/udp

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
