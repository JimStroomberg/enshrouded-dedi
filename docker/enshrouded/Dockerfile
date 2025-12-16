FROM --platform=linux/amd64 debian:bookworm-slim

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
      lib32gcc-s1 \
      lib32stdc++6 \
      libcurl4:i386 \
      libkrb5-3:i386 \
      libtcmalloc-minimal4:i386 \
      libdbus-1-3:i386 \
      wine64 \
      wine32 \
    && rm -rf /var/lib/apt/lists/*

# SteamCMD (Linux)
RUN mkdir -p /opt/steamcmd \
    && cd /opt/steamcmd \
    && curl -sqL "https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz" | tar -xz \
    && chmod +x /opt/steamcmd/steamcmd.sh

# Windows steamcmd (fallback via wine)
RUN mkdir -p /opt/steamcmd_win \
    && cd /opt/steamcmd_win \
    && curl -sqL "https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip" -o steamcmd.zip \
    && unzip steamcmd.zip \
    && rm -f steamcmd.zip

RUN useradd -m -d /home/steam -s /bin/bash steam \
    && mkdir -p /data \
    && chown -R steam:steam /data /opt/steamcmd /opt/steamcmd_win

USER steam
WORKDIR /data
ENV GAME_PORT=15636 QUERY_PORT=15637 SAVE_DIR=/data/savegame UPDATE_ON_START=true TZ=Etc/UTC

COPY --chmod=755 entrypoint.sh /entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --retries=5 CMD bash -c "pgrep -f enshrouded_server || exit 1"

EXPOSE 15636/tcp 15636/udp 15637/tcp 15637/udp

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
