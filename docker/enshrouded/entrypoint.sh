#!/usr/bin/env bash
set -euo pipefail

STEAMCMD_DIR="/opt/steamcmd"
SERVER_DIR="/data/server"
SAVE_DIR_DEFAULT="${SAVE_DIR:-/data/savegame}"
LOG_DIR="/data/logs"

export WINEDEBUG=-all
export WINEPREFIX=/data/wine
export DISPLAY=:1
export QEMU_LD_PREFIX=/
export BOX64_LD_LIBRARY_PATH=/lib:/lib/i386-linux-gnu:/usr/lib:/usr/lib/i386-linux-gnu

mkdir -p "$STEAMCMD_DIR" "$SERVER_DIR" "$SAVE_DIR_DEFAULT" "$LOG_DIR"
chown -R "$(id -u)":"$(id -g)" /data || true

update_server() {
  echo "[enshrouded] updating via steamcmd"
  "$STEAMCMD_DIR/steamcmd.sh" +@sSteamCmdForcePlatformType windows +force_install_dir "$SERVER_DIR" +login anonymous +app_update 2278520 validate +quit
}

generate_config() {
  local cfg="$SERVER_DIR/server_config.txt"
  if [ -f "$cfg" ]; then
    return
  fi
  cat >"$cfg" <<CONFIG
SERVER_NAME=${SERVER_NAME:-Enshrouded Server}
SERVER_PASSWORD=${SERVER_PASSWORD:-}
MAX_PLAYERS=${MAX_PLAYERS:-16}
GAME_PORT=${GAME_PORT:-15636}
QUERY_PORT=${QUERY_PORT:-15637}
SAVE_DIR=${SAVE_DIR:-/data/savegame}
CONFIG
}

run_server() {
  local bin="$SERVER_DIR/enshrouded_server.exe"
  if [ ! -f "$bin" ]; then
    echo "[enshrouded] server binary missing at $bin"
  fi
  local args=("$bin" "-log" "-SteamServerGamePort=${GAME_PORT:-15636}" "-SteamServerQueryPort=${QUERY_PORT:-15637}" "-ServerName=${SERVER_NAME:-Enshrouded Server}" "-SaveDirectory=${SAVE_DIR:-/data/savegame}" "-MaxPlayers=${MAX_PLAYERS:-16}")
  if [ -n "${SERVER_PASSWORD:-}" ]; then
    args+=("-Password=${SERVER_PASSWORD}")
  fi
  echo "[enshrouded] launching server via wine"
  exec wine "${args[@]}"
}

if [ "${UPDATE_ON_START:-true}" = "true" ]; then
  update_server
fi

generate_config
run_server
