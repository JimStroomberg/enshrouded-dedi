#!/usr/bin/env bash
# Avoid exiting on non-zero steamcmd to prevent restart loops; handle errors manually.
set -uo pipefail

STEAMCMD_DIR="/opt/steamcmd"
STEAMCMD_WIN="/opt/steamcmd_win/steamcmd.exe"
SERVER_DIR="/data/server"
SAVE_DIR_DEFAULT="${SAVE_DIR:-/data/savegame}"
LOG_DIR="/data/logs"
RATE_LIMIT_FILE="/data/steam_rate_limit.lock"
STEAM_HOME="/data/steamcmd-home"
WINE_BIN="/usr/bin/wine"
STEAM_AUTH_FILE="/data/steam_auth.env"
SERVER_CONFIG_JSON="$SERVER_DIR/enshrouded_server.json"
if [ ! -x "$WINE_BIN" ] && [ -x "/usr/bin/wine64" ]; then
  WINE_BIN="/usr/bin/wine64"
fi
if [ ! -x "$WINE_BIN" ] && [ -x "/usr/lib/wine/wine64" ]; then
  WINE_BIN="/usr/lib/wine/wine64"
fi

export WINEDEBUG=-all
export WINEPREFIX=/data/wine
export DISPLAY=:1

mkdir -p "$STEAMCMD_DIR" "$SERVER_DIR" "$SAVE_DIR_DEFAULT" "$LOG_DIR" "$STEAM_HOME/.steam" "$STEAM_HOME/.local/share/Steam"
# Ensure steam user home points to persistent Steam data to keep sentry/guard tokens.
if [ ! -e /home/steam/.steam ]; then
  ln -sf "$STEAM_HOME/.steam" /home/steam/.steam
fi
if [ ! -e /home/steam/.local/share/Steam ]; then
  mkdir -p /home/steam/.local/share
  ln -sf "$STEAM_HOME/.local/share/Steam" /home/steam/.local/share/Steam
fi
export HOME="$STEAM_HOME"
# Only chown if we are running as root; unprivileged users cannot change ownership.
if [ "$(id -u)" = "0" ]; then
  chown -R "$(id -u)":"$(id -g)" /data /home/steam || true
fi

load_steam_auth() {
  if [ -f "$STEAM_AUTH_FILE" ]; then
    # shellcheck disable=SC1090
    set -a && source "$STEAM_AUTH_FILE" && set +a
  fi
}

update_server() {
  # If we recently hit a Steam rate limit, warn but still allow a retry (user may choose to wait).
  if [ -f "$RATE_LIMIT_FILE" ]; then
    last=$(cat "$RATE_LIMIT_FILE" 2>/dev/null || echo 0)
    now=$(date +%s)
    elapsed=$((now - last))
    cooldown=$((30 * 60))
    remaining=$(((cooldown - elapsed + 59) / 60))
    if [ "$elapsed" -lt "$cooldown" ]; then
      echo "[enshrouded] Steam login was rate-limited ~$((elapsed / 60)) minute(s) ago; you may want to wait ~${remaining} minute(s) before retrying, continuing anyway."
    fi
  fi

  # Determine login mode. Default to unset unless env creds are provided.
  local login_mode="${STEAM_LOGIN:-}"
  local login_chosen="${STEAM_CHOSEN:-}"
  if [ -z "$login_mode" ]; then
    if [ -n "${STEAM_USERNAME:-}" ] && [ -n "${STEAM_PASSWORD:-}" ]; then
      login_mode="user"
      login_chosen="1"
    else
      login_mode="unset"
    fi
  fi
  local login_args=("anonymous")

  if [ "$login_mode" = "anonymous" ]; then
    if [ -z "$login_chosen" ]; then
      echo "[enshrouded] Steam login mode unset; choose anonymous or user in the UI, then restart."
      tail -f /dev/null
    fi
    echo "[enshrouded] using anonymous steamcmd login (selected in UI)"
  elif [ "$login_mode" = "unset" ]; then
    echo "[enshrouded] Steam login mode unset; choose anonymous or user in the UI, then restart."
    tail -f /dev/null
  else
    if [ -z "$login_chosen" ]; then
      echo "[enshrouded] Steam login mode unset; choose anonymous or user in the UI, then restart."
      tail -f /dev/null
    fi
    if [ -z "${STEAM_USERNAME:-}" ] || [ -z "${STEAM_PASSWORD:-}" ]; then
      echo "[enshrouded] steam credentials missing; waiting (set via UI Steam Login, then restart)"
      tail -f /dev/null
    fi
    login_args=("${STEAM_USERNAME}" "${STEAM_PASSWORD}")
    if [ -n "${STEAM_GUARD_CODE:-}" ]; then
      login_args+=("${STEAM_GUARD_CODE}")
    fi
  fi
  echo "[enshrouded] updating via steamcmd"
  local log_file="$LOG_DIR/steamcmd.log"
  mkdir -p "$SERVER_DIR/steamapps/downloading" "$SERVER_DIR/steamapps/common"
  attempt=1
  fallback_win=0
  while :; do
    set +e
    "$STEAMCMD_DIR/steamcmd.sh" +@sSteamCmdForcePlatformType windows +@sSteamCmdForcePlatformBitness 64 +force_install_dir "$SERVER_DIR" +login "${login_args[@]}" +app_update 2278520 validate +quit 2>&1 | tee "$log_file"
    rc=${PIPESTATUS[0]}
    set -e

    if grep -qiE "rate limit|too many login" "$log_file"; then
      date +%s >"$RATE_LIMIT_FILE"
      echo "[enshrouded] Steam login was rate-limited; please wait ~30 minutes and try again, then restart."
      tail -f /dev/null
    fi

    if grep -qiE "two-factor code mismatch|Two-factor code mismatch" "$log_file"; then
      echo "[enshrouded] Steam Guard code mismatch; update credentials in the UI and restart."
      tail -f /dev/null
    fi

    if grep -qiE "Invalid Password" "$log_file"; then
      echo "[enshrouded] Steam password invalid; update credentials in the UI and restart."
      tail -f /dev/null
    fi

    if [ "$rc" -eq 0 ]; then
      rm -f "$RATE_LIMIT_FILE"
      if [ -n "${STEAM_GUARD_CODE:-}" ] && [ -f "$STEAM_AUTH_FILE" ]; then
        # Guard code is one-time; drop it after a successful login to avoid repeated 2FA prompts.
        sed -i '/^STEAM_GUARD_CODE=/d' "$STEAM_AUTH_FILE" || true
        unset STEAM_GUARD_CODE
        echo "[enshrouded] cleared one-time Steam Guard code after successful login."
      fi
      break
    fi

    if [ "$attempt" -ge 2 ]; then
      if [ "$fallback_win" -eq 0 ]; then
        echo "[enshrouded] linux steamcmd failed (exit $rc); attempting Windows steamcmd via wine64..."
        fallback_win=1
        set +e
        WINEDLLOVERRIDES="steam.exe=b;steamcmd.exe=b" "$WINE_BIN" "$STEAMCMD_WIN" +@sSteamCmdForcePlatformType windows +force_install_dir "$SERVER_DIR" +login "${login_args[@]}" +app_update 2278520 validate +quit 2>&1 | tee "$log_file"
        rc=${PIPESTATUS[0]}
        set -e
        if [ "$rc" -eq 0 ]; then
          rm -f "$RATE_LIMIT_FILE"
          break
        fi
      fi
      echo "[enshrouded] steamcmd failed (exit $rc); check $log_file for details."
      tail -f /dev/null
    fi

    echo "[enshrouded] steamcmd failed (exit $rc); cleaning steam app manifest and retrying once..."
    rm -f "$SERVER_DIR/steamapps/appmanifest_2278520.acf"
    rm -rf "$SERVER_DIR/steamapps/downloading/2278520" "$SERVER_DIR/steamapps/common/Enshrouded" "$SERVER_DIR/steamapps/appcache"
    mkdir -p "$SERVER_DIR/steamapps/downloading" "$SERVER_DIR/steamapps/common"
    chown -R "$(id -u)":"$(id -g)" "$SERVER_DIR/steamapps" || true
    attempt=$((attempt + 1))
  done
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

sync_json_config() {
  if [ ! -f "$SERVER_CONFIG_JSON" ]; then
    echo "[enshrouded] server config $SERVER_CONFIG_JSON not found; skipping json sync."
    return
  fi
  python3 - "$SERVER_CONFIG_JSON" <<'PY'
import json
import os
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

name = os.getenv("SERVER_NAME") or "Enshrouded Server"
save_dir = os.getenv("SAVE_DIR") or "/data/savegame"
query_port = os.getenv("QUERY_PORT") or "15637"
max_players = os.getenv("MAX_PLAYERS") or "16"
password = os.getenv("SERVER_PASSWORD", "")

data["name"] = name
data["saveDirectory"] = save_dir
try:
    data["queryPort"] = int(query_port)
except ValueError:
    pass
try:
    data["slotCount"] = int(max_players)
except ValueError:
    pass

if password:
    groups = data.get("userGroups")
    if isinstance(groups, list):
        for group in groups:
            if isinstance(group, dict) and group.get("name") == "Friend":
                group["password"] = password
                break

with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PY
}

run_server() {
  local bin="$SERVER_DIR/enshrouded_server.exe"
  if [ ! -f "$bin" ]; then
    echo "[enshrouded] server binary missing at $bin (run Steam update after login)"
    tail -f /dev/null
  fi
  local args=("$bin" "-log" "-SteamServerGamePort=${GAME_PORT:-15636}" "-SteamServerQueryPort=${QUERY_PORT:-15637}" "-ServerName=${SERVER_NAME:-Enshrouded Server}" "-SaveDirectory=${SAVE_DIR:-/data/savegame}" "-MaxPlayers=${MAX_PLAYERS:-16}")
  if [ -n "${SERVER_PASSWORD:-}" ]; then
    args+=("-Password=${SERVER_PASSWORD}")
  fi
  echo "[enshrouded] launching server via wine"
  exec "$WINE_BIN" "${args[@]}"
}

if [ "${UPDATE_ON_START:-true}" = "true" ]; then
  load_steam_auth
  update_server
fi

sync_json_config
generate_config
run_server
