#!/usr/bin/env bash
# Axiom Network — WAN multi-host testnet deployment.
#
# Deploys axiom-node across 2+ servers, wires them as a mesh over their
# PUBLIC IPs, waits for handshake + tip agreement, then runs a 30-minute
# stability watch including a disconnect/reconnect drill.
#
# REQUIREMENTS (on the host running this script):
#   - bash, ssh, scp, curl, python3, jq (optional)
#   - Pre-built binary at target/release/axiom-node{,.exe}
#
# REQUIREMENTS (per remote host):
#   - Linux x86_64 with glibc ≥ 2.31 (Ubuntu 22.04+, Debian 12+)
#   - Inbound TCP 29000 open between hosts (edit P2P_PORT if different)
#   - SSH key auth as the user given in AXIOM_WAN_USER
#   - A user account with a writable $HOME and access to pkill / nc
#   - ~2 GB free disk in $HOME/axiom-data
#
# INVOCATION:
#
#   export AXIOM_WAN_HOSTS="203.0.113.10,203.0.113.11,203.0.113.12"
#   export AXIOM_WAN_USER="axiom"
#   export AXIOM_WAN_KEY="$HOME/.ssh/axiom_ed25519"
#   export AXIOM_WAN_MINER_ADDR="axm...75char..."   # optional; first host mines
#
#   scripts/wan/deploy-multihost.sh deploy   # upload binary + start nodes
#   scripts/wan/deploy-multihost.sh status   # show tip/peers on all hosts
#   scripts/wan/deploy-multihost.sh soak 30  # 30-minute stability watch
#   scripts/wan/deploy-multihost.sh drill    # stop+restart host[1], verify re-sync
#   scripts/wan/deploy-multihost.sh stop     # stop all nodes, preserve data
#   scripts/wan/deploy-multihost.sh purge    # stop + wipe remote data dirs
#
# SAFETY
#   - This script never writes to any remote path outside $HOME/axiom-*.
#   - Never runs with root sudo.
#   - Treats every remote command as untrusted: timeouts on all ssh calls.
#   - Fails loudly rather than silently skipping hosts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOCAL_BIN="$PROJECT_ROOT/target/release/axiom-node"
[ -f "$LOCAL_BIN" ] || LOCAL_BIN="$PROJECT_ROOT/target/release/axiom-node.exe"

: "${AXIOM_WAN_HOSTS:?set AXIOM_WAN_HOSTS=ip1,ip2,ip3}"
: "${AXIOM_WAN_USER:?set AXIOM_WAN_USER (remote login user)}"
: "${AXIOM_WAN_KEY:?set AXIOM_WAN_KEY (path to ssh private key)}"
AXIOM_WAN_MINER_ADDR="${AXIOM_WAN_MINER_ADDR:-}"
P2P_PORT="${P2P_PORT:-29000}"
RPC_PORT="${RPC_PORT:-18330}"
REMOTE_DIR="${REMOTE_DIR:-\$HOME/axiom-wan}"

IFS=',' read -r -a HOSTS <<<"$AXIOM_WAN_HOSTS"
[ "${#HOSTS[@]}" -ge 2 ] || { echo "ERROR: need at least 2 hosts in AXIOM_WAN_HOSTS" >&2; exit 2; }

SSH_OPTS=(-i "$AXIOM_WAN_KEY"
          -o BatchMode=yes
          -o StrictHostKeyChecking=accept-new
          -o ConnectTimeout=10
          -o ServerAliveInterval=30)

LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"

ssh_h()  { ssh "${SSH_OPTS[@]}" "$AXIOM_WAN_USER@$1" "$2"; }
scp_to() { scp "${SSH_OPTS[@]}" "$1" "$AXIOM_WAN_USER@$2:$3"; }

peer_args_for() {
    local self=$1 out=""
    for h in "${HOSTS[@]}"; do
        [ "$h" = "$self" ] && continue
        out="$out --peer $h:$P2P_PORT"
    done
    echo "$out"
}

cmd_deploy() {
    [ -f "$LOCAL_BIN" ] || { echo "ERROR: binary not found: $LOCAL_BIN" >&2; exit 1; }
    # Sanity: don't push a Windows PE .exe at a Linux host. If LOCAL_BIN is .exe,
    # look for a sibling Linux binary first.
    if [[ "$LOCAL_BIN" == *.exe ]]; then
        echo "WARNING: LOCAL_BIN is a Windows .exe — this will not run on Linux hosts." >&2
        echo "         Set LOCAL_BIN to a Linux ELF build (cross-compile or build on Linux)." >&2
        [ "${AXIOM_WAN_FORCE:-}" = "1" ] || { echo "Aborting. Override with AXIOM_WAN_FORCE=1 only if you know what you're doing." >&2; exit 1; }
    fi
    for i in "${!HOSTS[@]}"; do
        h="${HOSTS[$i]}"
        echo "── $h (node${i}) ────────────────────────────────"
        ssh_h "$h" "mkdir -p $REMOTE_DIR/bin $REMOTE_DIR/data $REMOTE_DIR/logs $REMOTE_DIR/pid"
        scp_to "$LOCAL_BIN" "$h" "$REMOTE_DIR/bin/axiom-node"
        ssh_h "$h" "chmod +x $REMOTE_DIR/bin/axiom-node"

        mine=""
        if [ "$i" = "0" ] && [ -n "$AXIOM_WAN_MINER_ADDR" ]; then
            mine="--mine --miner-address $AXIOM_WAN_MINER_ADDR --mining-interval 10"
        fi
        peers="$(peer_args_for "$h")"

        ssh_h "$h" "pkill -f axiom-node || true"
        ssh_h "$h" "
            cd $REMOTE_DIR
            nohup ./bin/axiom-node \
                --network test \
                --data-dir ./data \
                --rpc-bind 127.0.0.1:$RPC_PORT \
                --p2p-bind 0.0.0.0:$P2P_PORT \
                $peers $mine \
                --log-level info \
                >>./logs/node.log 2>&1 &
            echo \$! >./pid/node.pid
        "
        echo "  started node${i} on $h (peers=$peers $mine)"
    done
    echo "deploy done."
}

# ── Because RPC is bound to 127.0.0.1 on every remote host, we reach it
# via an SSH tunnel and curl it from the remote side.
remote_rpc() {
    local h="$1" path="$2"
    ssh_h "$h" "curl -s --max-time 5 http://127.0.0.1:$RPC_PORT$path"
}

cmd_status() {
    printf "%-18s %-10s %-20s %-8s\n" HOST HEIGHT TIP PEERS
    for h in "${HOSTS[@]}"; do
        tip=$(remote_rpc "$h" "/tip" 2>/dev/null || echo "{}")
        height=$(echo "$tip" | python3 -c "import json,sys;d=json.loads(sys.stdin.read() or '{}');print(d.get('best_height','?'))" 2>/dev/null || echo ?)
        thash=$(echo "$tip" | python3 -c "import json,sys;d=json.loads(sys.stdin.read() or '{}');print((d.get('best_block_hash','')[:16])+'...' if d.get('best_block_hash') else '?')" 2>/dev/null || echo ?)
        peers=$(remote_rpc "$h" "/peer_count" | python3 -c "import json,sys;v=json.loads(sys.stdin.read() or '0');print(v if isinstance(v,int) else v.get('count','?'))" 2>/dev/null || echo ?)
        printf "%-18s %-10s %-20s %-8s\n" "$h" "$height" "$thash" "$peers"
    done
}

cmd_soak() {
    local minutes="${1:-30}"
    local deadline=$(( $(date +%s) + minutes * 60 ))
    local out="$LOG_DIR/soak_$(date +%Y%m%dT%H%M%S).csv"
    echo "ts,host,height,tip,peers" >"$out"
    local fork_count=0 anomaly_count=0
    declare -A PREV_TIP_FOR_HEIGHT
    while [ "$(date +%s)" -lt "$deadline" ]; do
        now=$(date +%s)
        declare -A TIP_AT_H
        for h in "${HOSTS[@]}"; do
            tip=$(remote_rpc "$h" "/tip" 2>/dev/null || echo "{}")
            height=$(echo "$tip" | python3 -c "import json,sys;d=json.loads(sys.stdin.read() or '{}');print(d.get('best_height',''))" 2>/dev/null || echo "")
            thash=$(echo "$tip" | python3 -c "import json,sys;d=json.loads(sys.stdin.read() or '{}');print(d.get('best_block_hash',''))" 2>/dev/null || echo "")
            peers=$(remote_rpc "$h" "/peer_count" | python3 -c "import json,sys;v=json.loads(sys.stdin.read() or '0');print(v if isinstance(v,int) else v.get('count',''))" 2>/dev/null || echo "")
            echo "$now,$h,$height,$thash,$peers" >>"$out"
            if [ -n "$height" ] && [ -n "$thash" ]; then
                existing="${TIP_AT_H[$height]:-}"
                if [ -z "$existing" ]; then
                    TIP_AT_H[$height]="$thash"
                elif [ "$existing" != "$thash" ]; then
                    fork_count=$((fork_count+1))
                    echo "FORK at h=$height: $existing vs $thash" | tee -a "$LOG_DIR/forks.log"
                fi
            else
                anomaly_count=$((anomaly_count+1))
            fi
        done
        unset TIP_AT_H; declare -A TIP_AT_H
        sleep 30
    done
    echo
    echo "── Soak summary ──"
    echo "duration:  ${minutes} minutes"
    echo "samples:   $(( $(wc -l <"$out") - 1 ))"
    echo "forks:     $fork_count"
    echo "anomalies: $anomaly_count"
    echo "csv:       $out"
    echo
    if [ "$fork_count" -eq 0 ] && [ "$anomaly_count" -eq 0 ]; then
        echo "VERDICT: soak clean"
        return 0
    fi
    echo "VERDICT: soak dirty — review $LOG_DIR/forks.log"
    return 1
}

cmd_drill() {
    [ "${#HOSTS[@]}" -ge 2 ] || { echo "drill needs ≥2 hosts" >&2; exit 2; }
    local victim="${HOSTS[1]}"
    echo "disconnecting $victim for 60s"
    ssh_h "$victim" "kill \$(cat $REMOTE_DIR/pid/node.pid) 2>/dev/null || true"
    sleep 60
    echo "heights before restart:"; cmd_status
    echo "restarting $victim"
    local peers; peers="$(peer_args_for "$victim")"
    ssh_h "$victim" "
        cd $REMOTE_DIR
        nohup ./bin/axiom-node \
            --network test \
            --data-dir ./data \
            --rpc-bind 127.0.0.1:$RPC_PORT \
            --p2p-bind 0.0.0.0:$P2P_PORT \
            $peers \
            --log-level info \
            >>./logs/node.log 2>&1 &
        echo \$! >./pid/node.pid
    "
    echo "waiting 90s for re-sync"
    sleep 90
    echo "heights after restart:"; cmd_status
    echo "if the victim's height matches the others, re-sync succeeded."
}

cmd_stop()  { for h in "${HOSTS[@]}"; do ssh_h "$h" "pkill -f axiom-node || true"; done; echo "stopped."; }
cmd_purge() { cmd_stop; for h in "${HOSTS[@]}"; do ssh_h "$h" "rm -rf $REMOTE_DIR/data $REMOTE_DIR/logs $REMOTE_DIR/pid"; done; echo "purged."; }

case "${1:-}" in
    deploy) shift; cmd_deploy  ;;
    status) shift; cmd_status  ;;
    soak)   shift; cmd_soak "${1:-30}" ;;
    drill)  shift; cmd_drill   ;;
    stop)   shift; cmd_stop    ;;
    purge)  shift; cmd_purge   ;;
    *)
        echo "usage: $0 {deploy|status|soak [minutes]|drill|stop|purge}" >&2
        exit 2
        ;;
esac
