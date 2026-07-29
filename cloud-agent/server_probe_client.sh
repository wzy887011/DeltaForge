#!/system/bin/sh
# Query a self-hosted DeltaForge observation endpoint and preserve raw evidence.
set -u

URL=${1:-}
OUT=${2:-/data/local/tmp/deltaforge_server_probe.json}
[ -n "$URL" ] || { echo 'usage: server_probe_client.sh URL [OUTPUT]'; exit 2; }

CURL="$(command -v curl 2>/dev/null || true)"
[ -n "$CURL" ] || CURL=/data/data/com.termux/files/usr/bin/curl
[ -x "$CURL" ] || { echo 'curl not found'; exit 1; }

mkdir -p "$(dirname "$OUT")"
TMP="$OUT.work.$$"
META="$OUT.meta"

"$CURL" -4 -fsS --connect-timeout 10 --max-time 30 \
    -H 'Accept: application/json' \
    -H 'User-Agent: DeltaForge-Integration/8.7' \
    -o "$TMP" \
    -w 'http_code=%{http_code} remote_ip=%{remote_ip} local_ip=%{local_ip} connect=%{time_connect} tls=%{time_appconnect} total=%{time_total}\n' \
    "$URL" > "$META" || { rc=$?; rm -f "$TMP"; echo "probe failed rc=$rc"; exit "$rc"; }

mv "$TMP" "$OUT"
chmod 0600 "$OUT" "$META"
cat "$META"
cat "$OUT"
