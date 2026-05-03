set -e

PROXY_NAME="myproxy"
LATENCY=${2:-35}
BANDWIDTH=${3:-12500}
LISTEN_PORT=${4:-1213}
UPSTREAM_PORT=${5:-1212}

case "$1" in
  start)
    echo "==> Killing any existing toxiproxy-server..."
    pkill toxiproxy-server 2>/dev/null || true
    sleep 0.5

    echo "==> Starting toxiproxy-server..."
    toxiproxy-server > /tmp/toxiproxy.log 2>&1 &
    sleep 0.5

    echo "==> Creating proxy: 127.0.0.1:${LISTEN_PORT} -> 127.0.0.1:${UPSTREAM_PORT}..."
    toxiproxy-cli create --listen 127.0.0.1:${LISTEN_PORT} --upstream 127.0.0.1:${UPSTREAM_PORT} ${PROXY_NAME}

    echo "==> Adding latency: ${LATENCY}ms downstream..."
    toxiproxy-cli toxic add --type=latency --attribute=latency=${LATENCY} --downstream ${PROXY_NAME}

    echo "==> Adding latency: ${LATENCY}ms upstream..."
    toxiproxy-cli toxic add --type=latency --attribute=latency=${LATENCY} --upstream ${PROXY_NAME}

    echo "==> Adding bandwidth: ${BANDWIDTH} KB/s downstream..."
    toxiproxy-cli toxic add --type=bandwidth --attribute=rate=${BANDWIDTH} --downstream ${PROXY_NAME}

    echo "==> Adding bandwidth: ${BANDWIDTH} KB/s upstream..."
    toxiproxy-cli toxic add --type=bandwidth --attribute=rate=${BANDWIDTH} --upstream ${PROXY_NAME}

    echo ""
    echo "==> WAN simulation active:"
    toxiproxy-cli inspect ${PROXY_NAME}
    echo ""
    echo "RTT: $((LATENCY * 2))ms | Bandwidth: ${BANDWIDTH} KB/s both ways"
    echo "Point your sender to 127.0.0.1:${LISTEN_PORT}"
    ;;

  stop)
    echo "==> Removing proxy..."
    toxiproxy-cli delete ${PROXY_NAME} 2>/dev/null || true
    echo "==> Stopping toxiproxy-server..."
    pkill toxiproxy-server 2>/dev/null || true
    echo "==> Done."
    ;;

  status)
    toxiproxy-cli inspect ${PROXY_NAME}
    ;;

  *)
    echo "Usage: $0 {start|stop|status} [latency_ms] [bandwidth_kbps] [listen_port] [upstream_port]"
    echo ""
    echo "Examples:"
    echo "  $0 start                      # 35ms one-way (70ms RTT), 100 Mbit/s both ways"
    echo "  $0 start 50 6250              # 50ms one-way (100ms RTT), 50 Mbit/s both ways"
    echo "  $0 start 35 12500 1213 1212   # explicit ports"
    echo "  $0 stop"
    echo "  $0 status"
    exit 1
    ;;
esac