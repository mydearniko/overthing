// Cloudflare Worker: WebSocket-to-TCP bridge for overthing relay traffic.
//
// Kaggle/notebook egress sees a normal HTTPS WebSocket to Cloudflare; the
// worker dials the actual relay (any host:port) over raw TCP from the edge.
//
// Usage from the client:
//   wss://<this-worker>.<account>.workers.dev/?relay=<base64url(host:port)>
//
// The 'relay' query parameter is the relay address, base64url-encoded, so it
// survives URL parsing. The client (overthing TunnelDialer) builds this
// automatically from the relay address it would have dialed directly.

export default {
  async fetch(request, env, ctx) {
    // Optional lock: set env.ALLOWED_TARGETS to a CSV of host:port entries
    // to restrict which relays this worker will dial. Empty/unset = allow all.
    if (request.method !== "GET") {
      return new Response("method not allowed", { status: 405 });
    }

    const upgradeHeader = request.headers.get("Upgrade");
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }

    const url = new URL(request.url);
    const relayB64 = url.searchParams.get("relay");
    if (!relayB64) {
      return new Response("missing relay parameter", { status: 400 });
    }

    let relayAddr;
    try {
      relayAddr = atob(
        relayB64.replace(/-/g, "+").replace(/_/g, "/") +
          "===".slice((relayB64.length + 3) % 4)
      );
    } catch {
      return new Response("bad relay encoding", { status: 400 });
    }

    // Validate address shape: host:port, port numeric.
    const idx = relayAddr.lastIndexOf(":");
    if (idx <= 0) {
      return new Response("bad relay address", { status: 400 });
    }
    const host = relayAddr.slice(0, idx);
    const port = parseInt(relayAddr.slice(idx + 1), 10);
    if (!/^[a-zA-Z0-9.\-]+$/.test(host) || !(port > 0 && port < 65536)) {
      return new Response("bad relay address", { status: 400 });
    }

    if (env.ALLOWED_TARGETS) {
      const allowed = String(env.ALLOWED_TARGETS).split(",");
      if (!allowed.includes(`${host}:${port}`)) {
        return new Response("relay not allowed", { status: 403 });
      }
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    // Accept the WebSocket, then connect to the relay from the edge.
    server.addEventListener("open", async () => {
      try {
        const socket = connect(relayAddr, { secureTransport: "never" });
        await socket.opened;

        // Pipe: websocket -> relay socket
        server.addEventListener("message", (event) => {
          if (typeof event.data === "string") {
            // Text frames are not part of the protocol; ignore them.
            return;
          }
          const writer = socket.writable.getWriter();
          writer.write(new Uint8Array(event.data)).then(() => writer.releaseLock());
        });

        // Pipe: relay socket -> websocket
        pumpSocketToWS(socket.readable, server);

        server.addEventListener("close", () => {
          try { socket.close(); } catch {}
        });
      } catch (err) {
        try { server.close(1011, "relay connect failed"); } catch {}
      }
    });

    server.addEventListener("error", () => {});

    return new Response(null, { status: 101, webSocket: client });
  },
};

async function pumpSocketToWS(readable, ws) {
  const reader = readable.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        // Copy into a plain ArrayBuffer so it survives as a binary frame.
        const copy = value.slice();
        ws.send(copy);
      }
    }
  } catch {
    // socket error: close the websocket
    try { ws.close(1011, "upstream closed"); } catch {}
  }
}
