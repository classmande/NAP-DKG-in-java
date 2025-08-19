// delay-proxy.mjs — adds base±jitter delay to every request, then proxies to upstream
import http from "http";

const LISTEN_PORT = Number(process.env.LISTEN || "3003"); // where your app connects
const UP_HOST = process.env.UP_HOST || "127.0.0.1";
const UP_PORT = Number(process.env.UP_PORT || "3004"); // where json-server runs
const BASE_MS = Number(process.env.DELAY || "0"); // e.g., 50
const JITTER_MS = Number(process.env.JITTER || "0"); // e.g., 150

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function jitteredDelay() {
  if (!JITTER_MS) return Math.max(0, BASE_MS);
  const j = Math.floor(Math.random() * (2 * JITTER_MS + 1)) - JITTER_MS;
  return Math.max(0, BASE_MS + j);
}

const server = http.createServer(async (req, res) => {
  try {
    const d = jitteredDelay();
    if (d) await sleep(d);

    const opts = {
      hostname: UP_HOST,
      port: UP_PORT,
      path: req.url,
      method: req.method,
      headers: req.headers,
    };

    const upReq = http.request(opts, (upRes) => {
      res.writeHead(upRes.statusCode || 502, upRes.headers);
      upRes.pipe(res);
    });

    upReq.on("error", (err) => {
      res.statusCode = 502;
      res.end("Bad Gateway: " + err.message);
    });

    req.pipe(upReq);
  } catch (e) {
    res.statusCode = 500;
    res.end("Proxy error: " + String(e));
  }
});

server.listen(LISTEN_PORT, () => {
  console.log(
    `Delay proxy listening on ${LISTEN_PORT} -> ${UP_HOST}:${UP_PORT} (delay ${BASE_MS}±${JITTER_MS} ms)`
  );
});
