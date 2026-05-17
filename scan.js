const fs = require("fs");
const WebSocket = require("ws");

/**
 * Parse a vless:// link (type=ws) and return connection details
 */
function parseVless(link) {
  const url = new URL(link);
  if (url.protocol !== "vless:") throw new Error("Not a vless:// URL");

  const params = url.searchParams;
  if (params.get("type") !== "ws") throw new Error("type must be ws");

  const sni = params.get("sni") || params.get("host") || url.hostname;
  const proto = params.get("security") === "none" ? "ws" : "wss";
  const path = params.get("path") || "/";
  const port = url.port || (proto === "wss" ? 443 : 80);

  return {
    uuid: url.username,
    wsUrl: `${proto}://${sni}:${port}${path}`,
    host: params.get("host") || sni,   // used in HTTP Host header
    sni: sni,
    port: port,
  };
}

/**
 * Convert UUID string to 16-byte Uint8Array
 */
function uuidToBytes(uuid) {
  const hex = uuid.replace(/-/g, "");
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Build the initial VLESS command packet:
 * [1 byte version=0] [16 bytes uuid] [1 byte address type=2] [1 byte host length] [host] [2 bytes port]
 */
function buildVlessCommand(host, port, uuid) {
  const hostBytes = Buffer.from(host, "utf-8");
  const cmd = Buffer.alloc(1 + 16 + 1 + 1 + hostBytes.length + 2);
  let offset = 0;
  cmd[offset++] = 0;                           // version
  cmd.set(uuidToBytes(uuid), offset); offset += 16;
  cmd[offset++] = 2;                           // address type: domain
  cmd[offset++] = hostBytes.length;            // host length
  cmd.set(hostBytes, offset); offset += hostBytes.length;
  cmd.writeUInt16BE(port, offset);             // port (big-endian)
  return cmd;
}

/**
 * Perform a test request to https://detectportal.firefox.com/success.txt
 * through the given VLESS over WebSocket configuration.
 * Returns true if HTTP 200 is received, false otherwise.
 */
async function testVlessConfig(link) {
  const conf = parseVless(link);
  console.log(`\nTesting: ${conf.wsUrl} (uuid: ${conf.uuid.substring(0, 8)}...)`);

  // Open WebSocket
  const ws = new WebSocket(conf.wsUrl, { handshakeTimeout: 10000 });
  let chunks = [];

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      ws.close();
      reject(new Error("connection timeout"));
    }, 15000);

    ws.on("open", () => {
      console.log(" WS connected");
      // 1. Send VLESS command
      const cmd = buildVlessCommand(conf.sni, conf.port, conf.uuid);
      ws.send(cmd);

      // 2. Send HTTP request to detectportal.firefox.com
      const httpReq = `GET /success.txt HTTP/1.1\r\nHost: detectportal.firefox.com\r\nConnection: close\r\n\r\n`;
      ws.send(httpReq);
    });

    ws.on("message", (data) => {
      chunks.push(Buffer.from(data));
    });

    ws.on("close", (code) => {
      clearTimeout(timeout);
      console.log(` WS closed (code ${code})`);
      resolve();
    });

    ws.on("error", (err) => {
      clearTimeout(timeout);
      console.error(" WS error:", err.message);
      reject(err);
    });
  });

  // Parse response
  const response = Buffer.concat(chunks).toString("utf-8");
  if (!response) {
    console.log(" Empty response");
    return false;
  }
  const statusLine = response.split("\r\n")[0];
  const statusCode = statusLine ? parseInt(statusLine.split(" ")[1], 10) : 0;
  console.log(` HTTP status: ${statusCode || "parse error"}`);
  return statusCode === 200;
}

// ------------------- Main scanner -------------------
(async () => {
  const configUrl = process.argv[2];
  if (!configUrl) {
    console.error("Usage: node scan.js <raw_url>");
    process.exit(1);
  }

  console.log(`Fetching config list from: ${configUrl}`);
  const resp = await fetch(configUrl);
  if (!resp.ok) throw new Error(`Failed to fetch config list (HTTP ${resp.status})`);
  const text = await resp.text();

  // Split by lines, trim, keep only lines starting with vless://
  const links = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.startsWith("vless://"));

  if (links.length === 0) {
    console.log("No vless:// links found in file.");
    fs.writeFileSync("working.json", "[]");
    return;
  }

  console.log(`Found ${links.length} config(s). Starting scan...`);

  const working = [];
  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    try {
      const ok = await testVlessConfig(link);
      if (ok) {
        working.push(link);
        console.log(` ✅ [${i + 1}/${links.length}] WORKING`);
      } else {
        console.log(` ❌ [${i + 1}/${links.length}] FAILED (non-200 response)`);
      }
    } catch (e) {
      console.log(` ❌ [${i + 1}/${links.length}] ERROR: ${e.message}`);
    }
  }

  // Save working links
  fs.writeFileSync("working.json", JSON.stringify(working, null, 2));
  console.log(`\nDone. ${working.length} out of ${links.length} configs are working.`);
  console.log("Results saved to working.json");
})();
