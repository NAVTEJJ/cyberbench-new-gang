const esbuild = require("esbuild");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = __dirname;
const distExt = path.join(root, "dist_ext");

async function build() {
  // Clean
  fs.rmSync(distExt, { recursive: true, force: true });
  fs.mkdirSync(distExt, { recursive: true });

  // 1. Tailwind CSS
  console.log("Building Tailwind CSS...");
  execSync(
    `npx @tailwindcss/cli -i src/styles.css -o dist_ext/styles.css --minify`,
    { stdio: "inherit", cwd: root }
  );

  // 2. Background service worker (ethers bundle)
  await esbuild.build({
    entryPoints: [path.join(root, "src/background.js")],
    bundle: true,
    outfile: path.join(distExt, "background.js"),
    format: "iife",
    target: "chrome110",
    define: { global: "globalThis" },
  });

  // 3. Popup JS (no external deps, just our SPA code)
  await esbuild.build({
    entryPoints: [path.join(root, "src/popup.js")],
    bundle: false,
    outfile: path.join(distExt, "popup.js"),
    target: "chrome110",
  });

  // 4. Content script
  await esbuild.build({
    entryPoints: [path.join(root, "src/content.js")],
    bundle: false,
    outfile: path.join(distExt, "content.js"),
    target: "chrome110",
  });

  // 5. Inpage script
  await esbuild.build({
    entryPoints: [path.join(root, "src/inpage.js")],
    bundle: false,
    outfile: path.join(distExt, "inpage.js"),
    target: "chrome110",
  });

  // 6. Copy static assets for extension
  fs.copyFileSync(path.join(root, "popup.html"), path.join(distExt, "popup.html"));
  fs.copyFileSync(path.join(root, "manifest.json"), path.join(distExt, "manifest.json"));

  // Copy icons
  const iconsDir = path.join(distExt, "icons");
  fs.mkdirSync(iconsDir, { recursive: true });
  const iconsSrc = path.join(root, "icons");
  for (const f of fs.readdirSync(iconsSrc)) {
    fs.copyFileSync(path.join(iconsSrc, f), path.join(iconsDir, f));
  }

  // Copy fonts
  const fontsDir = path.join(distExt, "fonts");
  fs.mkdirSync(fontsDir, { recursive: true });
  const fontsSrc = path.join(root, "fonts");
  for (const f of fs.readdirSync(fontsSrc)) {
    fs.copyFileSync(path.join(fontsSrc, f), path.join(fontsDir, f));
  }

  console.log("Build complete -> dist_ext/");
}

build().catch((e) => { console.error(e); process.exit(1); });
