#!/usr/bin/env node
/**
 * CyberSec Toolkit — Network Recon Tool
 * =======================================
 * Lightweight reconnaissance: DNS lookups, HTTP header grabbing,
 * robots.txt/sitemap extraction, and WHOIS via public APIs.
 *
 * Usage:
 *   node recon.js dns    example.com
 *   node recon.js headers example.com
 *   node recon.js robots  example.com
 *   node recon.js all     example.com
 *
 * No external npm packages required — uses only Node.js stdlib.
 *
 * Educational use only. See ETHICAL_USE.txt before use.
 */

"use strict";

const dns   = require("dns").promises;
const https = require("https");
const http  = require("http");
const url   = require("url");

// ─────────────────────────────────────────────────────────────────────────────
// Colour helpers
// ─────────────────────────────────────────────────────────────────────────────

const C = {
  reset:  "\x1b[0m",
  green:  "\x1b[92m",
  yellow: "\x1b[93m",
  cyan:   "\x1b[96m",
  red:    "\x1b[91m",
  bold:   "\x1b[1m",
  dim:    "\x1b[2m",
  blue:   "\x1b[94m",
};

const green  = (s) => `${C.green}${s}${C.reset}`;
const yellow = (s) => `${C.yellow}${s}${C.reset}`;
const cyan   = (s) => `${C.cyan}${s}${C.reset}`;
const red    = (s) => `${C.red}${s}${C.reset}`;
const bold   = (s) => `${C.bold}${s}${C.reset}`;
const dim    = (s) => `${C.dim}${s}${C.reset}`;
const blue   = (s) => `${C.blue}${s}${C.reset}`;

function section(title) {
  console.log(`\n  ${bold(cyan("┌─ " + title + " " + "─".repeat(Math.max(0, 48 - title.length)) + "┐"))}`);
}
function sectionEnd() {
  console.log(`  ${bold(cyan("└" + "─".repeat(53) + "┘"))}`);
}
function row(label, value) {
  const pad = 18;
  console.log(`  │  ${bold(label.padEnd(pad))} ${green(value)}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP fetch helper
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Simple GET request. Returns { status, headers, body }.
 * Follows one redirect, uses https by default.
 */
function fetch(targetUrl, { timeout = 8000, followRedirect = true } = {}) {
  return new Promise((resolve, reject) => {
    const parsed = url.parse(targetUrl);
    const lib = parsed.protocol === "http:" ? http : https;

    const opts = {
      hostname: parsed.hostname,
      path: parsed.path || "/",
      port: parsed.port || (parsed.protocol === "http:" ? 80 : 443),
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (CyberSec-Toolkit/1.0; educational)",
        Accept: "text/html,*/*",
      },
      timeout,
      rejectUnauthorized: false,        // don't fail on self-signed certs in labs
    };

    const req = lib.request(opts, (res) => {
      // Follow one redirect
      if (followRedirect && [301, 302, 303, 307, 308].includes(res.statusCode)) {
        const loc = res.headers["location"];
        if (loc) {
          const redirectUrl = loc.startsWith("http") ? loc : `${parsed.protocol}//${parsed.hostname}${loc}`;
          return fetch(redirectUrl, { timeout, followRedirect: false })
            .then(resolve).catch(reject);
        }
      }

      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });

    req.on("timeout", () => { req.destroy(); reject(new Error("Request timed out")); });
    req.on("error",   (e) => reject(e));
    req.end();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Recon modules
// ─────────────────────────────────────────────────────────────────────────────

async function reconDNS(domain) {
  section("DNS Records");

  const types = [
    ["A",     () => dns.resolve4(domain)],
    ["AAAA",  () => dns.resolve6(domain)],
    ["MX",    () => dns.resolveMx(domain).then((r) => r.map((m) => `${m.exchange} (priority ${m.priority})`))],
    ["NS",    () => dns.resolveNs(domain)],
    ["TXT",   () => dns.resolveTxt(domain).then((r) => r.map((t) => t.join("")))],
    ["CNAME", () => dns.resolveCname(domain)],
    ["SOA",   () => dns.resolveSoa(domain).then((r) => [`${r.nsname} (serial: ${r.serial})`])],
  ];

  for (const [type, resolver] of types) {
    try {
      const records = await resolver();
      const arr = Array.isArray(records) ? records : [records];
      arr.forEach((r) => row(type, String(r)));
    } catch (e) {
      console.log(`  │  ${bold(type.padEnd(18))} ${dim("no record / not found")}`);
    }
  }

  sectionEnd();
}

async function reconHeaders(domain) {
  section("HTTP Headers");
  const target = domain.startsWith("http") ? domain : `https://${domain}`;

  let result;
  try {
    result = await fetch(target);
  } catch (e) {
    // Try plain HTTP fallback
    try {
      result = await fetch(`http://${domain}`);
    } catch (e2) {
      console.log(`  │  ${red("Error: " + e2.message)}`);
      sectionEnd();
      return;
    }
  }

  row("Status", String(result.status));
  const interesting = [
    "server", "x-powered-by", "x-frame-options", "x-xss-protection",
    "x-content-type-options", "strict-transport-security", "content-security-policy",
    "set-cookie", "access-control-allow-origin", "referrer-policy",
    "permissions-policy", "x-aspnet-version", "x-generator",
  ];

  for (const [key, val] of Object.entries(result.headers)) {
    if (interesting.includes(key.toLowerCase())) {
      const flag = ["server","x-powered-by","x-aspnet-version","x-generator"].includes(key.toLowerCase())
        ? yellow("[info-leak]") : green("[security]");
      row(key, `${val} ${dim(flag)}`);
    }
  }

  // Security header audit
  const missing = ["strict-transport-security","x-frame-options","content-security-policy",
                   "x-content-type-options","referrer-policy"].filter(
    (h) => !result.headers[h]
  );
  if (missing.length) {
    console.log(`\n  │  ${yellow("⚠ Missing security headers:")}`);
    missing.forEach((h) => console.log(`  │    ${red("✘")} ${h}`));
  }
  sectionEnd();
}

async function reconRobots(domain) {
  section("robots.txt & sitemap.xml");
  const base = domain.startsWith("http") ? domain : `https://${domain}`;

  // robots.txt
  try {
    const r = await fetch(`${base}/robots.txt`);
    if (r.status === 200 && r.body.toLowerCase().includes("disallow")) {
      const lines = r.body.split(/\r?\n/).filter((l) =>
        l.trim() && !l.startsWith("#")
      );
      console.log(`  │  ${green("robots.txt found")} (${lines.length} directives)`);
      const disallowed = lines.filter((l) => l.toLowerCase().startsWith("disallow"));
      if (disallowed.length) {
        console.log(`  │  ${yellow("Disallowed paths:")}`);
        disallowed.slice(0, 15).forEach((l) =>
          console.log(`  │    ${dim("→")} ${l.replace(/^[Dd]isallow:\s*/,"").trim()}`)
        );
        if (disallowed.length > 15)
          console.log(`  │    ${dim(`... and ${disallowed.length - 15} more`)}`);
      }
    } else {
      console.log(`  │  ${dim("robots.txt")} — ${yellow("not found or empty")}`);
    }
  } catch (e) {
    console.log(`  │  robots.txt — ${red(e.message)}`);
  }

  // sitemap.xml
  try {
    const s = await fetch(`${base}/sitemap.xml`);
    if (s.status === 200) {
      const urls = (s.body.match(/<loc>(.*?)<\/loc>/g) || []).length;
      console.log(`  │  ${green("sitemap.xml found")} — ${urls} URL(s) indexed`);
    } else {
      console.log(`  │  ${dim("sitemap.xml")} — ${yellow("not found")}`);
    }
  } catch (e) {
    console.log(`  │  sitemap.xml — ${red(e.message)}`);
  }
  sectionEnd();
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner & CLI
// ─────────────────────────────────────────────────────────────────────────────

function banner() {
  console.log(cyan(`
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  Network Recon — CyberSec Toolkit v1.0
  github.com/nikhiltomar2712/cybersec
`));
}

function printHelp() {
  console.log(`
  ${bold("Usage:")}
    node recon.js <command> <domain>

  ${bold("Commands:")}
    dns      <domain>    DNS record enumeration (A, MX, NS, TXT, SOA…)
    headers  <domain>    HTTP header grabbing + security audit
    robots   <domain>    Fetch robots.txt and sitemap.xml
    all      <domain>    Run all modules

  ${bold("Examples:")}
    node recon.js dns     example.com
    node recon.js headers example.com
    node recon.js all     example.com
  `);
}

async function main() {
  banner();

  const args = process.argv.slice(2);
  if (args.length < 2 || args[0] === "help") { printHelp(); return; }

  const [cmd, target] = args;
  const domain = target.replace(/^https?:\/\//, "").split("/")[0];

  console.log(`  ${bold("Target  :")} ${cyan(domain)}`);
  console.log(`  ${bold("Command :")} ${cmd}`);
  console.log(`  ${bold("Time    :")} ${new Date().toISOString()}`);

  try {
    switch (cmd.toLowerCase()) {
      case "dns":     await reconDNS(domain); break;
      case "headers": await reconHeaders(domain); break;
      case "robots":  await reconRobots(domain); break;
      case "all":
        await reconDNS(domain);
        await reconHeaders(domain);
        await reconRobots(domain);
        break;
      default:
        console.error(red(`[!] Unknown command: ${cmd}`));
        printHelp();
    }
  } catch (e) {
    console.error(red(`[!] Fatal: ${e.message}`));
    process.exit(1);
  }
}

main();
