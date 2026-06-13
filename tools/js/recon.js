#!/usr/bin/env node
/**
 * CyberSec Toolkit — Reconnaissance Tool
 * Fixed: Proper async handling, added CT logs, S3 bucket detection
 */
const dns = require('dns').promises;
const https = require('https');
const http = require('http');
const { URL } = require('url');

async function getDNSRecords(domain) {
    console.log(`\n[DNS Records for ${domain}]`);
    const recordTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME'];
    
    for (const type of recordTypes) {
        try {
            const records = await dns.resolve(domain, type);
            console.log(`  ${type}: ${JSON.stringify(records)}`);
        } catch (e) {
            // No records of this type
        }
    }
}

async function getHttpHeaders(url) {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        const req = client.get(url, { timeout: 5000 }, (res) => {
            const headers = res.headers;
            console.log(`\n[HTTP Headers for ${url}]`);
            console.log(`  Status: ${res.statusCode}`);
            console.log(`  Server: ${headers.server || 'N/A'}`);
            console.log(`  X-Powered-By: ${headers['x-powered-by'] || 'N/A'}`);
            console.log(`  Content-Type: ${headers['content-type'] || 'N/A'}`);
            console.log(`  Set-Cookie: ${headers['set-cookie'] || 'N/A'}`);
            console.log(`  Strict-Transport-Security: ${headers['strict-transport-security'] || 'N/A'}`);
            console.log(`  Content-Security-Policy: ${headers['content-security-policy'] || 'N/A'}`);
            console.log(`  X-Frame-Options: ${headers['x-frame-options'] || 'N/A'}`);
            resolve(headers);
        });
        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Timeout'));
        });
    });
}

async function checkRobotsTxt(domain) {
    const url = `https://${domain}/robots.txt`;
    try {
        const response = await fetch(url, { timeout: 5000 });
        if (response.ok) {
            const text = await response.text();
            console.log(`\n[robots.txt for ${domain}]`);
            console.log(text.split('\n').slice(0, 20).join('\n'));
        }
    } catch (e) {
        console.log(`\n[!] robots.txt not found or error`);
    }
}

async function checkCertificateTransparency(domain) {
    console.log(`\n[Certificate Transparency Logs for ${domain}]`);
    try {
        const response = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, { timeout: 10000 });
        const data = await response.json();
        const subdomains = new Set();
        data.forEach(entry => {
            const names = entry.name_value.split('\n');
            names.forEach(name => {
                if (name.includes(domain)) subdomains.add(name.trim());
            });
        });
        console.log(`  Found ${subdomains.size} unique subdomains in CT logs:`);
        Array.from(subdomains).slice(0, 20).forEach(sub => console.log(`    - ${sub}`));
    } catch (e) {
        console.log(`  [!] Error fetching CT logs: ${e.message}`);
    }
}

async function checkS3Buckets(domain) {
    console.log(`\n[S3 Bucket Check for ${domain}]`);
    const buckets = [
        domain,
        `${domain}-backup`,
        `${domain}-assets`,
        `${domain}-data`,
        `${domain}-files`
    ];
    
    for (const bucket of buckets) {
        try {
            const response = await fetch(`https://${bucket}.s3.amazonaws.com`, { timeout: 5000 });
            if (response.status !== 404) {
                console.log(`  [!] Potential bucket found: ${bucket}.s3.amazonaws.com (Status: ${response.status})`);
            }
        } catch (e) {
            // Bucket doesn't exist or no access
        }
    }
}

async function main() {
    const args = process.argv.slice(2);
    if (args.length < 2) {
        console.log(`
CyberSec Recon Tool
Usage:
  node recon.js dns <domain>         - DNS enumeration
  node recon.js headers <domain>     - HTTP headers analysis
  node recon.js robots <domain>     - robots.txt check
  node recon.js ct <domain>         - Certificate Transparency logs
  node recon.js s3 <domain>         - S3 bucket enumeration
  node recon.js all <domain>        - Run all checks
        `);
        return;
    }
    
    const [command, domain] = args;
    
    try {
        switch (command) {
            case 'dns':
                await getDNSRecords(domain);
                break;
            case 'headers':
                await getHttpHeaders(`https://${domain}`);
                break;
            case 'robots':
                await checkRobotsTxt(domain);
                break;
            case 'ct':
                await checkCertificateTransparency(domain);
                break;
            case 's3':
                await checkS3Buckets(domain);
                break;
            case 'all':
                await getDNSRecords(domain);
                await getHttpHeaders(`https://${domain}`);
                await checkRobotsTxt(domain);
                await checkCertificateTransparency(domain);
                await checkS3Buckets(domain);
                break;
            default:
                console.log('Unknown command');
        }
    } catch (error) {
        console.error(`[!] Error: ${error.message}`);
    }
}

main();
