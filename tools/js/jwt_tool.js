#!/usr/bin/env node
/**
 * CyberSec Toolkit — JWT Security Analyzer
 * Decode, verify, and crack JWT tokens
 */
const crypto = require('crypto');

function base64UrlDecode(str) {
    // Add padding
    const padding = '='.repeat((4 - str.length % 4) % 4);
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/') + padding;
    return JSON.parse(Buffer.from(base64, 'base64').toString('utf8'));
}

function decodeJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
    }
    
    return {
        header: base64UrlDecode(parts[0]),
        payload: base64UrlDecode(parts[1]),
        signature: parts[2]
    };
}

function checkSecurity(jwt) {
    const issues = [];
    
    if (jwt.header.alg === 'none') {
        issues.push('CRITICAL: Algorithm is "none" - token can be forged');
    }
    if (jwt.header.alg === 'HS256' && !jwt.header.kid) {
        issues.push('WARNING: No key ID specified');
    }
    if (jwt.payload.exp && jwt.payload.exp < Date.now() / 1000) {
        issues.push('WARNING: Token has expired');
    }
    if (!jwt.payload.exp && !jwt.payload.iat) {
        issues.push('INFO: No expiration or issued-at time');
    }
    if (jwt.payload.sub && jwt.payload.sub.includes('admin')) {
        issues.push('INFO: Token contains admin subject');
    }
    
    return issues;
}

function bruteForceSecret(token, wordlist) {
    const parts = token.split('.');
    const data = parts[0] + '.' + parts[1];
    
    for (const secret of wordlist) {
        const hmac = crypto.createHmac('sha256', secret)
                          .update(data)
                          .digest('base64url');
        if (hmac === parts[2]) {
            return secret;
        }
    }
    return null;
}

function main() {
    const args = process.argv.slice(2);
    
    if (args.length < 1) {
        console.log(`
JWT Security Analyzer
Usage:
  node jwt_tool.js decode <token>           - Decode JWT
  node jwt_tool.js analyze <token>          - Security analysis
  node jwt_tool.js crack <token> <wordlist> - Brute force secret
        `);
        return;
    }
    
    const command = args[0];
    const token = args[1];
    
    try {
        switch (command) {
            case 'decode': {
                const jwt = decodeJWT(token);
                console.log('Header:', JSON.stringify(jwt.header, null, 2));
                console.log('Payload:', JSON.stringify(jwt.payload, null, 2));
                break;
            }
            case 'analyze': {
                const jwt = decodeJWT(token);
                const issues = checkSecurity(jwt);
                console.log('Header:', JSON.stringify(jwt.header, null, 2));
                console.log('Payload:', JSON.stringify(jwt.payload, null, 2));
                console.log('\nSecurity Issues:');
                issues.forEach(i => console.log('  ' + i));
                break;
            }
            case 'crack': {
                const wordlist = require('fs').readFileSync(args[2], 'utf8')
                    .split('\n').filter(Boolean);
                console.log(`[*] Testing ${wordlist.length} secrets...`);
                const found = bruteForceSecret(token, wordlist);
                if (found) {
                    console.log(`[+] Secret found: ${found}`);
                } else {
                    console.log('[-] Secret not found');
                }
                break;
            }
            default:
                console.log('Unknown command');
        }
    } catch (e) {
        console.error(`[!] Error: ${e.message}`);
    }
}

main();
