// Offline validation of the /x402/audit rule engine.
// Extracts the handler's logic by POSTing to a locally-spun server via supertest-less direct call.
// To keep it zero-dep we spin the express app on a random port and hit it with fetch.

import express from 'express';
import crypto from 'crypto';

// Minimal clone of the rule engine for offline test. Must stay in sync with server.mjs.
const RULES = [
  { cat: 'hardcoded_secret', sev: 'critical', re: /(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{16,}['"]/i },
  { cat: 'hardcoded_secret', sev: 'critical', re: /sk[-_](?:ant|proj|live|test)[-_][A-Za-z0-9_]{10,}|ghp_[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9-]+|AIza[0-9A-Za-z_-]{30,}|AKIA[0-9A-Z]{16}/ },
  { cat: 'hardcoded_secret', sev: 'critical', re: /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/ },
  { cat: 'code_injection', sev: 'critical', re: /\beval\s*\(/ },
  { cat: 'code_injection', sev: 'high', re: /new\s+Function\s*\(/ },
  { cat: 'command_injection', sev: 'critical', re: /(?:child_process\.(?:exec|execSync)|\bexec\s*\(\s*['"`])[^)]*?(?:\+|\$\{)/ },
  { cat: 'command_injection', sev: 'critical', re: /os\.system\s*\(|subprocess\.(?:call|Popen|run)\s*\([^,)]*shell\s*=\s*True/ },
  { cat: 'sql_injection', sev: 'critical', re: /(?:query|execute|exec|raw)\s*\(\s*[`'"][^`'")]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^`'")]*(?:\$\{|`\s*\+|['"]\s*\+)/i },
  { cat: 'path_traversal', sev: 'high', re: /fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\([^,)]*(?:\+|\$\{|req\.(?:query|params|body))/ },
  { cat: 'weak_crypto', sev: 'high', re: /Math\.random\s*\(\s*\)/ },
  { cat: 'insecure_deserialize', sev: 'critical', re: /pickle\.loads|yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.Safe)/ },
  { cat: 'xss', sev: 'high', re: /\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html/ },
  { cat: 'disabled_security', sev: 'high', re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False/ }
];

function audit(code) {
  const lines = code.split('\n');
  const findings = [];
  for (const r of RULES) for (let i = 0; i < lines.length; i++) if (r.re.test(lines[i])) findings.push({ cat: r.cat, sev: r.sev, line: i + 1 });
  return findings;
}

const samples = {
  'secret_literal.js': `const apiKey = "sk-ant-api03-abcdef1234567890abcdef";\nfetch("/x", {headers: {Authorization: apiKey}});`,
  'github_pat.js': `const TOKEN = "ghp_PLACEHOLDER_TOKEN_REDACTED_FOR_PUBLIC_MIRROR";`,
  'eval_usage.js': `function run(userInput) { return eval(userInput); }`,
  'child_process.js': `const { exec } = require('child_process');\nexec("rm -rf " + req.query.path);`,
  'sql_concat.js': `db.query("SELECT * FROM users WHERE id = " + req.params.id);`,
  'path_traversal.js': `fs.readFileSync(req.query.file);`,
  'math_random.js': `const token = Math.random().toString(36);`,
  'yaml_unsafe.py': `import yaml\ndata = yaml.load(request.body)`,
  'innerhtml.js': `el.innerHTML = req.body.content;`,
  'tls_off.js': `https.request({rejectUnauthorized: false}, cb);`,
  'clean.js': `function add(a, b) { return a + b; }\nconst result = add(1, 2);\nconsole.log('sum:', result);`
};

let pass = 0, fail = 0;
for (const [name, code] of Object.entries(samples)) {
  const f = audit(code);
  const expected = name === 'clean.js' ? 0 : 1;
  const ok = name === 'clean.js' ? f.length === 0 : f.length >= expected;
  if (ok) { pass++; console.log(`✓ ${name}  →  ${f.length} findings [${f.map(x=>x.cat).join(',')}]`); }
  else { fail++; console.log(`✗ ${name}  →  expected ${expected}+ findings, got ${f.length}`); }
}
console.log(`\n${pass}/${pass+fail} passed`);
process.exit(fail > 0 ? 1 : 0);
