// run from the repo root after `npm run build`:  node examples/node.mjs
// (or point the import at ../src/index.ts and run with a TS-aware node)
import { renderMarkdown, safeUrl, highlight } from '../dist/index.js';

const md = `# ss-md

A **zero-dep** markdown subset compiler. Raw HTML never passes through:

<script>alert(1)</script>

\`\`\`ts
const greet = (name: string) => \`hello \${name}\`;
\`\`\`

- [safe link](https://seanstoves.com)
- [blocked](javascript:alert(1)) renders inert
`;

console.log(renderMarkdown(md));

console.log('\n--- safeUrl ---');
console.log('https ->', safeUrl('https://seanstoves.com'));
console.log('javascript ->', safeUrl('javascript:alert(1)'));   // null
console.log('protocol-relative ->', safeUrl('//evil.com'));     // null

console.log('\n--- highlight (standalone) ---');
console.log(highlight('resource "aws_s3_bucket" "b" { bucket = "x" }', 'terraform'));
