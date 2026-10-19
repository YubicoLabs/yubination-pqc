import { readdir, readFile, access } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const files = ['README.md', ...(await readdir(resolve(root, 'docs'))).filter(x => x.endsWith('.md')).map(x => `docs/${x}`)];
let count = 0;
for (const file of files) {
  const text = await readFile(resolve(root, file), 'utf8');
  for (const match of text.matchAll(/\[[^\]]*\]\(([^\s)]+)\)/g)) {
    if (/^https?:\/\//.test(match[1]) || match[1].startsWith('#')) continue;
    await access(resolve(dirname(resolve(root, file)), match[1].split('#')[0])); count++;
  }
}
for (const file of ['simplewebauthn', 'keycloak', 'migration', 'policy']) {
  const text = await readFile(resolve(root, `docs/${file}.md`), 'utf8');
  for (const heading of ['Objective:', '## Predict', '## Do', '## Reveal', '## Optional deep dive', '## Done when', '**Win:**', '<details>', '<summary>']) {
    if (!text.includes(heading)) throw new Error(`${file}: missing ${heading}`);
  }
  if ((text.match(/<details>/g) || []).length !== (text.match(/<\/details>/g) || []).length) throw new Error(`${file}: unbalanced reveals`);
  if (/worksheet/i.test(text)) throw new Error(`${file}: worksheet instruction is not part of this journey`);
}
console.log(`PASS: ${files.length} active guide files, ${count} local links, four learning contracts. No runtime/hardware validation is implied.`);
