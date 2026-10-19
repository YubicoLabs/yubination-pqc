// Run after `mvn package` in examples/keycloak/virtual-authenticator.
// Pinned dependency notice coverage, not a legal-compliance certification.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
const jar = fileURLToPath(new URL('../examples/keycloak/virtual-authenticator/target/virtual-mldsa-authenticator.jar', import.meta.url));
const entries = new Set(execFileSync('unzip', ['-Z1',jar],{encoding:'utf8'}).trim().split('\n'));
const base = 'META-INF/dependency-notices/';
for (const artifact of ['jackson-core','jackson-databind','jackson-annotations','jackson-dataformat-cbor']) {
  for (const name of ['LICENSE','NOTICE']) {
    const path = `${base}${artifact}-2.19.2-jar/META-INF/${name}`;
    assert(entries.has(path), `Missing ${path}`);
    assert(execFileSync('unzip',['-p',jar,path]).length > 0,`Empty ${path}`);
  }
}
for (const path of ['bcprov-jdk18on-1.82-LICENSE.html', 'jackson-core-2.19.2-jar/META-INF/FastDoubleParser-LICENSE','jackson-core-2.19.2-jar/META-INF/FastDoubleParser-NOTICE','jackson-core-2.19.2-jar/META-INF/thirdparty-LICENSE']) {
  assert(entries.has(base+path), `Missing ${path}`);
}
console.log('PASS: pinned runtime dependency notices preserved separately in test JAR.');
