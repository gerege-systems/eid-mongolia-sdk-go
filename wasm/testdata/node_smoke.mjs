// Node smoke: буруу оролтын дараа runtime амьд хэвээр (panic-гүй), дахин дуудахад ажиллана.
// node node_smoke.mjs <wasm_exec.js> <eidpades.wasm> <pdf>
import fs from "node:fs";
import { createRequire } from "node:module";
const [execJS, wasmPath, pdfPath] = process.argv.slice(2);
createRequire(import.meta.url)(execJS);
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(fs.readFileSync(wasmPath), go.importObject);
go.run(instance);
const p = globalThis.eidPades;
const fail = (m) => { console.error("FAIL", m); process.exit(1); };
for (let i = 0; i < 2; i++) {
  const r = p.prepare(new Uint8Array([1]), {});
  if (!r.error || r.error.code !== "PDF_INVALID") fail("prepare #" + i + ": " + JSON.stringify(r));
}
const pdf = new Uint8Array(fs.readFileSync(pdfPath));
const r2 = p.prepare(pdf, {});
if (!r2.error || r2.error.code !== "SIGNER_INVALID") fail("prepare signer: " + JSON.stringify(r2));
const r3 = p.prepare(pdf, { bogus: 1 });
if (!r3.error || r3.error.code !== "REQUEST_INVALID") fail("prepare opts: " + JSON.stringify(r3));
const v = p.verify(pdf, {});
if (v.error || v.indication !== "valid" || v.signatures.length !== 0) fail("verify: " + JSON.stringify(v));
const v2 = p.verify(new Uint8Array([1, 2]), {});
if (!v2.error) fail("verify bad: " + JSON.stringify(v2));
try {
  await p.complete(new Uint8Array([1]), new Uint8Array([2]), {});
  fail("complete resolved");
} catch (e) {
  if (e.code !== "STATE_INVALID") fail("complete: " + e.code);
}
if (p.version !== "pades-client/1") fail("version");
console.log("OK");
process.exit(0);
