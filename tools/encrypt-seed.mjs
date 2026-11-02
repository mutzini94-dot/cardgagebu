// 카드 거래내역 CSV를 비밀번호로 암호화해 seed-data.enc.js를 만든다.
// 사용법: node tools/encrypt-seed.mjs <거래내역.csv>
// 비밀번호는 화면에 표시되지 않고, 어디에도 저장되지 않는다.
import { readFile, writeFile } from "node:fs/promises";
import { webcrypto as crypto } from "node:crypto";
import readline from "node:readline";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ITER = 600000;
const src = process.argv[2];
if (!src) { console.error("사용법: node tools/encrypt-seed.mjs <거래내역.csv>"); process.exit(1); }
const out = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "seed-data.enc.js");

function askHidden(q) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = s => { if (s.includes(q)) rl.output.write(q); else if (s.includes("\n") || s.includes("\r")) rl.output.write("\n"); else rl.output.write("*"); };
    rl.question(q, a => { rl.close(); resolve(a); });
  });
}

const csv = (await readFile(src, "utf8")).replace(/^﻿/, "");
const pw = await askHidden("가계부 비밀번호: ");
const pw2 = await askHidden("한 번 더 입력: ");
if (!pw || pw !== pw2) { console.error("비밀번호가 비어 있거나 서로 다릅니다."); process.exit(1); }

const te = new TextEncoder();
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey("raw", te.encode(pw), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(csv)));
const b64 = u8 => Buffer.from(u8).toString("base64");

await writeFile(out, `// 비밀번호로 암호화된 초기 거래 데이터 (AES-GCM, PBKDF2-SHA256 ${ITER}회)\nwindow.SEED_ENC = ${JSON.stringify({ v: 1, iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) })};\n`);
console.log(`암호화 완료: ${out} (${csv.split("\n").length - 2}건)`);
