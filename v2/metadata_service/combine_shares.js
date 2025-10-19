// /app/combine_shares.js
const fs = require('fs');
// --- MODIFICATION: Use the actual library ---
const { combine } = require('shamirs-secret-sharing');

function detectXOffset(buffers){
  if (!buffers.length) return 0;
  const shareLen = buffers[0].length;
  // Scan only the first few bytes to avoid false positives on random data
  const scanLimit = Math.min(8, shareLen - 1);
  let best = 0, score = 0;
  for(let off = 0; off < scanLimit; off++){
    const uniq = new Set(buffers.map(b => b[off])).size;
    if(uniq > score){ score = uniq; best = off; }
  }
  return best;
}

function main(){
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const k = input.k || 2;
  const raws = input.shares.map(s => Buffer.from(s, 'base64'));
  if (raws.length < k) throw new Error(`Not enough shares provided: got ${raws.length}, need ${k}`);

  // The logic to detect x and normalize is still valid and important
  const xOff = detectXOffset(raws);
  
  const byX = new Map();
  for (const b of raws) {
    if (b.length < xOff + 1) continue;
    const x = b[xOff];
    // The library expects the full raw share buffer
    if (!byX.has(x)) byX.set(x, b);
  }

  const canonical = Array.from(byX.values());
  if (canonical.length < k) {
      throw new Error(`Not enough unique shares after normalization: got ${canonical.length}, need ${k}`);
  }

  // --- MODIFICATION: Call the library's combine function ---
  const combined = combine(canonical.slice(0, k));
  process.stdout.write(JSON.stringify({ ciphertextB64: Buffer.from(combined).toString('base64') }));
}

try {
  main();
} catch (e) {
  // Write errors to stderr so Python can capture them
  process.stderr.write(JSON.stringify({ error: e.message || String(e) }));
  process.exit(1);
}