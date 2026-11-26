// Generates the PNG companions to docs/favicon.svg.
//
// WHY THIS IS A SCRIPT AND NOT A CHECKED-IN BINARY: a PNG with no source is a
// maintenance trap — nobody can change the artwork without a design tool, and
// nothing proves the shipped bytes match the shipped SVG. This renders the SAME
// artwork as docs/favicon.svg with no dependencies at all (Node's zlib is the
// only thing it needs), so `node scripts/make-favicon.mjs` reproduces the
// committed assets byte-for-byte and the icons can never silently drift apart.
//
// WHY A PNG EXISTS AT ALL: <link rel="apple-touch-icon"> is ignored when it
// points at an SVG — iOS wants a real raster. And it must be OPAQUE. iOS
// composites a transparent icon onto black before applying its own rounded mask,
// so shipping the rounded tile with transparent corners (exactly what the .svg
// is) produces a black halo around the artwork. So the touch icon is a
// FULL-BLEED opaque square and iOS does the rounding itself.

import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

// ── geometry ───────────────────────────────────────────────────────────────
// Lucide "zap", the same polygon the SVG uses. 24x24 user space.
const BOLT = [[13, 2], [3, 14], [12, 14], [11, 22], [21, 10], [12, 10]];

const INK = { r: 0x07, g: 0x10, b: 0x17 };        // #071017 brand tile
const GLOW = { r: 0x00, g: 0xff, b: 0x88 };       // #00ff88
const BOLT_A = { r: 0x2f, g: 0xff, b: 0xd2 };     // #2fffd2 gradient start
const BOLT_B = { r: 0x00, g: 0xff, b: 0x88 };     // gradient end
const STROKE = { r: 0x00, g: 0xff, b: 0x88 };

// ── raster helpers ─────────────────────────────────────────────────────────

/** Even-odd point-in-polygon. The zap polygon is simple (non-self-intersecting),
 *  so this is exact; no self-intersection handling is needed and none is faked. */
function inPolygon(px, py, pts) {
  let inside = false;
  for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
    const [xi, yi] = pts[i];
    const [xj, yj] = pts[j];
    if ((yi > py) !== (yj > py) && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

/** Signed distance to a rounded rectangle (negative = inside). */
function roundedRectSdf(px, py, x0, y0, x1, y1, r) {
  const cx = (x0 + x1) / 2;
  const cy = (y0 + y1) / 2;
  const hx = (x1 - x0) / 2 - r;
  const hy = (y1 - y0) / 2 - r;
  const qx = Math.abs(px - cx) - hx;
  const qy = Math.abs(py - cy) - hy;
  const outside = Math.hypot(Math.max(qx, 0), Math.max(qy, 0));
  return outside + Math.min(Math.max(qx, qy), 0) - r;
}

const clamp255 = (v) => (v < 0 ? 0 : v > 255 ? 255 : Math.round(v));
const mix = (a, b, t) => a + (b - a) * t;

// ── the render ─────────────────────────────────────────────────────────────

/**
 * @param {number} size output edge length in px
 * @returns {Buffer} raw RGB scanlines (3 bytes per pixel, no alpha — opaque)
 */
function renderIcon(size) {
  const u = size / 64; // the SVG's 64-unit viewBox maps onto this canvas

  // Full-bleed background with a soft green bloom near the upper centre, the
  // same radial glow the SVG carries (raised slightly so it reads at 180px).
  const glowCx = size * 0.5;
  const glowCy = size * 0.42;
  const glowR = size * 0.6;
  const glowPeak = 0.35;

  // Inner keyline. Deliberately inset well clear of the edge: iOS masks this
  // image with its own rounded corners, so a stroke at x=0 would be clipped.
  const inset = size * 0.055;
  const strokeHalf = Math.max(1, size * 0.011);

  // Bolt, sized off the shorter axis and centred on its own bounding box.
  const boltScale = (size * 0.545) / 20; // 20 = bolt height in user space
  const bcx = (Math.min(...BOLT.map((p) => p[0])) + Math.max(...BOLT.map((p) => p[0]))) / 2;
  const bcy = (Math.min(...BOLT.map((p) => p[1])) + Math.max(...BOLT.map((p) => p[1]))) / 2;
  const boltPts = BOLT.map(([x, y]) => [
    (x - bcx) * boltScale + size / 2,
    (y - bcy) * boltScale + size / 2,
  ]);
  const bMinX = Math.min(...boltPts.map((p) => p[0]));
  const bMaxX = Math.max(...boltPts.map((p) => p[0]));
  const bMinY = Math.min(...boltPts.map((p) => p[1]));
  const bMaxY = Math.max(...boltPts.map((p) => p[1]));

  const SS = 4; // 4x4 supersample — enough to keep the thin keyline clean
  const px = Buffer.alloc(size * size * 3);

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let boltHits = 0;
      let strokeHits = 0;

      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const fx = x + (sx + 0.5) / SS;
          const fy = y + (sy + 0.5) / SS;
          if (inPolygon(fx, fy, boltPts)) boltHits++;
          const d = roundedRectSdf(fx, fy, inset, inset, size - inset, size - inset, size * 0.19);
          if (Math.abs(d) <= strokeHalf) strokeHits++;
        }
      }

      const cx = x + 0.5;
      const cy = y + 0.5;

      // background + bloom
      const gt = Math.min(1, Math.hypot(cx - glowCx, cy - glowCy) / glowR);
      const bloom = (1 - gt) * (1 - gt) * glowPeak;
      let r = mix(INK.r, GLOW.r, bloom);
      let g = mix(INK.g, GLOW.g, bloom);
      let b = mix(INK.b, GLOW.b, bloom);

      // keyline
      const sa = strokeHits / (SS * SS);
      if (sa > 0) {
        const k = sa * 0.45; // same 0.45 opacity the SVG stroke uses
        r = mix(r, STROKE.r, k);
        g = mix(g, STROKE.g, k);
        b = mix(b, STROKE.b, k);
      }

      // bolt, with the SVG's diagonal two-stop gradient
      const ba = boltHits / (SS * SS);
      if (ba > 0) {
        const tx = (cx - bMinX) / Math.max(1, bMaxX - bMinX);
        const ty = (cy - bMinY) / Math.max(1, bMaxY - bMinY);
        const t = Math.min(1, Math.max(0, (tx + ty) / 2));
        const br = mix(BOLT_A.r, BOLT_B.r, t);
        const bg = mix(BOLT_A.g, BOLT_B.g, t);
        const bb = mix(BOLT_A.b, BOLT_B.b, t);
        r = mix(r, br, ba);
        g = mix(g, bg, ba);
        b = mix(b, bb, ba);
      }

      const o = (y * size + x) * 3;
      px[o] = clamp255(r);
      px[o + 1] = clamp255(g);
      px[o + 2] = clamp255(b);
    }
  }
  void u;
  return px;
}

// ── PNG encoding (colour type 2: truecolour, 8-bit, no alpha) ─────────────

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function encodePng(rgb, size) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // colour type 2 = truecolour RGB
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  // Each scanline is prefixed with filter byte 0 (None). The image is a smooth
  // gradient, so Paeth would compress a little better, but None keeps this
  // encoder readable and the file is ~5 KB either way.
  const stride = size * 3;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (stride + 1)] = 0;
    rgb.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }

  return Buffer.concat([
    sig,
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// ── emit ───────────────────────────────────────────────────────────────────

// The output directory is overridable so the reproducibility TEST can render
// into a scratch directory and compare against the committed bytes. It must
// never write into docs/ during a test run: these assets are only ever
// referenced from <link> tags, so a concurrent reader can observe a
// half-written icon and nothing would report it. Writing the real files is what
// `node scripts/make-favicon.mjs` (no args) is for.
const OUT_DIR = process.argv[2] || 'docs';
mkdirSync(OUT_DIR, { recursive: true });

const OUTS = [
  { file: 'apple-touch-icon.png', size: 180 },
  { file: 'icon-512.png', size: 512 },
];

for (const { file, size } of OUTS) {
  const png = encodePng(renderIcon(size), size);
  const dest = join(OUT_DIR, file);
  writeFileSync(dest, png);
  console.log(`${dest}  ${size}x${size}  ${png.length} bytes`);
}
