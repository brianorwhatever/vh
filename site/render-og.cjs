// Regenerate the committed social image from og.html and the implementation list.
// Requires @napi-rs/canvas (rendering only; the Pages build has no new dependency).
// Run from the repository root: node site/render-og.cjs
const fs = require('node:fs');
const path = require('node:path');
const { createCanvas, GlobalFonts } = require('@napi-rs/canvas');
const count = JSON.parse(fs.readFileSync(path.join(__dirname, '../implementations.json'))).implementations.length;
const sourcePath = path.join(__dirname, 'og.html');
const html = fs.readFileSync(sourcePath, 'utf8').replace(/in (?:ten|\d+) languages/, `in ${count} languages`);
fs.writeFileSync(sourcePath, html);
for (const [file, family] of [['newsreader-var', 'Newsreader'], ['newsreader-var-italic', 'Newsreader Italic'], ['commit-mono-400', 'Commit Mono']]) {
  if (!GlobalFonts.registerFromPath(path.join(__dirname, `fonts/${file}.woff2`), family)) throw new Error(`Cannot load ${file}`);
}
const canvas = createCanvas(1200, 630), ctx = canvas.getContext('2d');
const ink = '#1c1823', rule = '#d2cfd8', highlight = '#fae0ff', accent = '#a800b6';
ctx.fillStyle = '#faf9fd'; ctx.fillRect(0, 0, 1200, 630);
ctx.fillStyle = ink; ctx.font = '190px Newsreader'; ctx.fillText('vh', 56, 280);
ctx.font = '38px Newsreader';
const headline = `VH-Log in ${count} languages that produce the same bytes.`;
let line = '', y = 371;
for (const word of headline.split(' ')) {
  if (line && ctx.measureText(line + ' ' + word).width > 410) { ctx.fillText(line, 56, y); y += 42.56; line = word; }
  else line += (line ? ' ' : '') + word;
}
ctx.fillText(line, 56, y);
const decode = s => s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
const rows = [...html.matchAll(/<div class="staff"><i>(.*?)<\/i><code>(.*?)<\/code><\/div>/g)];
const rowHeight = 34, top = (630 - rows.length * rowHeight) / 2;
ctx.strokeStyle = ink; ctx.lineWidth = 3; ctx.beginPath(); ctx.moveTo(521, top); ctx.lineTo(521, top + rows.length * rowHeight); ctx.stroke();
ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(519, top-4); ctx.bezierCurveTo(510, top-4, 509, top+2, 509, top+9); ctx.lineTo(509, top+rows.length*rowHeight-9); ctx.bezierCurveTo(509, top+rows.length*rowHeight-2,510,top+rows.length*rowHeight+4,519,top+rows.length*rowHeight+4); ctx.stroke();
rows.forEach(([, name, code], i) => {
  const baseline = top + i * rowHeight + 23;
  ctx.strokeStyle = rule; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(522, top + i * rowHeight + .5); ctx.lineTo(1144, top + i * rowHeight + .5); ctx.stroke();
  ctx.fillStyle = ink; ctx.font = '21px "Newsreader Italic"'; ctx.fillText(decode(name), 538, baseline);
  ctx.save(); ctx.beginPath(); ctx.rect(669, top+i*rowHeight, 475, rowHeight); ctx.clip();
  ctx.font = '15px "Commit Mono"'; let x = 669;
  for (const part of code.split(/(<mark>.*?<\/mark>)/g).filter(Boolean)) {
    const marked = part.startsWith('<mark>'), text = decode(part.replace(/<\/?mark>/g, ''));
    const width = ctx.measureText(text).width;
    if (marked) {ctx.fillStyle = highlight; ctx.fillRect(x-2, baseline-16, width+4, 22);}
    ctx.fillStyle = marked ? accent : ink; ctx.fillText(text, x, baseline); x += width;
  }
  ctx.restore();
});
ctx.strokeStyle = rule; ctx.beginPath(); ctx.moveTo(522, top+rows.length*rowHeight+.5); ctx.lineTo(1144, top+rows.length*rowHeight+.5); ctx.stroke();
fs.writeFileSync(path.join(__dirname, 'og.png'), canvas.toBuffer('image/png'));
console.log(`Rendered 1200×630 preview for ${count} languages.`);
