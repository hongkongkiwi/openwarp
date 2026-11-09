'use strict';

// Measures WCAG contrast for the theme tokens embedded in the console.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../src/ui.rs'), 'utf8');
function tokens(selector) {
  const start = source.indexOf(selector + '{');
  assert.ok(start >= 0, `${selector} block is present`);
  const body = source.slice(start + selector.length + 1, source.indexOf('}', start));
  return Object.fromEntries([...body.matchAll(/--([\w-]+):([^;]+);/g)].map(m => [m[1], m[2].trim()]));
}
const themes = { light: tokens(':root'), dark: tokens(':root[data-theme=dark]') };
function channel(v) { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }
function luminance(hex) {
  const h = hex.replace('#', '');
  const full = h.length === 3 ? [...h].map(c => c + c).join('') : h;
  const [r, g, b] = [0, 2, 4].map(i => channel(parseInt(full.slice(i, i + 2), 16)));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function ratio(foreground, background) {
  const [a, b] = [luminance(foreground), luminance(background)].sort((x, y) => y - x);
  return (a + 0.05) / (b + 0.05);
}
const pairs = [
  ['text', 'bg', 4.5], ['text', 'panel', 4.5], ['muted', 'panel', 4.5], ['faint', 'panel', 4.5],
  ['acc2', 'panel', 4.5], ['on-acc', 'acc', 4.5], ['bad', 'panel', 4.5], ['ok', 'panel', 4.5],
  ['warn', 'panel', 4.5], ['muted', 'bg2', 4.5], ['faint', 'bg2', 4.5], ['bad', 'bg2', 4.5],
  ['ok', 'bg2', 4.5], ['warn', 'bg2', 4.5],
];
for (const [theme, values] of Object.entries(themes)) {
  test(`${theme} theme text pairs meet WCAG AA contrast`, () => {
    for (const [fg, bg, minimum] of pairs) {
      const measured = ratio(values[fg], values[bg]);
      assert.ok(measured >= minimum, `${theme}: --${fg} on --${bg} is ${measured.toFixed(2)}:1, needs ${minimum}:1`);
    }
  });
}
