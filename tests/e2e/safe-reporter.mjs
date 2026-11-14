// Assertion diagnostics can contain recovery kits or plaintext DOM snapshots.
export default class SafeReporter {
  onBegin(_config, suite) { this.total = suite.allTests().length; this.counts = {}; }
  onTestEnd(test, result) {
    this.counts[result.status] = (this.counts[result.status] || 0) + 1;
    console.log(`${result.status.toUpperCase()} [${test.parent.project()?.name}] ${test.title}`);
    for (const annotation of test.annotations.filter(value => ['safe-browser-counts', 'safe-phase', 'safe-focus'].includes(value.type))) console.log(annotation.description);
    for (const error of result.errors) {
      console.log('Failure details withheld to avoid secret-bearing diagnostics. Assertion locations:');
      console.log((error.stack || '').split('\n').filter(line => /^\s+at .*[/\\](specs[/\\]|fixture\.mjs)/.test(line)).join('\n'));
    }
  }
  onError() { console.error('HARNESS ERROR (details withheld to avoid secret-bearing diagnostics)'); }
  onEnd(result) { console.log(JSON.stringify({status: result.status, total: this.total, counts: this.counts})); }
}
