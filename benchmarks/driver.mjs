import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { performance } from 'node:perf_hooks';

// One outstanding request. Frame on LF only: U+2028/U+2029 are valid JSON text.
export class Driver {
  constructor(command, options, timeoutMs = 30_000) {
    this.timeoutMs = timeoutMs;
    this.nextId = 0;
    this.stderr = '';
    this.buffer = '';
    this.decoder = new StringDecoder('utf8');
    this.proc = spawn(command[0], command.slice(1), { ...options, stdio: ['pipe', 'pipe', 'pipe'] });
    this.closed = new Promise(resolve => this.proc.once('close', resolve));
    this.proc.stderr.on('data', b => { this.stderr = (this.stderr + b).slice(-2000); });
    this.proc.on('error', error => this.fail(error));
    this.proc.stdin.on('error', error => this.fail(error));
    this.proc.on('exit', code => this.fail(new Error(`Driver exited (${code}): ${this.stderr}`)));
    this.proc.stdout.on('data', b => {
      this.buffer += this.decoder.write(b);
      let end;
      while ((end = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, end);
        this.buffer = this.buffer.slice(end + 1);
        try {
          const response = JSON.parse(line);
          const pending = this.pending;
          if (!pending || response.id !== pending.id) throw new Error('Unexpected driver response ID');
          const ms = performance.now() - pending.start;
          clearTimeout(pending.timer);
          this.pending = null;
          if (response.ok !== true) pending.reject(new Error(`Driver error: ${response.error}`));
          else pending.resolve({ result: response.result, ms });
        } catch (error) { this.fail(error); }
      }
    });
  }
  fail(error) {
    this.error ??= error;
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(error);
      this.pending = null;
    }
  }
  call(op, input) {
    if (this.error) return Promise.reject(this.error);
    if (this.pending) throw new Error('Only one benchmark request may be in flight');
    const id = ++this.nextId;
    const request = JSON.stringify({ id, op, input }) + '\n';
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.fail(new Error(`Driver timed out after ${this.timeoutMs} ms`));
        this.proc.kill('SIGKILL');
      }, this.timeoutMs);
      this.pending = { id, resolve, reject, timer, start: performance.now() };
      this.proc.stdin.write(request);
    });
  }
  async close() {
    this.proc.stdin.end();
    const timer = setTimeout(() => this.proc.kill('SIGKILL'), 2000);
    await this.closed;
    clearTimeout(timer);
  }
}
