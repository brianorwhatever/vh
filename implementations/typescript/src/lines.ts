import type { Readable } from "node:stream";

/**
 * Yields `\n`-terminated lines. Unlike node:readline this does not also split on
 * `\r`, U+2028 or U+2029, which can appear unescaped inside JSON strings.
 */
export async function* lines(stream: Readable): AsyncGenerator<string> {
  let buffer = "";
  stream.setEncoding("utf8");
  for await (const chunk of stream) {
    buffer += chunk;
    let i: number;
    while ((i = buffer.indexOf("\n")) !== -1) {
      yield buffer.slice(0, i);
      buffer = buffer.slice(i + 1);
    }
  }
  if (buffer !== "") yield buffer;
}
