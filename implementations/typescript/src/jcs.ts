/**
 * RFC 8785 JSON Canonicalization Scheme.
 *
 * ECMAScript's JSON.stringify already implements the RFC's number and string
 * serialisation, and the default sort compares UTF-16 code units, which is the
 * order RFC 8785 requires for object keys.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JCS: non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const members = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k]));
    return "{" + members.join(",") + "}";
  }
  throw new Error(`JCS: unsupported type ${typeof value}`);
}
