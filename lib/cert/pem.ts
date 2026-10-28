export function bytesToBase64(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  const chunk = 0x8000;
  for (let offset = 0; offset < view.length; offset += chunk) {
    const slice = view.subarray(offset, offset + chunk);
    binary += String.fromCharCode.apply(null, slice as unknown as number[]);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64.replace(/\s+/g, ""));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function derToPem(der: ArrayBuffer | Uint8Array, label: string): string {
  const base64 = bytesToBase64(der);
  const lines = base64.match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

/** 从任意包含 PEM 的文本中提取第一个指定类型的块。 */
export function extractPem(text: string, label?: string): string | null {
  const pattern = label
    ? new RegExp(`-----BEGIN ${label}-----[\\s\\S]*?-----END ${label}-----`)
    : /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/;
  const match = text.match(pattern);
  return match ? `${match[0]}\n` : null;
}

export function pemToDer(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  return base64ToBytes(body);
}

export function toHex(bytes: ArrayBuffer | Uint8Array, separator = ":"): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Array.from(view)
    .map((byte) => byte.toString(16).padStart(2, "0").toUpperCase())
    .join(separator);
}

export function randomSerialNumber(byteLength = 16): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  // 最高位清零，保证序列号为正整数
  bytes[0] &= 0x7f;
  if (bytes[0] === 0) bytes[0] = 0x01;
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function formatDate(value: Date): string {
  const pad = (input: number) => String(input).padStart(2, "0");
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())} ${pad(
    value.getHours(),
  )}:${pad(value.getMinutes())}`;
}
