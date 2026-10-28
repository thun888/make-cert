import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { extractPem } from "./pem";
import { sha256Fingerprint } from "./parse";
import { importCaPrivateKey, signAlgorithmForPublicKey } from "./issue";

const KEY_LABELS = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];

export interface CaBundle {
  certPem?: string;
  keyPem?: string;
  subject?: string;
  notAfter?: Date;
  isCa?: boolean;
  sha256?: string;
  keyMatchesCert?: boolean | null;
  notes: string[];
}

export function splitPemMaterials(text: string): { certPems: string[]; keyPem?: string } {
  const certPems = (text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []).map(
    (block) => `${block}\n`,
  );
  let keyPem: string | undefined;
  for (const label of KEY_LABELS) {
    const found = extractPem(text, label);
    if (found) {
      keyPem = found;
      break;
    }
  }
  return { certPems, keyPem };
}

/**
 * 读取一段 PEM 内容里的 CA 材料：可以是包含证书+私钥的单个文件，
 * 也可以是分开的两份。会顺带验证私钥与证书是否配对。
 */
export async function describeCaBundle(text: string, preferredKeyPem?: string): Promise<CaBundle> {
  const { certPems, keyPem: foundKey } = splitPemMaterials(text);
  const keyPem = foundKey ?? preferredKeyPem;
  const notes: string[] = [];

  if (certPems.length === 0 && !keyPem) {
    return { notes: ["没有在文件里找到 PEM 证书或私钥。"] };
  }

  const candidates: Array<{ bundle: CaBundle; score: number }> = [];

  for (const certPem of certPems) {
    let certificate: x509.X509Certificate;
    try {
      certificate = new x509.X509Certificate(certPem);
    } catch {
      notes.push("跳过一段无法解析的证书内容。");
      continue;
    }

    const basic = certificate.getExtension(x509.BasicConstraintsExtension);
    const bundle: CaBundle = {
      certPem,
      keyPem,
      subject: certificate.subject,
      notAfter: certificate.notAfter,
      isCa: basic?.ca ?? false,
      sha256: await sha256Fingerprint(certificate.rawData),
      keyMatchesCert: null,
      notes: [],
    };

    if (keyPem) {
      try {
        const privateKey = await importCaPrivateKey(keyPem, certificate);
        const algorithm = signAlgorithmForPublicKey(certificate.publicKey as unknown as CryptoKey);
        const probe = new TextEncoder().encode("make-cert:key-pair-check");
        const signature = await crypto.subtle.sign(algorithm, privateKey, probe);
        const publicKey = await certificate.publicKey.export();
        bundle.keyMatchesCert = await crypto.subtle.verify(algorithm, publicKey, signature, probe);
      } catch {
        bundle.keyMatchesCert = false;
      }
    }

    // 优先选「CA:TRUE 且私钥配对」的那一张
    const score = (bundle.isCa ? 2 : 0) + (bundle.keyMatchesCert ? 1 : 0);
    candidates.push({ bundle, score });
  }

  if (candidates.length === 0) {
    return { keyPem, notes: [...notes, "文件里有私钥，但没有找到可用的证书。"] };
  }

  candidates.sort((a, b) => b.score - a.score);
  const best = candidates[0].bundle;
  best.notes = [...notes, ...best.notes];

  if (candidates.length > 1) {
    best.notes.push(`文件里含 ${candidates.length} 张证书，已选用最匹配的一张。`);
  }
  if (keyPem && best.keyMatchesCert === false) {
    best.notes.push("这段私钥与该证书不配对，签发出来的证书链会校验失败。");
  }
  if (keyPem && best.keyMatchesCert === null) {
    best.notes.push("私钥格式无法在当前浏览器中预检，请在签发后确认链路。");
  }

  return best;
}

function toBinaryString(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(offset, offset + chunk) as unknown as number[]);
  }
  return binary;
}

/** 解开 PKCS#12（.pfx/.p12），返回其中的证书与私钥 PEM。 */
export async function readPkcs12(
  bytes: Uint8Array,
  password: string,
): Promise<{ certPems: string[]; keyPem?: string }> {
  const forgeModule = await import("node-forge");
  const forge = (forgeModule as unknown as { default?: typeof forgeModule }).default ?? forgeModule;

  let p12: ReturnType<typeof forge.pkcs12.pkcs12FromAsn1>;
  try {
    const buffer = forge.util.createBuffer(toBinaryString(bytes));
    p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(buffer), password);
  } catch {
    throw new Error("无法打开这个 PKCS#12 文件：口令错误，或文件已损坏。");
  }

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] ?? [];
  const certPems = certBags
    .map((bag) => (bag.cert ? forge.pki.certificateToPem(bag.cert) : null))
    .filter((pem): pem is string => Boolean(pem));

  const shrouded = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
    forge.pki.oids.pkcs8ShroudedKeyBag
  ];
  const plain = p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag];
  const keyBag = [...(shrouded ?? []), ...(plain ?? [])].find((bag) => bag.key);

  const keyPem = keyBag?.key ? forge.pki.privateKeyToPem(keyBag.key) : undefined;

  return { certPems, keyPem };
}
