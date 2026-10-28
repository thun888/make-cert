export interface Pkcs12Options {
  certPem: string;
  keyPem: string;
  chainPem?: string;
  password: string;
  friendlyName?: string;
}

function splitPemBlocks(text: string): string[] {
  return text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

/**
 * 打包 PKCS#12（.pfx/.p12）。node-forge 仅支持 RSA 私钥，
 * 因此 ECDSA 证书会抛出可读错误，引导用户改用 PEM。
 */
export async function createPkcs12(options: Pkcs12Options): Promise<Uint8Array> {
  const forgeModule = await import("node-forge");
  const forge = (forgeModule as unknown as { default?: typeof forgeModule }).default ?? forgeModule;

  let privateKey: ReturnType<typeof forge.pki.privateKeyFromPem>;
  try {
    privateKey = forge.pki.privateKeyFromPem(options.keyPem);
  } catch {
    throw new Error(
      "当前私钥不是 RSA 格式，PKCS#12 打包暂不支持 ECDSA。请使用 PEM 格式导出（nginx / Node / Go 均直接支持）。",
    );
  }

  const certificates = [options.certPem, ...splitPemBlocks(options.chainPem ?? "")].map((pem) =>
    forge.pki.certificateFromPem(pem),
  );

  const asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, certificates, options.password, {
    algorithm: "3des",
    friendlyName: options.friendlyName,
  });

  const der = forge.asn1.toDer(asn1).getBytes();
  const bytes = new Uint8Array(der.length);
  for (let i = 0; i < der.length; i += 1) {
    bytes[i] = der.charCodeAt(i);
  }
  return bytes;
}
