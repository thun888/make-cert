import "reflect-metadata";
import * as x509 from "@peculiar/x509";

export type SignatureState = "valid" | "invalid" | "unknown";

export interface ChainNode {
  subject: string;
  issuer: string;
  isCa: boolean;
  selfSigned: boolean;
  notBefore: Date;
  notAfter: Date;
  signatureState: SignatureState;
  akiMatched: boolean | null;
  note?: string;
}

export interface ChainIssue {
  level: "error" | "warn" | "info";
  title: string;
  detail?: string;
}

export interface ChainReport {
  nodes: ChainNode[];
  issues: ChainIssue[];
  complete: boolean;
  ignoredCount: number;
}

export function splitCertificates(text: string): string[] {
  return text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

/**
 * 从叶子证书向上逐级拼接证书链。
 * 输入顺序无关，第一张作为起点（通常是站点证书）。
 */
export async function analyzeChain(pems: string[], now: number): Promise<ChainReport> {
  if (pems.length === 0) {
    throw new Error("没有找到 PEM 证书块。");
  }

  const certificates = pems.map((pem) => new x509.X509Certificate(pem));
  const [leaf, ...pool] = certificates;
  const used = new Set<number>();
  const nodes: ChainNode[] = [];
  const issues: ChainIssue[] = [];
  let complete = false;
  let current: x509.X509Certificate = leaf;

  for (let depth = 0; depth < 8; depth += 1) {
    const selfSigned = current.subject === current.issuer;
    const basic = current.getExtension(x509.BasicConstraintsExtension);
    const node: ChainNode = {
      subject: current.subject,
      issuer: current.issuer,
      isCa: basic?.ca ?? false,
      selfSigned,
      notBefore: current.notBefore,
      notAfter: current.notAfter,
      signatureState: "unknown",
      akiMatched: null,
    };

    if (selfSigned) {
      let ok = false;
      try {
        ok = (await current.verify({ publicKey: current.publicKey })) !== false;
      } catch {
        ok = false;
      }
      nodes.push({ ...node, signatureState: ok ? "valid" : "invalid" });
      if (!ok) {
        issues.push({
          level: "error",
          title: `自签名证书的签名无法自证：${current.subject}`,
          detail: "说明证书内容被改动过，或者 DER 编码损坏。",
        });
      }
      complete = true;
      issues.push({
        level: "warn",
        title: "链的顶端是一张自签名证书",
        detail: "它能自证签名，但只有把它装进系统/浏览器信任库，客户端才会认为这条链可信。",
      });
      break;
    }

    const issuerIndex = pool.findIndex(
      (candidate, index) => !used.has(index) && candidate.subject === current.issuer,
    );

    if (issuerIndex === -1) {
      nodes.push({ ...node, signatureState: "unknown", note: "缺少签发者" });
      issues.push({
        level: "error",
        title: `证书链不完整：缺少签发者 ${current.issuer}`,
        detail:
          "客户端会报 “unable to verify the first certificate / 证书链不完整”。需要把中间证书（或根证书）一起下发。",
      });
      break;
    }

    used.add(issuerIndex);
    const issuer = pool[issuerIndex];

    let valid = false;
    try {
      valid = (await current.verify({ publicKey: issuer.publicKey })) !== false;
    } catch {
      valid = false;
    }

    const aki = current.getExtension(x509.AuthorityKeyIdentifierExtension);
    const ski = issuer.getExtension(x509.SubjectKeyIdentifierExtension);
    const akiMatched =
      aki?.keyId && ski?.keyId ? aki.keyId.toLowerCase() === ski.keyId.toLowerCase() : null;

    nodes.push({
      ...node,
      signatureState: valid ? "valid" : "invalid",
      akiMatched,
      note: valid ? undefined : "签名不匹配",
    });

    if (!valid) {
      issues.push({
        level: "error",
        title: "签名校验失败",
        detail: `无法用「${issuer.subject}」的公钥验证「${current.subject}」的签名，可能是填错了签发者，或证书被改动过。`,
      });
      break;
    }

    if (akiMatched === false) {
      issues.push({
        level: "warn",
        title: "AKI 与签发者 SKI 不一致",
        detail: "同名 CA 轮换过密钥时会出现。签名能过就说明签发关系成立，但部分老客户端会因此挑错链。",
      });
    }

    const issuerBasic = issuer.getExtension(x509.BasicConstraintsExtension);
    if (!(issuerBasic?.ca ?? false)) {
      issues.push({
        level: "warn",
        title: "签发者不是 CA 证书",
        detail: "BasicConstraints 为 CA:FALSE 的证书不能签发其它证书，浏览器会拒绝整条链。",
      });
    }

    current = issuer;
  }

  for (const node of nodes) {
    if (node.notAfter.getTime() < now) {
      issues.push({ level: "error", title: `已过期：${node.subject}` });
    } else if (node.notBefore.getTime() > now) {
      issues.push({ level: "warn", title: `尚未生效：${node.subject}` });
    }
  }

  const ignoredCount = pool.length - used.size;

  if (ignoredCount > 0) {
    issues.push({
      level: "info",
      title: `有 ${ignoredCount} 张证书未参与链构建`,
      detail: "它们与被分析的证书没有签发关系，常见的是一起打包的无关证书。",
    });
  }

  return { nodes, issues, complete, ignoredCount };
}
