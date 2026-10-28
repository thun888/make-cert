import type { CheckItem, IssueRequest, SanEntry } from "./types";

export function isIpAddress(value: string): boolean {
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = value.match(ipv4);
  if (match) {
    return match.slice(1).every((part) => Number(part) >= 0 && Number(part) <= 255);
  }
  if (value.includes(":")) {
    try {
      new URL(`http://[${value}]`);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

export function validateSanEntry(entry: SanEntry): string | null {
  const value = entry.value.trim();
  if (!value) return "值为空";
  if (entry.type === "ip") {
    return isIpAddress(value) ? null : "不是合法的 IP 地址";
  }
  if (entry.type === "email") {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? null : "不是合法的邮箱地址";
  }
  if (entry.type === "url") {
    try {
      new URL(value);
      return null;
    } catch {
      return "不是合法的 URI";
    }
  }
  if (/\s/.test(value)) return "域名不能包含空格";
  if (value.length > 253) return "域名过长";
  if (value.includes("*")) {
    if (!/^\*\.[^.*]+\.[^.*]+$/.test(value)) {
      return "通配符只能出现在最左侧标签，且形如 *.example.com";
    }
  }
  return null;
}

/** 生成默认 SAN：从 CN 推导。 */
export function defaultSans(commonName: string): SanEntry[] {
  const value = commonName.trim() || "localhost";
  const type = isIpAddress(value) ? "ip" : "dns";
  return [{ id: "san-primary", type: value.includes(":") ? "ip" : type, value }];
}

const PUBLIC_TLS_MAX_DAYS = 200;

export function validateRequest(request: IssueRequest): CheckItem[] {
  const checks: CheckItem[] = [];
  const sans = request.sans.filter((entry) => entry.value.trim().length > 0);
  const isCa = request.mode === "ca";

  if (isCa) {
    if (request.days < 365) {
      checks.push({
        level: "warn",
        title: "根 CA 有效期偏短",
        detail: "根 CA 通常签 10 年。它过期后，所有由它签发的证书都需要重新签发。",
      });
    }
  } else if (sans.length === 0) {
    checks.push({
      level: "error",
      title: "缺少 SAN（主题备用名称）",
      detail:
        "自 2017 年起主流浏览器不再读取 CN，没有 SAN 的证书会被直接判定为无效。请至少填写一个域名或 IP。",
    });
  }

  for (const entry of isCa ? [] : sans) {
    const error = validateSanEntry(entry);
    if (error) {
      checks.push({
        level: "error",
        title: `SAN 条目不合法：${entry.value || "(空)"}`,
        detail: error,
      });
    }
  }

  const cn = request.subject.commonName.trim();
  if (!cn) {
    checks.push({
      level: "warn",
      title: "CN 为空",
      detail: "CN 仅用于显示与兼容旧客户端，但留空会让部分工具显示异常，建议填写主域名。",
    });
  } else if (cn.length > 64) {
    checks.push({ level: "error", title: "CN 超过 64 个字符", detail: "X.509 规定 CN 上限为 64。" });
  } else if (!isCa && !sans.some((entry) => entry.value.trim().toLowerCase() === cn.toLowerCase())) {
    checks.push({
      level: "warn",
      title: "CN 未出现在 SAN 中",
      detail: "浏览器只看 SAN。若 CN 是主域名，请同步加入 SAN，否则访问该域名仍然报错。",
    });
  }

  if (request.subject.country && !/^[A-Za-z]{2}$/.test(request.subject.country.trim())) {
    checks.push({ level: "error", title: "国家代码必须是两位字母", detail: "例如 CN、US、JP。" });
  }

  if (request.days <= 0) {
    checks.push({ level: "error", title: "有效期必须大于 0 天" });
  } else if (request.days > 825) {
    checks.push({
      level: "warn",
      title: `有效期 ${request.days} 天偏长`,
      detail: "私钥泄露后的暴露窗口会随之拉长。根 CA 可以长一些，站点证书建议不超过 397 天。",
    });
  } else if (request.days > PUBLIC_TLS_MAX_DAYS && request.mode !== "ca") {
    checks.push({
      level: "info",
      title: `超过公信证书的 ${PUBLIC_TLS_MAX_DAYS} 天上限`,
      detail:
        "自签名证书不受 CA/B 论坛限制，可以正常使用；但公信证书自 2026-03-15 起最长只能签 200 天（2027 年降到 100 天，2029 年 47 天）。",
    });
  }

  const wildcardCount = sans.filter((entry) => entry.value.includes("*")).length;
  if (!isCa && wildcardCount > 0 && sans.length > 1) {
    checks.push({
      level: "info",
      title: "同时包含通配符与具体域名",
      detail: "通配符 *.example.com 不覆盖 example.com 本身，二者需要分别写入 SAN。",
    });
  }

  if (request.mode === "leaf" && (!request.caCertPem?.trim() || !request.caKeyPem?.trim())) {
    checks.push({
      level: "error",
      title: "缺少签发用的 CA",
      detail: "请先在「根 CA」标签生成一个 CA，或粘贴已有的 CA 证书与私钥。",
    });
  }

  if (request.mode !== "ca" && request.algorithm.startsWith("ec")) {
    checks.push({
      level: "info",
      title: "ECDSA 密钥的 KeyUsage 不含 keyEncipherment",
      detail: "EC 密钥不做 RSA 密钥交换，已自动改为 digitalSignature；TLS 1.2 的纯 RSA 套件将不可用。",
    });
  }

  if (checks.every((item) => item.level !== "error")) {
    checks.unshift({
      level: "info",
      title: "结构检查通过",
      detail: "证书扩展、SAN 与有效期均符合预期，可以生成。",
    });
  }

  return checks;
}
