"use client";

import { useRef, useState } from "react";
import { parseCertificate, type ParsedCertificate } from "@/lib/cert/parse";
import { analyzeChain, splitCertificates, type ChainReport } from "@/lib/cert/chain";
import { formatDate } from "@/lib/cert/pem";
import { Badge, Button, Card, CardHeader, Textarea } from "./ui";

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] text-zinc-400">{label}</span>
      <span className={`text-xs break-all text-zinc-700 ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  );
}

const ISSUE_DOT: Record<string, string> = {
  error: "bg-rose-500",
  warn: "bg-amber-500",
  info: "bg-zinc-300",
};

function ChainView({ report }: { report: ChainReport }) {
  return (
    <div className="space-y-3 border-t border-zinc-100 pt-4">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-medium text-zinc-900">证书链分析</h3>
        <Badge tone={report.complete ? "success" : "danger"}>
          {report.complete ? `完整 · ${report.nodes.length} 级` : "不完整"}
        </Badge>
      </div>

      <ol className="space-y-1">
        {report.nodes.map((node, index) => (
          <li key={`${node.subject}-${index}`} className="flex items-start gap-3">
            <div className="flex flex-col items-center">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-zinc-100 text-[10px] font-medium text-zinc-500">
                {index + 1}
              </span>
              {index < report.nodes.length - 1 ? <span className="h-6 w-px bg-zinc-200" /> : null}
            </div>
            <div className="min-w-0 flex-1 pb-1">
              <p className="truncate font-mono text-[11px] text-zinc-700">{node.subject}</p>
              <div className="mt-1 flex flex-wrap items-center gap-1">
                {index === 0 ? <Badge tone="info">叶子</Badge> : null}
                {node.isCa ? <Badge>CA</Badge> : null}
                {node.selfSigned ? <Badge>自签名顶端</Badge> : null}
                <Badge
                  tone={
                    node.signatureState === "valid"
                      ? "success"
                      : node.signatureState === "invalid"
                        ? "danger"
                        : "neutral"
                  }
                >
                  {node.signatureState === "valid"
                    ? "签名有效"
                    : node.signatureState === "invalid"
                      ? "签名无效"
                      : "未校验"}
                </Badge>
                {node.akiMatched === false ? <Badge tone="warn">AKI 不匹配</Badge> : null}
                {node.signatureState === "unknown" && node.note ? (
                  <span className="text-[11px] text-rose-600">{node.note}</span>
                ) : null}
                <span className="text-[11px] text-zinc-400">至 {formatDate(node.notAfter)}</span>
              </div>
            </div>
          </li>
        ))}
      </ol>

      <ul className="space-y-1.5">
        {report.issues.map((issue, index) => (
          <li key={`${issue.title}-${index}`} className="flex gap-2">
            <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${ISSUE_DOT[issue.level]}`} />
            <div>
              <p className="text-xs text-zinc-700">{issue.title}</p>
              {issue.detail ? (
                <p className="mt-0.5 text-[11px] leading-relaxed text-zinc-400">{issue.detail}</p>
              ) : null}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function Inspector() {
  const [input, setInput] = useState("");
  const [parsed, setParsed] = useState<ParsedCertificate | null>(null);
  const [parsedAt, setParsedAt] = useState(0);
  const [chain, setChain] = useState<ChainReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const reset = () => {
    setInput("");
    setParsed(null);
    setChain(null);
    setError(null);
  };

  const inspect = async (text: string) => {
    setError(null);
    setParsed(null);
    setChain(null);

    const blocks = splitCertificates(text);
    if (blocks.length === 0) {
      setError("没有找到 PEM 证书块（需要以 -----BEGIN CERTIFICATE----- 开头）。");
      return;
    }

    try {
      const info = await parseCertificate(blocks[0]);
      const now = Date.now();
      setParsed(info);
      setParsedAt(now);
      setChain(await analyzeChain(blocks, now));
    } catch {
      setError("证书解析失败，请确认内容完整且未被截断。");
    }
  };

  const readFile = async (file: File) => {
    const text = await file.text();
    setInput(text);
    await inspect(text);
  };

  const total = parsed ? parsed.notAfter.getTime() - parsed.notBefore.getTime() : 0;
  const remaining = parsed ? Math.max(0, parsed.notAfter.getTime() - parsedAt) : 0;
  const percent = total > 0 ? Math.min(100, Math.max(0, (remaining / total) * 100)) : 0;
  const expired = parsed ? parsed.daysLeft <= 0 : false;

  return (
    <Card>
      <CardHeader
        title="证书解析与链校验"
        description="拖入或粘贴一张或多张 PEM 证书。解析叶子证书的字段，并向上逐级验证签发关系、定位缺失的中间证书。"
        aside={
          <Button variant="ghost" onClick={() => fileRef.current?.click()}>
            选择文件
          </Button>
        }
      />
      <input
        ref={fileRef}
        type="file"
        accept=".crt,.pem,.cer,.cert,.chain,text/plain"
        className="hidden"
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) void readFile(file);
        }}
      />

      <div
        className={`grid gap-4 px-5 py-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] ${
          dragging ? "rounded-xl bg-zinc-50" : ""
        }`}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          const file = event.dataTransfer.files?.[0];
          if (file) void readFile(file);
        }}
      >
        <div className="space-y-2">
          <Textarea
            rows={12}
            value={input}
            placeholder={"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n\n（可继续粘贴中间证书）"}
            onChange={(event) => setInput(event.target.value)}
          />
          <div className="flex items-center gap-2">
            <Button variant="primary" onClick={() => void inspect(input)}>
              解析
            </Button>
            <Button variant="ghost" onClick={reset}>
              清空
            </Button>
            {error ? <span className="text-[11px] text-rose-600">{error}</span> : null}
          </div>
        </div>

        <div className="rounded-xl border border-zinc-100 bg-zinc-50/60 p-4">
          {parsed ? (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-1.5">
                {parsed.isSelfSigned ? <Badge tone="info">自签名</Badge> : <Badge>CA 签发</Badge>}
                {parsed.isCa ? <Badge tone="warn">CA 证书</Badge> : null}
                <Badge tone={expired ? "danger" : parsed.daysLeft < 30 ? "warn" : "success"}>
                  {expired ? "已过期" : `剩余 ${parsed.daysLeft} 天`}
                </Badge>
                <Badge>{parsed.keyDescription}</Badge>
              </div>

              <div className="h-1.5 overflow-hidden rounded-full bg-zinc-200">
                <div
                  className={`h-full rounded-full ${expired ? "bg-rose-400" : percent < 15 ? "bg-amber-400" : "bg-emerald-500"}`}
                  style={{ width: `${Math.max(2, percent)}%` }}
                />
              </div>

              <div className="grid grid-cols-2 gap-x-4 gap-y-3">
                <Row label="主体" value={parsed.subject} />
                <Row label="签发者" value={parsed.issuer} />
                <Row label="生效时间" value={formatDate(parsed.notBefore)} />
                <Row label="到期时间" value={formatDate(parsed.notAfter)} />
                <Row label="序列号" value={parsed.serialNumber} mono />
                <Row
                  label="签名算法"
                  value={`${parsed.signatureHash} ${parsed.signatureAlgorithm}`.trim()}
                />
              </div>

              <div>
                <p className="mb-1 text-[11px] text-zinc-400">SAN</p>
                <div className="flex flex-wrap gap-1">
                  {parsed.sans.length > 0 ? (
                    parsed.sans.map((san) => (
                      <span
                        key={`${san.type}-${san.value}`}
                        className="rounded-md bg-white px-1.5 py-0.5 font-mono text-[11px] text-zinc-600 ring-1 ring-zinc-200"
                      >
                        {san.value}
                      </span>
                    ))
                  ) : (
                    <span className="text-[11px] text-rose-600">
                      {parsed.isCa ? "CA 证书，无需 SAN" : "没有 SAN，现代浏览器会拒绝这张证书"}
                    </span>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                <Row label="KeyUsage" value={parsed.keyUsages.join(", ") || "—"} />
                <Row label="ExtendedKeyUsage" value={parsed.eku.join(", ") || "—"} />
                <Row label="SHA-256 指纹" value={parsed.sha256} mono />
                <Row label="SHA-1 指纹" value={parsed.sha1} mono />
              </div>
            </div>
          ) : (
            <div className="flex h-full min-h-[240px] flex-col items-center justify-center gap-2 text-center">
              <p className="text-xs text-zinc-500">把证书拖到这里，或粘贴后点击解析</p>
              <p className="max-w-[300px] text-[11px] leading-relaxed text-zinc-400">
                会展示主体、签发者、SAN、密钥用途、指纹与剩余有效期，并检查证书链是否缺少中间证书。
              </p>
            </div>
          )}
        </div>

        {chain ? (
          <div className="lg:col-span-2">
            <ChainView report={chain} />
          </div>
        ) : null}
      </div>
    </Card>
  );
}
