"use client";

import { useMemo, useState } from "react";
import { download } from "@/lib/download";
import { isVaultSupported, saveCa } from "@/lib/ca-store";
import { formatDate } from "@/lib/cert/pem";
import { deploymentSnippets } from "@/lib/cert/snippets";
import { createPkcs12 } from "@/lib/cert/pkcs12";
import type { IssueResult } from "@/lib/cert/types";
import { Badge, Button, Card, CardHeader, CodeBlock, Field, TextInput } from "./ui";

function InfoRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] text-zinc-400">{label}</span>
      <span className={`text-xs text-zinc-700 ${mono ? "font-mono break-all" : ""}`}>{value}</span>
    </div>
  );
}

type TabId = "cert" | "key" | "chain" | "csr" | "deploy";

export function ResultPanel({
  result,
  baseName,
  onUseAsCa,
}: {
  result: IssueResult | null;
  baseName: string;
  onUseAsCa: (certPem: string, keyPem: string) => void;
}) {
  const [tab, setTab] = useState<TabId>("cert");
  const [password, setPassword] = useState("changeit");
  const [p12Busy, setP12Busy] = useState(false);
  const [p12Error, setP12Error] = useState<string | null>(null);
  const [savedId, setSavedId] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const snippets = useMemo(
    () => (result ? deploymentSnippets(baseName, result.mode) : []),
    [result, baseName],
  );
  const [snippetId, setSnippetId] = useState("nginx");

  if (!result) {
    return (
      <Card className="overflow-hidden">
        <CardHeader title="输出" description="生成的证书、私钥与部署配置会出现在这里。" />
        <div className="flex flex-col items-center justify-center gap-3 px-6 py-24 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-dashed border-zinc-300 text-zinc-300">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 3v10m0 0 4-4m-4 4-4-4" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" strokeLinecap="round" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-medium text-zinc-700">还没有生成任何证书</p>
            <p className="mt-1 max-w-xs text-xs leading-relaxed text-zinc-400">
              填写左侧参数并生成后，这里会显示证书、私钥与部署配置。
            </p>
          </div>
        </div>
      </Card>
    );
  }

  const isEc = result.keyLabel.includes("ECDSA");
  const tabs: Array<{ id: TabId; label: string; hidden?: boolean }> = [
    { id: "cert", label: "证书" },
    { id: "key", label: "私钥" },
    { id: "chain", label: "证书链", hidden: result.mode === "self" },
    { id: "csr", label: "CSR", hidden: !result.csrPem },
    { id: "deploy", label: "部署" },
  ];

  const activeSnippet = snippets.find((item) => item.id === snippetId) ?? snippets[0];

  const exportPkcs12 = async () => {
    setP12Busy(true);
    setP12Error(null);
    try {
      const bytes = await createPkcs12({
        certPem: result.certPem,
        keyPem: result.keyPem,
        chainPem: result.chainPem,
        password,
        friendlyName: baseName,
      });
      download(`${baseName}.p12`, bytes, "application/x-pkcs12");
    } catch (error) {
      setP12Error(error instanceof Error ? error.message : "PKCS#12 打包失败");
    } finally {
      setP12Busy(false);
    }
  };

  return (
    <Card className="overflow-hidden">
      <CardHeader
        title="输出"
        description="时间按本地时区显示，下载前请确认主体与 SAN。"
        aside={<Badge tone="success">已生成</Badge>}
      />

      <div className="space-y-4 px-5 py-4">
        <div className="grid grid-cols-2 gap-x-4 gap-y-3">
          <InfoRow label="主体" value={result.subject} />
          <InfoRow label="密钥" value={result.keyLabel} />
          <InfoRow label="生效" value={formatDate(result.notBefore)} />
          <InfoRow label="到期" value={formatDate(result.notAfter)} />
          <InfoRow label="序列号" value={result.serialNumber} mono />
          <InfoRow label="SHA-256" value={result.sha256.slice(0, 47) + "…"} mono />
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {tabs
            .filter((item) => !item.hidden)
            .map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setTab(item.id)}
                className={`rounded-lg px-2.5 py-1 text-xs font-medium transition ${
                  tab === item.id
                    ? "bg-zinc-900 text-white"
                    : "text-zinc-500 hover:bg-zinc-100 hover:text-zinc-800"
                }`}
              >
                {item.label}
              </button>
            ))}
        </div>

        {tab === "cert" ? (
          <CodeBlock
            code={result.certPem}
            filename={`${baseName}.crt`}
            onDownload={() => download(`${baseName}.crt`, result.certPem, "application/x-pem-file")}
          />
        ) : null}

        {tab === "key" ? (
          <CodeBlock
            code={result.keyPem}
            filename={`${baseName}.key`}
            onDownload={() => download(`${baseName}.key`, result.keyPem, "application/x-pem-file")}
          />
        ) : null}

        {tab === "chain" ? (
          result.chainPem ? (
            <CodeBlock
              code={result.chainPem}
              filename={`${baseName}.chain.pem`}
              onDownload={() => download(`${baseName}.chain.pem`, result.chainPem, "application/x-pem-file")}
            />
          ) : (
            <p className="rounded-xl border border-dashed border-zinc-200 px-4 py-8 text-center text-xs text-zinc-400">
              自签名证书没有上游证书链。
            </p>
          )
        ) : null}

        {tab === "csr" ? (
          result.csrPem ? (
            <CodeBlock
              code={result.csrPem}
              filename={`${baseName}.csr`}
              onDownload={() => download(`${baseName}.csr`, result.csrPem as string, "application/pkcs10")}
            />
          ) : null
        ) : null}

        {tab === "deploy" ? (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-1">
              {snippets.map((snippet) => (
                <button
                  key={snippet.id}
                  type="button"
                  onClick={() => setSnippetId(snippet.id)}
                  className={`rounded-md px-2 py-1 text-[11px] font-medium transition ${
                    activeSnippet?.id === snippet.id
                      ? "bg-zinc-900 text-white"
                      : "bg-zinc-100 text-zinc-600 hover:bg-zinc-200"
                  }`}
                >
                  {snippet.label}
                </button>
              ))}
            </div>
            {activeSnippet ? (
              <>
                <p className="text-[11px] text-zinc-400">{activeSnippet.hint}</p>
                <CodeBlock code={activeSnippet.code} />
              </>
            ) : null}
          </div>
        ) : null}

        <div className="flex flex-wrap gap-2 border-t border-zinc-100 pt-4">
          <Button
            variant="primary"
            onClick={() => download(`${baseName}.fullchain.pem`, result.fullchainPem, "application/x-pem-file")}
          >
            下载完整证书链
          </Button>
          <Button
            onClick={() => download(`${baseName}.key`, result.keyPem, "application/x-pem-file")}
          >
            下载私钥
          </Button>
          <Button
            onClick={() => download(`${baseName}.crt`, result.certPem, "application/x-pem-file")}
          >
            下载证书
          </Button>
        </div>

        <div className="rounded-xl border border-zinc-200 bg-zinc-50/70 p-3">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-medium text-zinc-700">导出 PKCS#12（.p12 / .pfx）</p>
              <p className="mt-0.5 text-[11px] leading-relaxed text-zinc-500">
                {isEc
                  ? "当前是 ECDSA 密钥，浏览器端打包 PKCS#12 暂不可用，请使用 PEM；如需 p12 可在本地用 openssl 转换。"
                  : "适用于 Windows / IIS / Java 体系，导入时需要输入下面的口令。"}
              </p>
            </div>
          </div>
          <div className="mt-2 flex items-end gap-2">
            <Field label="口令" className="w-40">
              <TextInput value={password} onChange={(event) => setPassword(event.target.value)} />
            </Field>
            <Button variant="primary" disabled={isEc || p12Busy} onClick={exportPkcs12}>
              {p12Busy ? "打包中…" : "导出 .p12"}
            </Button>
          </div>
          {p12Error ? <p className="mt-2 text-[11px] text-rose-600">{p12Error}</p> : null}
        </div>

        {result.mode === "ca" ? (
          <div className="rounded-xl border border-emerald-200 bg-emerald-50/60 p-3">
            <p className="text-xs font-medium text-emerald-800">这是你自建的根 CA</p>
            <p className="mt-0.5 text-[11px] leading-relaxed text-emerald-700">
              把它安装进系统信任库后，用它签发的站点证书就不再报警。
            </p>
            <Button
              className="mt-2"
              onClick={() => onUseAsCa(result.certPem, result.keyPem)}
            >
              用这个 CA 签发站点证书
            </Button>
            <div className="mt-2 flex items-center gap-2">
              <Button
                variant="secondary"
                disabled={savedId === result.sha256 || !isVaultSupported()}
                onClick={async () => {
                  setSaveError(null);
                  try {
                    await saveCa({
                      id: result.sha256,
                      name: result.subject,
                      certPem: result.certPem,
                      keyPem: result.keyPem,
                      createdAt: Date.now(),
                      notAfter: result.notAfter.getTime(),
                    });
                    setSavedId(result.sha256);
                  } catch (cause) {
                    setSaveError(cause instanceof Error ? cause.message : "保存失败");
                  }
                }}
              >
                {savedId === result.sha256 ? "已存入本地 CA 库" : "存入本地 CA 库"}
              </Button>
              <span className="text-[11px] text-emerald-700/70">下次续签可直接选用</span>
            </div>
            {saveError ? <p className="mt-1 text-[11px] text-rose-600">{saveError}</p> : null}
          </div>
        ) : null}
      </div>
    </Card>
  );
}
