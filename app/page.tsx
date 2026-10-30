import { CertStudio } from "@/components/cert-studio";

export default function Home() {
  return (
    <div className="min-h-screen bg-[#fafaf9]">
      <header className="sticky top-0 z-20 border-b border-zinc-200/70 bg-white/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 sm:px-6">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-zinc-900 text-white">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                <rect x="4" y="10" width="16" height="10" rx="2" />
                <path d="M8 10V7a4 4 0 0 1 8 0v3" strokeLinecap="round" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-medium leading-tight text-zinc-900">make-cert</p>
              <p className="text-[11px] leading-tight text-zinc-500">浏览器内的 SSL 证书生成器</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <span className="hidden text-[11px] text-zinc-400 md:inline">
              自签名 · 内建 CA · 证书解析
            </span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 pb-16 pt-6 sm:px-6">
        <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1 className="text-lg font-medium tracking-tight text-zinc-900">
              在浏览器里造一张能用的证书
            </h1>
            <p className="mt-1 max-w-2xl text-xs leading-relaxed text-zinc-500">
              为本地开发、内网服务和测试环境签发证书，或解析已有证书并检查证书链。
            </p>
          </div>
          <p className="text-[11px] leading-relaxed text-zinc-400">
            公网信任的证书仍需通过 CA 签发，<br className="hidden sm:block" />
            本工具只负责自签名与私有 CA。
          </p>
        </div>

        <CertStudio />
      </main>
    </div>
  );
}
