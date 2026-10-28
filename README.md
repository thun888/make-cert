# make-cert

浏览器内的 SSL 证书生成器。为本地开发、内网服务和测试环境签发自签名证书与内建 CA 证书：密钥对由 WebCrypto 生成，X.509 结构由 [`@peculiar/x509`](https://github.com/PeculiarVentures/x509) 组装，全部在浏览器内完成，没有后端。

## 它能做什么

| 能力 | 说明 |
| --- | --- |
| 自签名证书 | 一张能装进测试服务器的证书，配合信任导入即可消除浏览器警告 |
| 内建根 CA | 生成 `CA:TRUE` 的根证书，装进系统信任库后，它签发的站点证书都会被认可 |
| 由 CA 签发 | 粘贴已有的 CA 证书与私钥（PKCS#8 / PKCS#1 / SEC1），签发叶子证书 |
| 多类型 SAN | DNS、通配符、IP（v4/v6）、邮箱、URI，支持多条 |
| 密钥与扩展 | RSA 2048/3072/4096、ECDSA P-256/P-384；BasicConstraints、KeyUsage、EKU、SKI/AKI |
| 导出 | PEM（证书 / 私钥 / 链 / fullchain）、CSR（PKCS#10）、PKCS#12（仅 RSA） |
| 部署片段 | Nginx、Apache、Node.js、Tomcat、IIS/Windows，以及三平台的信任安装命令 |
| 证书解析 | 拖入任意 PEM 证书，检查 SAN、用途、指纹与剩余有效期 |
| 本地 CA 库 | 根 CA 存在本机 IndexedDB，下次签发直接从下拉框选用，不用再翻 PEM 文件 |
| 从本地导入 CA | 直接读取 `.crt` / `.pem` / `.key` 或带口令的 `.pfx` / `.p12`，自动拼合证书与私钥、验证两者是否配对，并可一键存入 CA 库 |
| 链完整性校验 | 粘贴叶子 + 中间证书，逐级验证签发关系、AKI/SKI 匹配，定位缺失的中间证书 |

## 它不能做什么

- **签发被公网信任的证书。** 信任根在操作系统/浏览器的信任库里，浏览器无法自建可信根。公网 HTTPS 仍需要 CA 通过 ACME 完成域名校验，本工具最多帮你生成 CSR。
- **自动续期、吊销。** 没有 OCSP/CRL 分发，也没有定时任务。
- **打包 ECDSA 的 PKCS#12。** 浏览器端 PKCS#12 依赖 node-forge，它只支持 RSA 私钥；ECDSA 请导出 PEM（nginx / Node / Go 原生支持），或在本地用 `openssl pkcs12 -export` 转换。

## 开发

```bash
npm install
npm run dev      # http://localhost:3000
npm run build    # 静态导出到 out/
```

`next.config.ts` 里启用了 `output: "export"`：产物是纯静态文件（`out/`，约 1.5 MB），丢到任何静态托管上即可，运行期不需要 Node。因为资源路径是绝对的 `/_next/...`，本地预览需要一个 HTTP 服务（`npx serve out`），直接双击 HTML 打不开。静态导出与 `cacheComponents` / `partialPrefetching` 互斥，如需回到服务端渲染，删掉 `output` 并恢复这两个开关即可。

## 目录结构

```
app/
  page.tsx              页面骨架
  layout.tsx            元信息与字体
components/
  cert-studio.tsx       表单、模式切换、生成前自检、本地 CA 库
  result-panel.tsx      输出面板（证书 / 私钥 / 链 / CSR / 部署）
  inspector.tsx         证书解析与链校验
  ui.tsx                基础控件
lib/
  download.ts           文件下载与文件名清洗
  ca-store.ts           本地 CA 库（IndexedDB）
  cert/
    types.ts            领域类型
    pem.ts              PEM/DER、十六进制、序列号、日期
    keys.ts             密钥生成与导出
    issue.ts            签发核心：扩展组装、自签名、CA 签发、CSR
    import.ts           本地 CA 文件导入（PEM / PKCS#1 / PKCS#12）与配对校验
    parse.ts            证书解析、指纹、签发关系校验
    chain.ts            证书链拼接与完整性分析
    validate.ts         生成前自检规则
    pkcs12.ts           PKCS#12 打包（node-forge，仅 RSA）
    snippets.ts         部署与信任安装片段
```

## 实现要点

- **浏览器不能签发公信证书**，所以产品定位是「证书构造器 + CSR 生成器」，不是 CA。
- **必须在 WebCrypto 里用 `extractable: true`**，否则私钥无法导出成 PEM。代价是私钥会以可导出形式存在于页面内存中，关闭页面即释放。
- **序列号必须随机**（16 字节，最高位清零）——时间戳或自增序列号是可预测的，属于签发缺陷。
- **notBefore 回退 5 分钟**，避开部署机器与被访问机器之间的时钟漂移。
- **通配符只在最左侧标签有效**，且 `*.example.com` 不覆盖 `example.com` 本身。
- **有效期上限随 CA/B 论坛 SC-081v3 变化**：公信证书自 2026-03-15 起最长 200 天，2027 年 100 天，2029 年 47 天。自签名证书不受此限制，但界面会提示这一点，避免用户把它当成公信证书的规则。
- **根 CA 不生成 SAN**：CA 证书不需要 SAN，给它加 SAN 只会让工具输出看起来不专业。
- **本地 CA 库不加密**：IndexedDB 里存的是明文私钥。这和 mkcert 把 CA 私钥放在 `~/.mkcert` 是同一级别的信任假设，只适合个人电脑；清理浏览器数据会一起清掉。
- **导入时会验证私钥与证书是否配对**：私钥导入后用它对一段固定文本签名，再用证书里的公钥验签。不配对时直接拦下——否则签发过程不会报错，但产出的证书链必然校验不过，这种沉默的失败最难排查。
- **链校验不信任任何根**：只做「签名能否互相验证 + 名字是否对得上」，不判断这张根证书是否被系统信任——那件事只有客户端自己知道。

## 后续可以做的

- 用口令（PBKDF2 + AES-GCM）加密本地 CA 库，降低共享电脑上的风险
- 一键打包 ZIP、批量生成多域名证书
- 把链校验接进生成流程：签发后立刻验证新证书能否接上 CA
- ACME 客户端（`dns-01` / `http-01`），但这需要用户提供 DNS API Token 或服务端挑战响应，已经越过了「纯前端」的边界
