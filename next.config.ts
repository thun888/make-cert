import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // 纯客户端工具：静态导出后放在任意静态托管上即可，运行期不需要 Node。
  // 注意：静态导出与 cacheComponents / partialPrefetching（PPR）互斥，
  // 如需回到服务端渲染，删掉 output 并恢复那两个开关即可。
  output: "export",
  experimental: {
    agentFeedback: true,
  },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
