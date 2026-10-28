import type { IssueMode } from "./types";

export interface Snippet {
  id: string;
  label: string;
  hint: string;
  code: string;
}

export function deploymentSnippets(baseName: string, mode: IssueMode): Snippet[] {
  const cert = `${baseName}.fullchain.pem`;
  const key = `${baseName}.key`;
  const pfx = `${baseName}.p12`;

  const snippets: Snippet[] = [
    {
      id: "nginx",
      label: "Nginx",
      hint: "证书用 fullchain，私钥单独存放",
      code: `server {
    listen 443 ssl;
    http2 on;
    server_name ${baseName};

    ssl_certificate     /etc/nginx/certs/${cert};
    ssl_certificate_key /etc/nginx/certs/${key};

    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;
}`,
    },
    {
      id: "apache",
      label: "Apache",
      hint: "证书链要和站点证书写在同一个文件里",
      code: `<VirtualHost *:443>
    ServerName ${baseName}

    SSLEngine on
    SSLCertificateFile    /etc/apache2/certs/${cert}
    SSLCertificateKeyFile /etc/apache2/certs/${key}

    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
</VirtualHost>`,
    },
    {
      id: "node",
      label: "Node.js",
      hint: "cert 直接读取完整证书链",
      code: `import { readFileSync } from "node:fs";
import https from "node:https";

https
  .createServer(
    {
      cert: readFileSync("./${cert}"),
      key: readFileSync("./${key}"),
    },
    (req, res) => res.end("ok"),
  )
  .listen(443);`,
    },
    {
      id: "tomcat",
      label: "Tomcat",
      hint: "Java 体系用 PKCS#12，无需额外转换",
      code: `<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" SSLEnabled="true">
    <SSLHostConfig>
        <Certificate certificateKeystoreFile="conf/${pfx}"
                     certificateKeystoreType="PKCS12"
                     certificateKeystorePassword="你的口令"
                     type="RSA" />
    </SSLHostConfig>
</Connector>`,
    },
    {
      id: "windows",
      label: "Windows / IIS",
      hint: "双击导入也可以，命令行更适合批量",
      code: `Import-PfxCertificate -FilePath .\\${pfx} \`
  -CertStoreLocation Cert:\\LocalMachine\\My \`
  -Password (Read-Host -AsSecureString "PFX 口令")`,
    },
  ];

  if (mode === "ca") {
    snippets.push({
      id: "trust",
      label: "信任安装",
      hint: "把自己签的根 CA 装进系统信任库",
      code: `# macOS
sudo security add-trusted-cert -d -r trustRoot \\
  -k /Library/Keychains/System.keychain ${baseName}.crt

# Windows（管理员 PowerShell）
Import-Certificate -FilePath .\\${baseName}.crt \\
  -CertStoreLocation Cert:\\LocalMachine\\Root

# Debian / Ubuntu
sudo cp ${baseName}.crt /usr/local/share/ca-certificates/${baseName}.crt
sudo update-ca-certificates

# Firefox 使用独立信任库，需要在「证书管理器」中单独导入`,
    });
  } else if (mode === "leaf") {
    snippets.push({
      id: "trust",
      label: "信任安装",
      hint: "只需要信任签发这张证书的 CA",
      code: `# 服务端证书本身不需要被信任，需要被信任的是它的签发者
# 把 CA 证书装进系统信任库，叶子证书即可被识别：

# macOS
sudo security add-trusted-cert -d -r trustRoot \\
  -k /Library/Keychains/System.keychain ca.crt

# Windows
Import-Certificate -FilePath .\\ca.crt \\
  -CertStoreLocation Cert:\\LocalMachine\\Root

# Debian / Ubuntu
sudo cp ca.crt /usr/local/share/ca-certificates/internal-ca.crt
sudo update-ca-certificates`,
    });
  }

  return snippets;
}
