# CFDNS
基于Cloudflare Worker的支持EDNS Client Subnet的DNS over HTTPS中转代理

## 配置
- 安装[Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- ``npx wrangler login``登录到你的Cloudflare账号
- ``npx wrangler secret put USER`` 设置DNS服务的登陆用户名
- ``npx wrangler secret put PASSWORD`` 设置DNS服务的登陆密码q
- ``npx wrangler deploy``
- 推荐在Cloudflare的网页端对对应的Worker绑定自定义域名, 由于众所周知的原因Worker.dev域名在某些地区存在严重的DNS污染


## 使用
将你的DoH服务器设置为``https://自定义域名/上流DNS类型/用户名/密码即可``

其中上流DNS类型由`dns.ts`头部的`upstreams`变量定义

## 其他
- DNS Wireformat格式在Surge上测试可用, JSON格式未经过测试. 理论上现代工具都支持前者, 后者的维护意义不大. 有需求可自行提交PR
- 不考虑做基于TTL的缓存, 这部分交由客户端负责.

