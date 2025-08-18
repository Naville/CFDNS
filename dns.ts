// SPDX-License-Identifier: 0BSD
const dnsPacket = require('dns-packet');
const dnsPacket_types = require('dns-packet/types')

// 目前的实现要求所有的上流DNS都支持DNS Wireformat
// 第二个布尔值表示该上游是否“采纳/支持”ECS（仅在此为 true 时才在请求中附加 ECS）
const upstreams = {
  "cf":      ['https://cloudflare-dns.com/dns-query', false],
  "google":  ["https://dns.google/dns-query", true],
  "dnspod":  ["https://doh.pub/dns-query", true],
  "nextdns": ["https://dns.nextdns.io", true],
  "opendns": ["https://doh.opendns.com/dns-query", true],
  "twnic":   ["https://dns.twnic.tw/dns-query", true],
  "quad9-11":   ["https://dns11.quad9.net/dns-query", true],
  "quad9-12":   ["https://dns11.quad9.net/dns-query", true],
};

// ---------- EDNS/ECS 构造工具函数（新增） ----------
function parseIPv6ToBytes(ipv6 /*: string*/) /*: Uint8Array*/ {
  const parts = ipv6.split("::");
  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts[1] ? parts[1].split(":") : [];
  const zerosToAdd = 8 - (left.length + right.length);
  const full = [...left, ...Array(zerosToAdd).fill("0"), ...right].map(x => x || "0");
  const out /*: number[]*/ = [];
  for (const h of full) {
    const v = parseInt(h, 16) >>> 0;
    out.push((v >>> 8) & 0xff, v & 0xff); // 大端: 高字节在前
  }
  return new Uint8Array(out); // 16 字节
}

function truncateAddr(bytes /*: Uint8Array*/, prefixLen /*: number*/) /*: Uint8Array*/ {
  const need = Math.ceil(prefixLen / 8);
  if (need === 0) return new Uint8Array(0);
  const view = bytes.slice(0, need);
  const rem = prefixLen % 8;
  if (rem !== 0) {
    const mask = 0xff << (8 - rem);
    view[need - 1] &= mask; // 非前缀位清零
  }
  return view;
}

/**
 * 构造 RFC 7871 的 ECS 选项（TLV）
 * @param {string} cfConnectingIP 来自 'cf-connecting-ip'
 * @param {number} v4Prefix 建议 24
 * @param {number} v6Prefix 建议 56
 */
function buildECSOption(cfConnectingIP, v4Prefix = 24, v6Prefix = 56) /*: Uint8Array*/ {
  let family /*: number*/, srcPrefix /*: number*/, addrBytes /*: Uint8Array*/;

  if (cfConnectingIP.includes(":")) {
    family = 2; // IPv6
    const v6 = parseIPv6ToBytes(cfConnectingIP);
    srcPrefix = v6Prefix;
    addrBytes = truncateAddr(v6, srcPrefix);
  } else if (cfConnectingIP.includes(".")) {
    family = 1; // IPv4
    const v4 = new Uint8Array(cfConnectingIP.split(".").map(x => parseInt(x, 10) & 0xff));
    srcPrefix = v4Prefix;
    addrBytes = truncateAddr(v4, srcPrefix);
  } else {
    throw new Error("Unknown IP family for ECS");
  }

  // ECS TLV: code(2)=8, len(2), family(2), srcPrefix(1), scope(1)=0, addr(var)
  const tlvLen = 2 + 1 + 1 + addrBytes.length;
  const opt = new Uint8Array(4 + tlvLen);
  let o = 0;
  // OPTION-CODE = 8
  opt[o++] = 0x00; opt[o++] = 0x08;
  // OPTION-LENGTH
  opt[o++] = (tlvLen >>> 8) & 0xff; opt[o++] = tlvLen & 0xff;
  // FAMILY
  opt[o++] = (family >>> 8) & 0xff; opt[o++] = family & 0xff;
  // SOURCE PREFIX-LENGTH
  opt[o++] = srcPrefix & 0xff;
  // SCOPE PREFIX-LENGTH
  opt[o++] = 0x00;
  // ADDRESS
  opt.set(addrBytes, o);
  return opt;
}

/**
 * 构造 OPT 伪记录（仅包含一个 ECS 选项）
 * @param {Uint8Array} ecsOpt
 * @param {number} udpPayloadSize 通常取 1232（DoH 环境下也被许多实现参考）
 */
function buildOPTRecord(ecsOpt /*: Uint8Array*/, udpPayloadSize = 1232) /*: Uint8Array*/ {
  // NAME=0x00, TYPE=OPT(41), CLASS=udpPayloadSize, TTL=0, RDLEN=len(ecsOpt), RDATA=ecsOpt
  const rdlen = ecsOpt.length;
  const out = new Uint8Array(1 + 2 + 2 + 4 + 2 + rdlen);
  let o = 0;
  out[o++] = 0x00;                   // NAME=root
  out[o++] = 0x00; out[o++] = 0x29;  // TYPE=OPT (41)
  out[o++] = (udpPayloadSize >>> 8) & 0xff; out[o++] = udpPayloadSize & 0xff; // CLASS
  out[o++] = 0x00; out[o++] = 0x00; out[o++] = 0x00; out[o++] = 0x00;         // TTL
  out[o++] = (rdlen >>> 8) & 0xff; out[o++] = rdlen & 0xff;                   // RDLEN
  out.set(ecsOpt, o);
  return out;
}

/** 把 DNS 头部 ARCOUNT 自增 1（偏移 10–11，大端 16 位） */
function incrementARCOUNT(msg /*: Uint8Array*/) /*: void*/ {
  const ar = (((msg[10] << 8) | msg[11]) + 1) & 0xffff;
  msg[10] = (ar >>> 8) & 0xff;
  msg[11] = ar & 0xff;
}

// -------------------------------------------------------

const r404 = new Response(null, { status: 404 });
const r400 = new Response(null, { status: 400 });

export default {
  async fetch(request, env, ctx) {
    const username = env.USER;
    const passwd = env.PASSWORD;

    const { method, headers, url } = request;
    const { searchParams, pathname } = new URL(url);

    let auths = pathname.split("/").filter(str => str.length > 0);
    if (auths.length < 3) {
      return new Response(null, { status: 401 });
    }
    let upstream = auths[0];
    let un = auths[1];
    let pw = auths[2];
    if (!(upstream in upstreams)) {
      return new Response(null, { status: 400 });
    }
    if ((un != username) || (pw != passwd)) {
      return new Response(null, { status: 401 });
    }

    let [doh, edns] = upstreams[upstream];
    if (upstream == "nextdns") {
      doh = doh + "/" + env.NEXTDNS_KEY
    }

    // 构造（或空置）EDNS(0)+ECS 的 OPT 记录
    let extended_body = new Uint8Array(0);
    if (edns) {
      const ip = request.headers.get('cf-connecting-ip');
      if (ip) {
        try {
          const ecsOpt = buildECSOption(ip, /*v4*/24, /*v6*/56);
          extended_body = buildOPTRecord(ecsOpt, /*udpPayload*/1232);
        } catch (e) {
          // IP 异常则不加 ECS，但继续走查询
          extended_body = new Uint8Array(0);
        }
      }
    }

    switch (method) {
      case "POST": {
        const content_type = headers.get('content-type');
        if (content_type !== 'application/dns-message') {
          // 可视需要放宽匹配，例如以 'application/dns-message' 开头
          console.log("Unknown content_type: " + content_type + " for POST");
          return r400;
        }

        // 注意：ArrayBuffer 需先转为 Uint8Array 再操作
        const orig = new Uint8Array(await request.arrayBuffer());
        let body = orig;

        if (extended_body.length > 0) {
          body = new Uint8Array(orig.length + extended_body.length);
          body.set(orig, 0);
          body.set(extended_body, orig.length);
          incrementARCOUNT(body);
        }

        return await fetch(new Request(doh, {
          method: 'POST',
          headers: {
            'accept': 'application/dns-message',
            'content-type': 'application/dns-message',
          },
          body
        }));
      }

      case "GET": {
        const accept_kind = headers.get('accept');
        let query /*: Uint8Array*/ = new Uint8Array(0);

        switch (accept_kind) {
          case "application/dns-message": {
            if (searchParams.has('dns')) {
              // base64（URL 安全）-> Buffer -> Uint8Array
              query = Buffer.from(searchParams.get('dns'), 'base64');
            } else {
              console.log("No Query Found");
              return r404;
            }
            break;
          }
          case "application/dns-json": {
            let remote /*: string*/ = "";
            if (searchParams.has('name')) {
              remote = searchParams.get("name");
            } else {
              console.log("No Query Found");
              return r404;
            }
            const type = (searchParams.has('type')) ? searchParams.get('type') : 'A';
            let flag = dnsPacket.RECURSION_DESIRED;
            if (searchParams.has('do')) {
              const dnssec_str = searchParams.get('do');
              switch (dnssec_str) {
                case "1":
                case "true": {
                  flag = flag | dnsPacket.AUTHENTIC_DATA;
                  break;
                }
                // "0"/"false" 保持默认
              }
            }
            query = dnsPacket.encode({
              type: 'query',
              flags: flag,
              questions: [{
                type: type,
                name: remote
              }]
            });
            break;
          }
          default: {
            console.log("Unknown accept_kind: " + accept_kind + " for GET");
            return r400;
          }
        }

        // 追加 OPT（若启用）并自增 ARCOUNT
        let body = query;
        if (extended_body.length > 0) {
          const merged = new Uint8Array(query.length + extended_body.length);
          merged.set(query, 0);
          merged.set(extended_body, query.length);
          incrementARCOUNT(merged);
          body = merged;
        }

        const res = await fetch(new Request(doh, {
          method: 'POST',
          headers: {
            'accept': 'application/dns-message',
            'content-type': 'application/dns-message',
          },
          body,
        }));

        switch (accept_kind) {
          case "application/dns-message": {
            return res;
          }
          case "application/dns-json": {
            const buffers /*: Array<Uint8Array>*/ = [];
            for await (const data of res.body) {
              buffers.push(data);
            }
            const finalBuffer = Buffer.concat(buffers);
            const dns_resp = dnsPacket.decode(finalBuffer);

            const json_resp /*: any*/ = {};
            json_resp["Status"] = dns_resp.flags & 0xf;
            json_resp["AD"] = dns_resp.flag_ad;
            json_resp["CD"] = dns_resp.flag_cd;
            json_resp["RA"] = dns_resp.flag_ra;
            json_resp["RD"] = dns_resp.flag_rd;
            json_resp["TC"] = dns_resp.flag_tc;

            const questions /*: Array<Object>*/ = [];
            for (const q of dns_resp.questions) {
              const qq = { ...q };
              qq["type"] = dnsPacket_types.toType(qq.type);
              delete qq.class;
              questions.push(qq);
            }
            json_resp["Question"] = questions;

            const answers /*: Array<Object>*/ = [];
            for (const a of dns_resp.answers) {
              const aa = { ...a };
              aa["type"] = dnsPacket_types.toType(aa.type);
              aa["TTL"] = aa.ttl;
              delete aa.ttl;
              delete aa.class;
              delete aa.flush;
              answers.push(aa);
            }
            json_resp["Answer"] = answers;

            const json_resp_str = JSON.stringify(json_resp);
            return new Response(json_resp_str, {
              status: 200,
              headers: { "content-type": "application/dns-json" }
            });
          }
        }
      }

      default: {
        console.log("Unknown method: " + method);
        return r400;
      }
    }
  },
};
