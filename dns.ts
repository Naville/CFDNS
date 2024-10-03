// SPDX-License-Identifier: 0BSD
const dnsPacket = require('dns-packet');
const dnsPacket_types = require('dns-packet/types')
// 目前的实现要求所有的上流DNS都支持DNS Wireformat
const upstreams = { "cf": ['https://cloudflare-dns.com/dns-query', false], "google": ["https://dns.google/dns-query", true], "dnspod": ["https://doh.pub/dns-query", false] };
// Preserve the first X components or source IP when sending to upstream
const ip_strip_v4 = 2;
const ip_strip_v6 = 12;

// 定义响应
const r404 = new Response(null, { status: 404 });
const r400 = new Response(null, { status: 400 });

export default {
    async fetch(request, env, ctx) {

        const username = env.USER;
        const passwd = env.PASSWORD;

        const { method, headers, url } = request; // 从请求中获取方法、头部和URL
        const { searchParams, pathname } = new URL(url);
        let auths = pathname.split("/").filter(str => str.length > 0);
        if (auths.length < 3) {
            return new Response(null, { status: 401 });
        }
        let upstream = auths[0];
        let un = auths[1];
        let pw = auths[2];
        if (!(upstream in upstreams)) {
            // Invalid upstream
            return new Response(null, { status: 400 });
        }
        if ((un != username) || (pw != passwd)) {
            return new Response(null, { status: 401 });
        }
        let [doh, edns] = upstreams[upstream];
        // For NextDNS, we fixup device indicator to improve logging seen in NextDNS Console
        if (upstream == "nextdns") {
            if (auths.length == 4) {
                doh = doh + auths[3];
            }
            else {
                doh = doh + "cfworker";
            }
        }
        let extended_body = new Uint8Array(0);

        if (edns) {
            const ip = request.headers.get('cf-connecting-ip');
            const opt_code = new Uint8Array([0x0, 0x8]);
            var family = new Uint8Array(0);
            var src_ip: Array<number> = [];
            if (ip.includes(":")) {
                // IPv6
                // Expand IPV6 address to full form
                // Split the address into two parts if there's a '::' (zero compression)
                const parts = ip.split('::');

                let leftPart = parts[0].split(':');  // Left side of '::'
                let rightPart = parts[1] ? parts[1].split(':') : [];  // Right side of '::'

                // Calculate how many zeros we need to insert
                const zerosToAdd = 8 - (leftPart.length + rightPart.length);

                // Add the required number of '0000'
                const expanded = [
                    ...leftPart,
                    ...Array(zerosToAdd).fill('0000'),
                    ...rightPart
                ];

                // Ensure each group is fully expanded (4 hexadecimal digits)
                const ipv6_full = expanded.map(group => group.padStart(4, '0')).join(':');

                family = new Uint8Array([0x0, 0x2]);
                src_ip = ipv6_full.split(':').filter((comp) => comp.length > 0).map((comp) => parseInt(comp, 16));
                src_ip = src_ip.slice(0, ip_strip_v6);
            }
            else if (ip.includes(".")) {
                family = new Uint8Array([0x0, 0x1]);
                src_ip = ip.split('.').filter((comp) => comp.length > 0).map((comp) => parseInt(comp, 10));
                src_ip = src_ip.slice(0, ip_strip_v4);
            }
            else {
                console.log("Unknown Source IP");
                return r404;
            }
            var opt_fixed: Array<number> = [];
            // OPT RR FIXED
            //// NAME
            opt_fixed.push(0x0);
            //// TYPE
            opt_fixed.push(0x0,0x29);
            //// CLASS
            opt_fixed.push(0x2,0x0);
            //// TTL
            opt_fixed.push(0x0,0x0,0x0,0x0);



            // OPT RR VARIABLE
            var opt_variable: Array<number> = [];
            // OPTION-CODE
            opt_code.forEach((v) => opt_variable.push(v));
            // OPTION-LENGTH
            opt_variable.push(0x0);
            opt_variable.push(family.length + 1 + 1 + src_ip.length);
            // FAMILY
            family.forEach((v) => opt_variable.push(v));
            // SOURCE PREFIX-LENGTH
            opt_variable.push(src_ip.length * 8);// Unit is in bits
            // SCOPE PREFIX-LENGTH
            opt_variable.push(0);
            // Address
            src_ip.forEach((v) => opt_variable.push(v));

            // Update opt_fixed
            //// RDLENGTH
            opt_fixed.push(0x0,opt_variable.length); 

            // Concat everything
            var body_arr: Array<number> = [];
            opt_fixed.forEach((v) => body_arr.push(v));
            opt_variable.forEach((v) => body_arr.push(v));
            extended_body = new Uint8Array(body_arr);
            console.log(extended_body);
        }
        switch (method) {
            case "POST": {
                const content_type = headers.get('content-type');
                switch (content_type) {
                    case 'application/dns-message': {
                        const orig_body = await request.body.arrayBuffer();
                        var body_arr: Array<number> = [];
                        orig_body.forEach((v) => body_arr.push(v));
                        extended_body.forEach((v) => body_arr.push(v));
                        // Per RFC5935, update ARCOUNT in DNS header to reflect the number of OPT records
                        if (body_arr.length != 0) {
                            //body_arr[10] = 0;
                            body_arr[11] = 1;
                        }
                        const body = new Uint8Array(body_arr);
                        return await fetch(new Request(doh, {
                            method: 'POST',
                            headers: {
                                'accept': 'application/dns-message',
                                'content-type': 'application/dns-message',
                            },
                            body: body
                        }));

                    }
                    default: {
                        console.log("Unknown content_type: " + content_type + " for POST");
                        return r400;
                    }
                }

            }

            case "GET": {
                const accept_kind = headers.get('accept');
                var query: Uint8Array = new Uint8Array(0);
                switch (accept_kind) {
                    case "application/dns-message": {
                        if (searchParams.has('dns')) {
                            query = Buffer.from(searchParams.get('dns')!, 'base64');
                        }
                        else {
                            console.log("No Query Found");
                            return r404;
                        }
                        break;

                    }
                    case "application/dns-json": {
                        var remote: string = "";
                        if (searchParams.has('name')) {
                            remote = searchParams.get("name")!;
                        }
                        else {
                            console.log("No Query Found");
                            return r404;
                        }
                        var type: string = (searchParams.has('type')) ? searchParams.get('type')! : 'A';
                        var flag = dnsPacket.RECURSION_DESIRED;
                        if (searchParams.has('do')) {
                            const dnssec_str = searchParams.get('do')!;
                            switch (dnssec_str) {
                                case "0":
                                case "false": {
                                    break;
                                }
                                case "1":
                                case "true": {
                                    flag = flag | dnsPacket.AUTHENTIC_DATA;
                                }
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
                    default:{
                        console.log("Unknown accept_kind: " + accept_kind + " for GET");
                        return r400;
                    }
                }
                var body_arr: Array<number> = [];
                query.forEach((v) => body_arr.push(v));
                if (body_arr[11] === 0x00) {
                    // Per RFC5935, update ARCOUNT in DNS header to reflect the number of OPT records
                    body_arr[11] = 0x01;
                    extended_body.forEach((v) => body_arr.push(v));
                }
                const body = new Uint8Array(body_arr);
                console.log("Query_Full");
                console.log(body);
                var res = await fetch(new Request(doh, {
                    method: 'POST',
                    headers: {
                        'accept': 'application/dns-message',
                        'content-type': 'application/dns-message',
                    },
                    body: body,
                }));
                switch(accept_kind){
                    case "application/dns-message": {
                        return res;
                    }
                    case "application/dns-json": {
                        const buffers: Array<Uint8Array> = [];
                        for await (const data of res.body!) {
                            buffers.push(data);
                        }
        
                        const finalBuffer = Buffer.concat(buffers);
                        const dns_resp = dnsPacket.decode(finalBuffer);
                        console.log(dns_resp);
                        var json_resp = {};
                        json_resp["Status"] = dns_resp.flags & 0xf;
                        //json_resp["AA"] = dns_resp.flag_aa;
                        json_resp["AD"] = dns_resp.flag_ad;
                        json_resp["CD"] = dns_resp.flag_cd;
                        //json_resp["QR"] = dns_resp.flag_qr;
                        json_resp["RA"] = dns_resp.flag_ra;
                        json_resp["RD"] = dns_resp.flag_rd;
                        json_resp["TC"] = dns_resp.flag_tc;
                        var questions: Array<Object> = [];
                        for (var question of dns_resp.questions) {
                            question["type"] = dnsPacket_types.toType(question.type);
                            delete question.class;
                            questions.push(question);
                        }
                        json_resp["Question"] = questions;
                        var answers: Array<Object> = [];
                        for (var answer of dns_resp.answers) {
                            answer["type"] = dnsPacket_types.toType(answer.type);
                            answer["TTL"] = answer.ttl;
                            delete answer.ttl;
                            delete answer.class;
                            delete answer.flush;
                            answers.push(answer);
                        }
                        json_resp["Answer"] = answers;
                        const json_resp_str = JSON.stringify(json_resp);
                        console.log(json_resp_str);
                        return new Response(json_resp_str, {
                            status: 200,
                            headers: {
                                "content-type": "application/dns-json"
                            }
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