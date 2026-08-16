#!/usr/bin/env python3
# 指纹提取器：pcap -> 每个源IP的 TCP指纹 / 时钟频率 / 是否连上 / JA3+SNI / 端口扫描
# 纯标准库。用法: python3 extract.py a.pcap [b.pcap ...]
import sys, struct, hashlib
from collections import defaultdict

GREASE = {0x0a0a,0x1a1a,0x2a2a,0x3a3a,0x4a4a,0x5a5a,0x6a6a,0x7a7a,0x8a8a,0x9a9a,
          0xaaaa,0xbaba,0xcaca,0xdada,0xeaea,0xfafa}
OPTN = {2:"mss",3:"ws",4:"sackOK",5:"sack",8:"ts",1:"nop",0:"eol"}

def l3_offset(linktype, pkt):
    if linktype == 1:   # Ethernet
        if len(pkt) < 14: return None
        et = struct.unpack(">H", pkt[12:14])[0]
        if et == 0x8100 and len(pkt) >= 18: et = struct.unpack(">H", pkt[16:18])[0]; base=18
        else: base=14
        return base if et in (0x0800,0x86dd) else None
    if linktype == 113: return 16 if len(pkt)>=16 else None   # Linux SLL
    if linktype == 101: return 0                              # RAW IP
    if linktype == 12:  return 0
    if linktype == 239:  # NFLOG: 头4字节 + 一串TLV, IP包在 NFULA_PAYLOAD(type=9)
        i, n = 4, len(pkt)
        while i + 4 <= n:
            tl = struct.unpack("<H", pkt[i:i+2])[0]
            tt = struct.unpack("<H", pkt[i+2:i+4])[0] & 0x3fff
            if tl < 4: break
            if tt == 9: return i + 4          # 载荷TLV的值 = 原始IP包
            i += (tl + 3) & ~3               # 4字节对齐
        return None
    return None

def parse_tls_clienthello(payload):
    # payload 以 TLS record(0x16) 开头; 返回 (ja3, sni, alpn) 或 None
    try:
        if len(payload) < 6 or payload[0] != 0x16: return None
        # record: type(1) ver(2) len(2) ; handshake: type(1)=1 len(3) ver(2) random(32)...
        hs = payload[5:]
        if hs[0] != 0x01: return None
        ver = struct.unpack(">H", hs[4:6])[0]
        p = 6 + 32
        sidlen = hs[p]; p += 1 + sidlen
        clen = struct.unpack(">H", hs[p:p+2])[0]; p += 2
        ciphers = [struct.unpack(">H",hs[p+i:p+i+2])[0] for i in range(0,clen,2)]; p += clen
        cmlen = hs[p]; p += 1 + cmlen
        exts=[]; curves=[]; ecpf=[]; sni=""; alpn=[]
        if p+2 <= len(hs):
            extot = struct.unpack(">H",hs[p:p+2])[0]; p += 2
            end = p + extot
            while p+4 <= end and p+4 <= len(hs):
                et,el = struct.unpack(">HH",hs[p:p+4]); p += 4
                body = hs[p:p+el]; p += el
                exts.append(et)
                if et == 0x0000 and len(body) >= 5:  # SNI
                    sni = body[5:5+struct.unpack(">H",body[3:5])[0]].decode("latin1","replace")
                elif et == 0x000a and len(body) >= 2:  # supported_groups
                    gl = struct.unpack(">H",body[:2])[0]
                    curves = [struct.unpack(">H",body[2+i:4+i])[0] for i in range(0,gl,2)]
                elif et == 0x000b and body:  # ec_point_formats
                    ecpf = list(body[1:1+body[0]])
                elif et == 0x0010:  # ALPN
                    ap=3
                    while ap < len(body):
                        ln=body[ap]; alpn.append(body[ap+1:ap+1+ln].decode("latin1","replace")); ap+=1+ln
        def clean(xs): return [x for x in xs if x not in GREASE]
        ja3_str = "%d,%s,%s,%s,%s" % (ver,
            "-".join(map(str,clean(ciphers))), "-".join(map(str,clean(exts))),
            "-".join(map(str,clean(curves))), "-".join(map(str,ecpf)))
        return hashlib.md5(ja3_str.encode()).hexdigest(), sni, "/".join(alpn)
    except Exception:
        return None

def run(paths):
    tcpfp=defaultdict(set); tsvals=defaultdict(list); ports=defaultdict(list)
    connected=set(); ja3=defaultdict(set); sni=defaultdict(set)
    for path in paths:
        d=open(path,"rb").read()
        if len(d)<24: continue
        le = "<" if d[:4] in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else ">"
        linktype = struct.unpack(le+"I", d[20:24])[0]
        off=24
        while off+16 <= len(d):
            ts_s,ts_u,incl,orig = struct.unpack(le+"IIII", d[off:off+16]); off+=16
            pkt=d[off:off+incl]; off+=incl
            lo=l3_offset(linktype,pkt)
            if lo is None or len(pkt) < lo+20: continue
            l3=pkt[lo:]; ver=l3[0]>>4
            if ver==4:
                ihl=(l3[0]&0xf)*4; proto=l3[9]; ttl=l3[8]
                src=".".join(map(str,l3[12:16])); dst=".".join(map(str,l3[16:20])); tcp=l3[ihl:]
            elif ver==6 and len(l3)>=40:
                proto=l3[6]; ttl=l3[7]
                src=":".join("%x"%struct.unpack(">H",l3[8+i:10+i]) for i in range(0,16,2))
                dst=":".join("%x"%struct.unpack(">H",l3[24+i:26+i]) for i in range(0,16,2)); tcp=l3[40:]
            else: continue
            if proto!=6 or len(tcp)<20: continue
            sp,dp=struct.unpack(">HH",tcp[0:4]); doff=(tcp[12]>>4)*4; flags=tcp[13]; win=struct.unpack(">H",tcp[14:16])[0]
            syn=flags&0x02; ack=flags&0x10
            if syn and ack:      # SYN-ACK 来自服务器 => 对应的客户端"连上了"
                connected.add(dst)
            if syn and not ack:  # 客户端 SYN
                opts=tcp[20:doff]; order=[]; mss=ws=None; tsval=None; i=0
                while i<len(opts):
                    k=opts[i]
                    if k==0: break
                    if k==1: order.append("nop"); i+=1; continue
                    if i+1>=len(opts): break
                    ln=opts[i+1]; order.append(OPTN.get(k,f"op{k}"))
                    if k==2: mss=struct.unpack(">H",opts[i+2:i+4])[0]
                    elif k==3: ws=opts[i+2]
                    elif k==8 and ln>=6: tsval=struct.unpack(">I",opts[i+2:i+6])[0]
                    i+=ln if ln>=2 else 1
                tcpfp[src].add(f"ttl~{ttl}|win={win}|mss={mss}|ws={ws}|opts={','.join(order)}")
                ports[src].append(dp)
                if tsval is not None: tsvals[src].append((ts_s+ts_u/1e6, tsval))
            # TLS ClientHello（握手已进行）
            payload=tcp[doff:]
            if payload[:1]==b'\x16':
                r=parse_tls_clienthello(payload)
                if r: ja3[src].add(r[0]); (sni[src].add(r[1]) if r[1] else None)
    # 输出
    ips=set(tcpfp)|set(ja3)
    for ip in sorted(ips):
        print(f"\n=== {ip} ===")
        for fp in tcpfp.get(ip,[]): print(f"  TCP指纹 : {fp}")
        # 时钟频率
        tv=sorted(tsvals.get(ip,[]))
        if len(tv)>=2:
            (t0,v0),(t1,v1)=tv[0],tv[-1]
            if t1>t0: print(f"  时钟频率 : {round((v1-v0)/(t1-t0))} Hz  (样本{len(tv)}, 跨{round(t1-t0)}s)")
        pl=ports.get(ip,[])
        if pl: print(f"  连的端口 : {sorted(set(pl))}  (共{len(pl)}个SYN)")
        print(f"  连上了吗 : {'是(有SYN-ACK)' if ip in connected else '否(只SYN/被挡)'}")
        for j in ja3.get(ip,[]): print(f"  JA3     : {j}")
        for s in sni.get(ip,[]):
            if s: print(f"  SNI     : {s}")

if __name__=="__main__":
    if len(sys.argv)<2: print("用法: python3 extract.py a.pcap [b.pcap ...]"); sys.exit(1)
    run(sys.argv[1:])
