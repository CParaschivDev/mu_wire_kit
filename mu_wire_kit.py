#!/usr/bin/env python3
import argparse, socket, threading, time, binascii, collections, csv, sys
from pathlib import Path

def hexdump(b: bytes) -> str:
    import binascii
    return binascii.hexlify(b).decode()

def nowts():
    return time.strftime("%Y-%m-%d %H:%M:%S")

class MUStreamSplitter:
    def __init__(self):
        self.buf = bytearray()
    def feed(self, data: bytes):
        self.buf.extend(data)
        out = []
        while True:
            if len(self.buf) < 3:
                break
            h = self.buf[0]
            if h == 0xC1:
                if len(self.buf) < 3: break
                total = self.buf[1]
                if total <= 0 or len(self.buf) < total: break
                head = self.buf[2] if total >= 3 else 0
                sub = self.buf[3] if total >= 4 else None
                pkt = bytes(self.buf[:total])
                payload = pkt[3:]
                out.append(("C1", total, head, sub, payload, pkt))
                del self.buf[:total]
            elif h == 0xC2:
                if len(self.buf) < 4: break
                total = (self.buf[1] << 8) | self.buf[2]
                if total <= 0 or len(self.buf) < total: break
                head = self.buf[3] if total >= 4 else 0
                sub = self.buf[4] if total >= 5 else None
                pkt = bytes(self.buf[:total])
                payload = pkt[4:]
                out.append(("C2", total, head, sub, payload, pkt))
                del self.buf[:total]
            elif h == 0xC3:
                if len(self.buf) < 3: break
                total = self.buf[1]
                if total <= 0 or len(self.buf) < total: break
                head = self.buf[2] if total >= 3 else 0
                sub = self.buf[3] if total >= 4 else None
                pkt = bytes(self.buf[:total])
                payload = pkt[3:]
                out.append(("C3", total, head, sub, payload, pkt))
                del self.buf[:total]
            elif h == 0xC4:
                if len(self.buf) < 4: break
                total = (self.buf[1] << 8) | self.buf[2]
                if total <= 0 or len(self.buf) < total: break
                head = self.buf[3] if total >= 4 else 0
                sub = self.buf[4] if total >= 5 else None
                pkt = bytes(self.buf[:total])
                payload = pkt[4:]
                out.append(("C4", total, head, sub, payload, pkt))
                del self.buf[:total]
            else:
                del self.buf[0]
        return out


# ---- PCAP writer (synthetic IPv4+UDP) --------------------------------------
class PcapWriter:
    def __init__(self, path, dgram_ports):
        # dgram_ports = (src_port, dst_port) we will swap for direction
        self.path = Path(path)
        self.f = self.path.open("wb")
        # Global header (pcap LE, v2.4, LINKTYPE_RAW=101)
        self.f.write(b'\xd4\xc3\xb2\xa1' + b'\x02\x00' + b'\x04\x00' + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00' + b'\xff\xff\x00\x00' + b'\x65\x00\x00\x00')
        self.dgram_ports = dgram_ports
    def _ts(self):
        import time
        t = time.time()
        sec = int(t)
        usec = int((t - sec) * 1_000_000)
        return sec, usec
    def _ipv4_udp_packet(self, src_ip, dst_ip, src_port, dst_port, payload):
        import ipaddress, struct
        src = int(ipaddress.IPv4Address(src_ip))
        dst = int(ipaddress.IPv4Address(dst_ip))
        udp_len = 8 + len(payload)
        # IPv4 header (20 bytes)
        ver_ihl = 0x45; tos = 0
        total_len = 20 + udp_len
        identification = 0; flags_frag = 0
        ttl = 64; proto = 17; hdr_checksum = 0
        ipv4 = struct.pack("!BBHHHBBHII", ver_ihl, tos, total_len, identification, flags_frag, ttl, proto, hdr_checksum, src, dst)
        udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
        return ipv4 + udp
    def write_frame(self, src_ip, dst_ip, payload, direction):
        sec, usec = self._ts()
        sp, dp = self.dgram_ports if direction == "C→S" else (self.dgram_ports[1], self.dgram_ports[0])
        pkt = self._ipv4_udp_packet(src_ip, dst_ip, sp, dp, payload)
        incl_len = orig_len = len(pkt)
        self.f.write(sec.to_bytes(4, "little"))
        self.f.write(usec.to_bytes(4, "little"))
        self.f.write(incl_len.to_bytes(4, "little"))
        self.f.write(orig_len.to_bytes(4, "little"))
        self.f.write(pkt)
    def close(self):
        try: self.f.close()
        except: pass

class ProxyLogger:
    def __init__(self, listen_host, listen_port, target_host, target_port, log_path, only_dir=None, only_head=None, only_sub=None, xor_key_hex=None, strip_last_checksum=False, pcap_path=None):
        self.listen = (listen_host, listen_port)
        self.target = (target_host, target_port)
        self.log_path = Path(log_path)
        self.only_dir = only_dir
        self.only_head = set(int(x,16) for x in only_head.split(',')) if only_head else None
        self.only_sub = set(int(x,16) for x in only_sub.split(',')) if only_sub else None
        self.xor_key = bytes.fromhex(xor_key_hex) if xor_key_hex else None
        self.strip_last_checksum = strip_last_checksum
        self.pcap = PcapWriter(pcap_path, (50000, 50001)) if pcap_path else None
    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(self.listen)
        srv.listen(5)
        print(f"[{nowts()}] proxy listening on {self.listen[0]}:{self.listen[1]} → {self.target[0]}:{self.target[1]}")
        with self.log_path.open("a", encoding="utf-8") as fp:
            fp.write(f"# MU Wire Kit log started {nowts()}\n")
        while True:
            client, addr = srv.accept()
            print(f"[{nowts()}] client connected from {addr}")
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.connect(self.target)
            split_c2s = MUStreamSplitter()
            split_s2c = MUStreamSplitter()
            stop_flag = {"stop": False}
            def pump(src, dst, direction):
                splitter = split_c2s if direction == "C→S" else split_s2c
                with self.log_path.open("a", encoding="utf-8") as fp:
                    while not stop_flag["stop"]:
                        try:
                            data = src.recv(65535)
                            if not data: break
                            dst.sendall(data)
                            frames = splitter.feed(data)
                            for header, length, head, sub, payload, raw in frames:
                                # Optional decode for C3/C4 payload (XOR key) and strip checksum
                                decoded_payload = payload
                                if header in ("C3","C4") and self.xor_key:
                                    k = self.xor_key
                                    decoded_payload = bytes(b ^ k[i % len(k)] for i,b in enumerate(payload))
                                if self.strip_last_checksum and len(decoded_payload) > 0:
                                    decoded_payload = decoded_payload[:-1]
                                # Write to PCAP as synthetic UDP
                                if self.pcap is not None:
                                    self.pcap.write_frame(self.listen[0], self.target[0], raw, direction)

                                if self.only_dir and direction != self.only_dir:
                                    continue
                                if self.only_head is not None and head not in self.only_head:
                                    continue
                                if self.only_sub is not None and (sub is None or sub not in self.only_sub):
                                    continue
                                line = f"{direction} {header} head={head:02X} sub={sub:02X if sub is not None else 0} len={length:04d} hex={hexdump(raw)}"
                                print(f"[{nowts()}] {line}")
                                fp.write(line + "\n")
                                fp.flush()
                        except Exception as e:
                            break
                try:
                    src.shutdown(socket.SHUT_RDWR)
                except: pass
                try:
                    src.close()
                except: pass
            def mark_loop():
                try:
                    while not stop_flag["stop"]:
                        s = sys.stdin.readline()
                        if not s: break
                        with self.log_path.open("a", encoding="utf-8") as fp:
                            fp.write(f"# FOCUS MARK {nowts()}\n")
                            fp.flush()
                except Exception:
                    pass
            tm = threading.Thread(target=mark_loop, daemon=True)
            tm.start()
            t1 = threading.Thread(target=pump, args=(client, server, "C→S"), daemon=True)
            t2 = threading.Thread(target=pump, args=(server, client, "S→C"), daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()
            stop_flag["stop"] = True
            try:
                server.close(); client.close()
            except: pass
            if self.pcap is not None:
                try: self.pcap.close()
                except: pass
            print(f"[{nowts()}] connection closed")

def parse_log_lines(lines):
    import collections
    MUFrame = collections.namedtuple("MUFrame", "dir header length head sub payload_hex raw_hex")
    frames = []
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"): continue
        try:
            parts = ln.split()
            direction = parts[0]; header = parts[1]
            head = int(parts[2].split("=")[1], 16)
            sub_s = parts[3].split("=")[1]; sub = int(sub_s, 16) if sub_s else None
            length = int(parts[4].split("=")[1])
            hexstr = parts[5].split("=")[1]
            frames.append(MUFrame(direction, header, length, head, sub, "", hexstr))
        except Exception:
            pass
    return frames

def analyze_log(log_path, yaml_out=None, csv_out=None):
    lines = Path(log_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    frames = parse_log_lines(lines)
    import collections, csv
    counter = collections.Counter((f.dir, f.header, f.head, f.sub if f.sub is not None else -1, f.length) for f in frames)
    rows = []
    for (d,h,hd,sb,l), cnt in counter.most_common():
        rows.append({"dir": d, "header": h, "head": f"0x{hd:02X}", "sub": ("0x%02X" % sb) if sb>=0 else "-", "length": l, "count": cnt})
    if csv_out:
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["dir","header","head","sub","length","count"])
            w.writeheader()
            for r in rows:
                w.writerow(r)
    if yaml_out:
        y = ["# proto map"]
        for r in rows:
            name = f"{'CG' if r['dir']=='C→S' else 'GC'}_{r['head']}_{r['sub']}"
            y += [
                f"- name: {name}",
                f"  dir: {'C2S' if r['dir']=='C→S' else 'S2C'}",
                f"  header: {r['header']}",
                f"  head: {r['head']}",
                f"  sub: {r['sub']}",
                f"  length: {r['length']}",
                f"  note: fill after inspecting payload",
            ]
        Path(yaml_out).write_text("\n".join(y), encoding="utf-8")
    return rows

def generate_stubs(yaml_path, out_dir, style='basic'):
    text = Path(yaml_path).read_text(encoding="utf-8")
    blocks = [b for b in text.split("- name: ") if b.strip()]
    entries = []
    for b in blocks:
        lines = [x.strip() for x in b.splitlines() if x.strip()]
        name = lines[0].strip()
        rec = {"name": name}
        for line in lines[1:]:
            if ":" in line:
                k,v = line.split(":",1)
                rec[k.strip()] = v.strip()
        entries.append(rec)
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    recv_cases = []
    send_decls = []
    for e in entries:
        if e.get("dir")=="C2S":
            recv_cases += [
                f'    // {e["name"]} len={e.get("length","?")}',
                f'    case 0x{int(e.get("head","0x00"),16):02X}:',
                f'      // TODO parse sub={e.get("sub","-")} ; Handle_{e["name"]}(obj, p, len);',
                f'      break;',
            ]
        else:
            send_decls.append(f'void Send_{e["name"]}(OBJECT_STRUCT* o /*, fields */);')
    if style == "muemu":
        recv_cpp = "\n".join([
            "// Auto-generated MUEMU-style recv dispatcher skeleton",
            "#include \"Protocol.h\"",
            "void OnRecv_F3(OBJECT_STRUCT* lpObj, BYTE* aRecv, int aLen) {",
            "  PSBMSG_HEAD *lpHead = (PSBMSG_HEAD*)aRecv;",
            "  BYTE sub = lpHead->sub;",
            "  switch (sub) {",
            *recv_cases,
            "    default: LogAdd(\"[OnRecv_F3] unknown sub=%02X len=%d\", sub, aLen); break;",
            "  }",
            "}",
            ""
        ])
        send_h = "\n".join([
            "// Auto-generated MUEMU-style send declarations",
            "#pragma once",
            "#include \"Protocol.h\"",
            "struct OBJECT_STRUCT;",
            *send_decls,
            ""
        ])
    else:
        recv_cpp = "\n".join([
        "// Auto-generated recv dispatcher skeleton",
        "void OnRecv_F3(OBJECT_STRUCT* obj, BYTE* p, int len) {",
        "  BYTE sub = p[3]; // adjust if C2",
        "  switch (sub) {",
        *recv_cases,
        "    default: LogAdd(\"[OnRecv_F3] unknown sub=%02X len=%d\", sub, len); break;",
        "  }",
        "}",
        ""
    ])
    send_h = "\n".join([
        "// Auto-generated send declarations",
        "#pragma once",
        "struct OBJECT_STRUCT;",
        *send_decls,
        ""
    ])
    (out/"recv_dispatcher.cpp").write_text(recv_cpp, encoding="utf-8")
    (out/"send_stubs.h").write_text(send_h, encoding="utf-8")
    return str(out)

def main():
    ap = argparse.ArgumentParser(description="MU Wire Kit - proxy/analyze/gen")
    sub = ap.add_subparsers(dest="cmd")

    ap_proxy = sub.add_parser("proxy", help="run TCP proxy and log MU packets")
    ap_proxy.add_argument("--listen", required=True, help="listen host:port (e.g., 0.0.0.0:55901)")
    ap_proxy.add_argument("--target", required=True, help="target host:port (e.g., 127.0.0.1:55901)")
    ap_proxy.add_argument("--log", required=True, help="log file path")
    ap_proxy.add_argument("--only-dir", choices=["C→S","S→C"], help="log only one direction")
    ap_proxy.add_argument("--only-head", help="comma list of headcodes to keep (hex, e.g., F3,FB)")
    ap_proxy.add_argument("--only-sub", help="comma list of subcodes to keep (hex, e.g., 03,30)")
    ap_proxy.add_argument("--xor-key", help="hex key for C3/C4 XOR decode (e.g., 11aa22bb)")
    ap_proxy.add_argument("--strip-last-checksum", action="store_true", help="drop last byte of payload for simple checksumed packets")
    ap_proxy.add_argument("--pcap", help="write a .pcap file (synthetic IPv4+UDP frames)")

    ap_pmulti = sub.add_parser("proxy-multi", help="run multiple proxies at once")
    ap_pmulti.add_argument("--pairs", required=True, help="comma-separated listen->target pairs, e.g. 0.0.0.0:44405->127.0.0.1:44405,0.0.0.0:55901->127.0.0.1:55901")
    ap_pmulti.add_argument("--logdir", required=True, help="directory for logs")
    ap_pmulti.add_argument("--only-dir", choices=["C→S","S→C"], help="log only one direction")
    ap_pmulti.add_argument("--only-head", help="comma list of headcodes to keep (hex)")
    ap_pmulti.add_argument("--only-sub", help="comma list of subcodes to keep (hex)")
    ap_pmulti.add_argument("--xor-key", help="hex key for C3/C4 XOR decode")
    ap_pmulti.add_argument("--strip-last-checksum", action="store_true")
    ap_pmulti.add_argument("--pcap", action="store_true", help="write a .pcap per pair (in --logdir)")

    ap_ana = sub.add_parser("analyze", help="analyze a log file")
    ap_x = sub.add_parser("extract", help="extract a log slice between two focus marks")
    ap_x.add_argument("--log", required=True)
    ap_x.add_argument("--out", required=True)
    ap_x.add_argument("--start", type=int, default=1)
    ap_x.add_argument("--end", type=int, default=2)

    ap_ana.add_argument("--log", required=True, help="log file path")
    ap_ana.add_argument("--yaml", required=True, help="proto yaml out")
    ap_ana.add_argument("--csv", required=True, help="heatmap csv out")

    ap_gen = sub.add_parser("gen", help="generate C++ stubs from proto yaml")
    ap_genp = sub.add_parser("gen-parsers", help="generate C++ struct parsers from YAML field templates")
    ap_genp.add_argument("--yaml", required=True)
    ap_genp.add_argument("--out", required=True)
    ap_gen.add_argument("--yaml", required=True, help="proto yaml in")
    ap_gen.add_argument("--out", required=True, help="output dir for stubs")
    ap_gen.add_argument("--style", choices=["basic","muemu"], default="basic", help="stub style")

    args = ap.parse_args()
    if args.cmd == "proxy":
        lh, lp = args.listen.split(":"); th, tp = args.target.split(":")
        ProxyLogger(lh, int(lp), th, int(tp), args.log, only_dir=args.only_dir, only_head=args.only_head, only_sub=args.only_sub, xor_key_hex=args.xor_key, strip_last_checksum=args.strip_last_checksum, pcap_path=args.pcap).run()
    elif args.cmd == "proxy-multi":
        from threading import Thread
        Path(args.logdir).mkdir(parents=True, exist_ok=True)
        threads = []
        for pair in args.pairs.split(","):
            listen, arrow, target = pair.partition("->")
            lh, lp = listen.split(":"); th, tp = target.split(":")
            logf = str(Path(args.logdir)/f"{lh.replace(":","_")}_{lp}_to_{th.replace(":","_")}_{tp}.log")
            pcapf = str(Path(args.logdir)/f"{lh.replace(':','_')}_{lp}_to_{th.replace(':','_')}_{tp}.pcap") if args.pcap else None
            proxy = ProxyLogger(lh, int(lp), th, int(tp), logf, only_dir=args.only_dir, only_head=args.only_head, only_sub=args.only_sub, xor_key_hex=args.xor_key, strip_last_checksum=args.strip_last_checksum if hasattr(args, "strip_last_checksum") else args.strip_last_checksum, pcap_path=pcapf)
            t = Thread(target=proxy.run, daemon=True)
            t.start(); threads.append(t)
        print("proxy-multi running", len(threads), "proxies… (Ctrl+C to stop)")
        for t in threads: t.join()
    elif args.cmd == "extract":
        cnt = extract_log(args.log, args.out, args.start, args.end)
        print(f"[{nowts()}] extracted {cnt} lines to {args.out}")
    elif args.cmd == "analyze":
        rows = analyze_log(args.log, yaml_out=args.yaml, csv_out=args.csv)
        print(f"[{nowts()}] analyzed {len(rows)} unique (dir, header, head, sub, length) entries")
    elif args.cmd == "gen":
        outdir = generate_stubs(args.yaml, args.out, style=args.style)
        print(f"[{nowts()}] generated stubs in {outdir}")
    elif args.cmd == "gen-parsers":
        outdir = generate_parsers(args.yaml, args.out)
        print(f"[{nowts()}] generated parsers in {outdir}")
    else:
        print("Use subcommands: proxy | analyze | gen")

if __name__ == "__main__":
    main()

def extract_log(log_path, out_path, start_mark=1, end_mark=2):
    lines = Path(log_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    marks = [i for i,l in enumerate(lines) if l.startswith("# FOCUS MARK ")]
    if len(marks) < end_mark:
        raise SystemExit(f"Not enough marks in log (have {len(marks)}, need {end_mark})")
    s = marks[start_mark-1]+1
    e = marks[end_mark-1]
    out = "\n".join(lines[s:e])
    Path(out_path).write_text(out, encoding="utf-8")
    return e - s

def generate_parsers(yaml_path, out_dir):
    import re
    text = Path(yaml_path).read_text(encoding="utf-8")
    blocks = [b for b in text.split("- name: ") if b.strip()]
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    h_lines = ["#pragma once", "#include <cstdint>", "#include <vector>", "struct PacketView { const uint8_t* p; size_t n; };"]
    cpp_lines = ['#include "parsers.h"', "static inline uint16_t LE16(const uint8_t* p){ return (uint16_t)p[0] | ((uint16_t)p[1]<<8);}",
                 "static inline uint32_t LE32(const uint8_t* p){ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);}"]
    for b in blocks:
        lines = [x.strip() for x in b.splitlines() if x.strip()]
        name = lines[0].strip()
        kv = {}
        for line in lines[1:]:
            if ":" in line:
                k,v = line.split(":",1); kv[k.strip()] = v.strip()
        if "fields" in kv and "record_size" in kv:
            inner = kv["fields"].strip().strip("[]")
            parts = [x.strip() for x in inner.split(",") if x.strip()]
            flds = []
            for pz in parts:
                if ":" in pz:
                    nm, ty = [y.strip() for y in pz.split(":",1)]
                    flds.append((nm, ty))
            struct_name = name.replace("/","_").replace(" ","_")
            h_lines.append(f"struct {struct_name} {{")
            for nm, ty in flds:
                cty = "uint8_t" if ty in ("u1","byte") else ("uint16_t" if ty in ("u2","le16") else ("uint32_t" if ty in ("u4","le32") else "uint8_t"))
                h_lines.append(f"  {cty} {nm};")
            h_lines.append("};")
            h_lines.append(f"bool Parse_{struct_name}(PacketView v, {struct_name}& out);")
            cpp_lines.append(f"bool Parse_{struct_name}(PacketView v, {struct_name}& o){{")
            cpp_lines.append("  const uint8_t* p=v.p; size_t n=v.n; size_t off=0;")
            m = re.search(r'(\d+)', kv["record_size"])
            recsz = int(m.group(1)) if m else 0
            if recsz>0:
                cpp_lines.append(f"  if(n < {recsz}) return false;")
            for nm, ty in flds:
                if ty in ("u1","byte"):
                    cpp_lines.append(f"  o.{nm} = p[off]; off += 1;")
                elif ty in ("u2","le16"):
                    cpp_lines.append(f"  o.{nm} = LE16(p+off); off += 2;")
                elif ty in ("u4","le32"):
                    cpp_lines.append(f"  o.{nm} = LE32(p+off); off += 4;")
                else:
                    cpp_lines.append(f"  /* TODO: type {ty} */")
            cpp_lines.append("  return true; }")
    (out/'parsers.h').write_text("\n".join(h_lines)+"\n", encoding="utf-8")
    (out/'parsers.cpp').write_text("\n".join(cpp_lines)+"\n", encoding="utf-8")
    return str(out)
