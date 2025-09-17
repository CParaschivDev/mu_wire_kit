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
            else:
                del self.buf[0]
        return out

class ProxyLogger:
    def __init__(self, listen_host, listen_port, target_host, target_port, log_path):
        self.listen = (listen_host, listen_port)
        self.target = (target_host, target_port)
        self.log_path = Path(log_path)
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
            t1 = threading.Thread(target=pump, args=(client, server, "C→S"), daemon=True)
            t2 = threading.Thread(target=pump, args=(server, client, "S→C"), daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()
            stop_flag["stop"] = True
            try:
                server.close(); client.close()
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

def generate_stubs(yaml_path, out_dir):
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

    ap_ana = sub.add_parser("analyze", help="analyze a log file")
    ap_ana.add_argument("--log", required=True, help="log file path")
    ap_ana.add_argument("--yaml", required=True, help="proto yaml out")
    ap_ana.add_argument("--csv", required=True, help="heatmap csv out")

    ap_gen = sub.add_parser("gen", help="generate C++ stubs from proto yaml")
    ap_gen.add_argument("--yaml", required=True, help="proto yaml in")
    ap_gen.add_argument("--out", required=True, help="output dir for stubs")

    args = ap.parse_args()
    if args.cmd == "proxy":
        lh, lp = args.listen.split(":"); th, tp = args.target.split(":")
        ProxyLogger(lh, int(lp), th, int(tp), args.log).run()
    elif args.cmd == "analyze":
        rows = analyze_log(args.log, yaml_out=args.yaml, csv_out=args.csv)
        print(f"[{nowts()}] analyzed {len(rows)} unique (dir, header, head, sub, length) entries")
    elif args.cmd == "gen":
        outdir = generate_stubs(args.yaml, args.out)
        print(f"[{nowts()}] generated stubs in {outdir}")
    else:
        print("Use subcommands: proxy | analyze | gen")

if __name__ == "__main__":
    main()
