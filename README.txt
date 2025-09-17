MU Wire Kit (mini)
==================
A tiny toolkit to:
  1) Proxy MU client↔server traffic and log MU C1/C2 packets
  2) Analyze logs into a protocol heatmap + YAML
  3) Generate C++ recv/ send stub templates from that YAML

Files:
  - mu_wire_kit.py  (single-script CLI)

Quick start:

  # 1) Run proxy in front of your GameServer port (example 55901)
  python mu_wire_kit.py proxy --listen 0.0.0.0:55901 --target 127.0.0.1:55901 --log ./mu.log

  # Point your client to 127.0.0.1:55901 (hosts/serverlist). Do a short session:
  # Login -> CharList -> MapJoin -> open Shop -> (open MST/event panel) -> close

  # 2) Analyze the log
  python mu_wire_kit.py analyze --log ./mu.log --yaml ./proto.yaml --csv ./heatmap.csv

  # 3) Generate C++ stubs
  python mu_wire_kit.py gen --yaml ./proto.yaml --out ./stubs

Tips:
  - Run separate proxies for each port you care about (ConnectServer, GameServer).
  - Keep captures SHORT and focused on a single UI flow to isolate 3–8 packets quickly.
  - The YAML is intentionally simple; edit field notes as you learn payload structures.
  - Re-run 'analyze' after a new capture to grow your proto map incrementally.


Advanced usage:

  # Multi-port capture (ConnectServer + GameServer)
  python mu_wire_kit.py proxy-multi --pairs 0.0.0.0:44405->127.0.0.1:44405,0.0.0.0:55901->127.0.0.1:55901 --logdir ./logs

  # Filter just F3 subcodes 03 and 30 from client→server
  python mu_wire_kit.py proxy --listen 0.0.0.0:55901 --target 127.0.0.1:55901 --log ./mu.log --only-dir C→S --only-head F3 --only-sub 03,30

  # Generate MuEmu-style stubs
  python mu_wire_kit.py gen --yaml ./proto.yaml --out ./stubs --style muemu

New features
------------
PCAP writer (open in Wireshark):
  # single port
  python mu_wire_kit.py proxy --listen 0.0.0.0:55901 --target 127.0.0.1:55901 --log ./mu.log --pcap ./mu.pcap
  # multi-port writes one .pcap per pair (to --logdir)
  python mu_wire_kit.py proxy-multi --pairs 0.0.0.0:44405->127.0.0.1:44405,0.0.0.0:55901->127.0.0.1:55901 --logdir ./logs --pcap

C3/C4 XOR + checksum options:
  --xor-key 11aa22bb         # XOR-decode C3/C4 payloads with this repeating key
  --strip-last-checksum      # drop last byte (simple checksum) before analysis/pcap

Focus mode (interactive marks):
  # while proxy runs, press ENTER in the console to insert a '# FOCUS MARK' line
  # later, slice that window and analyze just those packets:
  python mu_wire_kit.py extract --log ./mu.log --out ./focus.log --start 1 --end 2
  python mu_wire_kit.py analyze --log ./focus.log --yaml ./focus.yaml --csv ./focus.csv

YAML field templates → struct parsers:
  # add to your YAML entry e.g.:
  # - name: GC_F3_30
  #   dir: S2C
  #   header: C2
  #   head: 0xF3
  #   sub: 0x30
  #   record_size: 16
  #   fields: [eventId:u1, status:u1, minutes:u2, minLevel:u2, map:u1, feeItem:u2, feeCount:u2, pad:u5]
  python mu_wire_kit.py gen-parsers --yaml ./focus.yaml --out ./parsers
