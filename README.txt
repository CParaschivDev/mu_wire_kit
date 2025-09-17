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
