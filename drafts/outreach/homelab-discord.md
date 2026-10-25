# Homelab / Sysmon / OTRF — 45 min ask

I built an open-source multi-host correlator (observe-only; no live quarantine).
I need someone who is **not me** to run a frozen packet and send hashes. I will
not sit on the call or type commands.

Pick one rung (~45 min):

1. Clone, `pip install -e .`, `corvex byo-windows` on the shipped Windows fixture, screenshot reconstruction gaps.
2. Fetch a public OTRF/Mordor slice and run `scripts/run_benign_baseline.py` (replication, not field proof).
3. Point it at **your** multi-host 4624/Sysmon JSON. You keep the raw logs.

Packet: https://github.com/Siddarthb07/corvex/blob/master/docs/external-operator-packet.md

Return: filled `operator_replication.json` + SHA-256 + one paragraph of what broke.
No retune. Agents do not count.
