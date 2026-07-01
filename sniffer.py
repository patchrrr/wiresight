import argparse 
import time 
import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw

class FlowTracker:
    def __init__(self):
        self.flows = {}

    def touch(self, key):
        now = time.time()
        if key not in self.flows:
            self.flows[key] = {"first": now, "last": now, "count": 0, "bytes": 0}
        self.flows[key]["last"] = now
        self.flows[key]["count"] += 1

    def report(self, top=10):
        ranked = sorted(self.flows.items(), key=lambda x: x[1]["count"], reverse=True)
        for key, stats in ranked[:top]:
            dur = stats["last"] - stats["first"]
            print(f"{key[0]:>15} <-> {key[1]:<15} proto={key[2]:<4} pkts={stats['count']:<6} dur={dur:.1f}s")

tracker = FlowTracker()
log_file = None

def handle(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
    sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
    dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)

    key = (src, dst, proto)
    tracker.touch(key)

    size = len(pkt)
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {src}:{sport} -> {dst}:{dport} {proto} {size}B"

    if Raw in pkt and proto == "TCP" and (sport == 80 or dport == 80):
        payload = bytes(pkt[Raw].load)[:64]
        if payload.startswith(b"GET") or payload.startswith(b"POST"):
            line += f" | {payload.split(chr(13).encode())[0].decode(errors='ignore')}"

    print(line)
    if log_file:
        log_file.write(line + "\n")
        log_file.flush()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", default=None)
    ap.add_argument("-f", "--filter", default="ip")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("-c", "--count", type=int, default=0)
    args = ap.parse_args()

    global log_file
    if args.out:
        log_file = open(args.out, "a")

    try:
        sniff(iface=args.iface, filter=args.filter, prn=handle, count=args.count, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n--- top flows ---")
        tracker.report()
        if log_file:
            log_file.close()

if __name__ == "__main__":
    main()
