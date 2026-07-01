# wiresight

Lightweight live traffic monitor built on scapy. Tracks flows between hosts, flags raw HTTP request lines, and prints a ranked flow summary on exit.

```
python sniffer.py -i eth0 -f "tcp port 80" -o capture.log
```

- `-i` interface
- `-f` BPF filter
- `-o` optional log file
- `-c` packet count cap (0 = unlimited)

Ctrl+C to stop and print top talkers by packet count.
