# RandMap

Randomized IP and Port Mapper

## Get last release

Check how to get last release by your Operational Systems procedures here [INSTALL.md](https://github.com/helviojunior/randmap/blob/main/INSTALL.md)


# Utilization

```
$ randmap -h

[:: RandMap ::] -// randomized ip & port feed for scans
     > inject chaos into your targets //

Usage:
  randmap rnd [flags]

Examples:

- randmap report dot --from-path ~/client_data/ --top-ports 100
- randmap report dot --from-path ~/client_data/ -p 80,443,445,3389
- randmap report dot --from-path ~/client_data/enumdns.sqlite3 --to-path ~/Desktop/ --top-ports 100


Flags:
      --disable-port-ratio      Disables sorting by port ratio when using --top-ports. Ports will be selected in linear order instead.
      --exclude strings         Exclude all IP or Network. You can specify multiple values by comma-separated terms or by repeating the flag.
  -I, --from-path strings       The file(s) or directory(ies) to convert from. You can specify multiple values by repeating the flag.
  -F, --full                    Include SaaS addresses to scan list
  -h, --help                    help for rnd
  -H, --hosts-per-scan int      Host count per scan instance (default 64)
      --include strings         Include only IP or Network. You can specify multiple values by comma-separated terms or by repeating the flag.
  -S, --max-same-subnet int     Number of same-subnet hosts scanned per scan (default 16)
  -m, --min-cidr-mask int       Defines the minimum subnet size (CIDR) to consider when expanding target hosts. Use /32 to treat each host individually, or a broader subnet like /27 to include nearby hosts. (default 27)
  -p, --port string             Only show specified ports. (Ex: -p22; -p1-65535; -p 53,111,137,21-25,80,139,8080)
  -P, --ports-per-host int      Number of ports scanned per host (default 128)
  -s, --scan-protocol strings   Protocol to scan (TCP or UDP). You can specify multiple values by comma-separated terms or by repeating the flag. (default [tcp])
  -o, --to-path string          The directory to store output files. (default "./randmap_out")
      --top-ports int           Show <number> most common ports

Global Flags:
  -D, --debug-log    Enable debug logging
      --local-temp   Store the temporary file in the current workspace
  -q, --quiet        Silence (almost all) logging

```


## Nmap command 

To generate the Nmap XML with certificate data use the followin parameters

1. `-A` or `--script ssl-cert`
2. `-oX` to save output to a XML

```bash
nmap -Pn -v -T4 -A -sTV -p $(tr '\n' , <scan_0001_ports.txt) -iL scan_0001_ips.txt -oX ~/Desktop/nmap.xml
```

## Disclaimer

This tool is intended for educational purpose or for use in environments where you have been given explicit/legal authorization to do so.