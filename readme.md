# cdns

A local DNS server to relay queries to public DNS-over-Https servers.

# Configuration

The configuration file uses [JSON](https://www.json.org) format. It includes an optional `address` string, a `groups` object and a `rules` array.

The `address` string specifies the address the server will listening on. `127.0.0.1:53` will be used by default if it is not specified in the configuration file.

Each key-value pair in `groups` specifies the group name and an array of servers. Each server consists of the URL of the DNS-over-HTTPS server and an optional array of well-known IPs for the server. The server URL should support POST for [RFC 8484](https://tools.ietf.org/html/rfc8484) UDP wire format.

Each `rule` in `rules` specifies a matching criterion for domains and the name of the server group to use for the matching domain. The matching criterion is a domain and will match any [subdomain](https://en.wikipedia.org/wiki/Subdomain) that is a child domain of it (including itself). For example, `example.com` matches:
- `example.com`
- `www.example.com`
- `a.b.example.com`

but does not match:
- `xample.com`
- `example.net`
- `example1.com`
- `2example.com`
- `www.exa3mple.com`

The rules are checked in the array order. If a rule matches the DNS query domain, the corresponding server group will be chosen, and the remaining rules are skipped.

If none of the rules matches the domain, the `default` group will be chosen if it exists, otherwise an arbitrary group will be chosen. The `groups` object should have at least one group specified. The `rules` array can be empty.

## Example Configuration

```json
{
    "groups": {
        "default": [
            {
                "url": "https://doh.pub/dns-query"
            },
            {
                "url": "https://dns.alidns.com/dns-query",
                "ips": [
                    "223.5.5.5",
                    "223.6.6.6",
                    "2400:3200::1",
                    "2400:3200:baba::1"
                ]
            }
        ],
        "overseas": [
            {
                "url": "https://cloudflare-dns.com/dns-query",
                "ips": [
                    "1.1.1.1",
                    "1.0.0.1",
                    "2606:4700:4700::1111",
                    "2606:4700:4700::1001"
                ]
            },
            {
                "url": "https://dns.google/dns-query",
                "ips": [
                    "8.8.8.8",
                    "8.8.4.4",
                    "2001:4860:4860::8888",
                    "2001:4860:4860::8844"
                ]
            }
        ]
    },
    "rules": [
        [
            "github.com",
            "overseas"
        ]
    ]
}
```

# Usage

Run `cdns /path/to/configuration.json`, it will listen on the specified address for DNS queries.
