# scanner run summary

## counts
```
{
  "sample_listed": 3,
  "l4_per_port": {
    "80": 3,
    "443": 2,
    "8080": 2
  },
  "l4_endpoints": 7,
  "l4_unique_ips": 3,
  "tarpit_ips_not_probed": 1,
  "sample_targets_per_port": 370225
}
```

## protocol_by_endpoint
```
{
  "not_attempted": 3,
  "tcp_only": 4
}
```

## tls_outcome_by_endpoint
```
{
  "None": 3,
  "tls_reset": 4
}
```

## final_hostname_status_by_row
```
{
  "no_hostname_evidence": 7
}
```

## dns_status_by_row
```
{}
```

## sni_confirmation_by_row
```
{}
```

## favicon_direct_by_endpoint
```
{}
```

## favicon_hostname_by_row
```
{}
```

## stage_seconds
```
{
  "sample_list": 0.0,
  "zmap": 0.0,
  "tls_direct": 0.0,
  "http_direct": 0.0,
  "ptr": 0.0,
  "candidates": 0.0,
  "dns_forward": 0.0,
  "sni_confirm": 0.0,
  "favicon": 0.0
}
```

## stage_errors
```
{}
```

- ips_with_verified_hostname: 0
- unique_ips: 3
- hostname_rows_with_ptr_and_certificate: 0
- tls_failed_but_sni_handshake_ok: 0
- wildcard_certificates: 0
- tarpit_suspect_ips: 2
- icons_declared_on_other_hosts: 0

## warnings
- sample list has 3 targets but the plan expected 370225; check raw/zmap/sample-*.
- port 80: hit rate 0.0008% is far below typical Internet rates; scan may be impaired (NAT, loss, filtering).
- port 443: hit rate 0.0005% is far below typical Internet rates; scan may be impaired (NAT, loss, filtering).
