# scanner run summary

## counts
```
{
  "sample_listed": 0,
  "l4_per_port": {
    "80": 0,
    "443": 0,
    "8080": 0
  },
  "l4_endpoints": 0,
  "l4_unique_ips": 0,
  "tarpit_ips_not_probed": 0,
  "sample_targets_per_port": 370225
}
```

## protocol_by_endpoint
```
{}
```

## tls_outcome_by_endpoint
```
{}
```

## final_hostname_status_by_row
```
{}
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
- unique_ips: 0
- hostname_rows_with_ptr_and_certificate: 0
- tls_failed_but_sni_handshake_ok: 0
- wildcard_certificates: 0
- tarpit_suspect_ips: 0
- icons_declared_on_other_hosts: 0

## warnings
- sample list has 0 targets but the plan expected 370225; check raw/zmap/sample-*.
- ZERO responsive endpoints: check egress/NAT (WSL2), ZMap interface/gateway settings and raw/stderr/*zmap*.txt.
