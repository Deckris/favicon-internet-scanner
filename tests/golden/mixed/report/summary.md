# scanner run summary

## counts
```
{
  "sample_listed": 6,
  "l4_per_port": {
    "80": 2,
    "443": 4,
    "8080": 3
  },
  "l4_endpoints": 9,
  "l4_unique_ips": 6,
  "tarpit_ips_not_probed": 0,
  "sample_targets_per_port": 370225,
  "dns_unknown_share": 0.0,
  "favicon_images_stored": 2,
  "favicon_images_indexed": 2
}
```

## protocol_by_endpoint
```
{
  "http": 2,
  "https": 6,
  "tcp_only": 1
}
```

## tls_outcome_by_endpoint
```
{
  "not_tls": 2,
  "tls_alert_unrecognized_name": 1,
  "tls_reset": 1,
  "tls_success": 5
}
```

## final_hostname_status_by_row
```
{
  "no_hostname_evidence": 2,
  "nxdomain": 5,
  "resolved_elsewhere": 3,
  "verified": 9
}
```

## dns_status_by_row
```
{
  "multiple_a_including_target": 3,
  "nxdomain": 5,
  "resolved_elsewhere": 3,
  "verified_current_mapping": 6
}
```

## sni_confirmation_by_row
```
{
  "confirmed": 2,
  "failed": 2,
  "tls_ok_cert_mismatch": 3
}
```

## favicon_direct_by_endpoint
```
{
  "image": 7
}
```

## favicon_hostname_by_row
```
{
  "image": 9
}
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

- ips_with_verified_hostname: 3
- unique_ips: 6
- hostname_rows_with_ptr_and_certificate: 2
- tls_failed_but_sni_handshake_ok: 1
- wildcard_certificates: 5
- tarpit_suspect_ips: 0
- icons_declared_on_other_hosts: 0

## warnings
- sample list has 6 targets but the plan expected 370225; check raw/zmap/sample-*.
- port 80: hit rate 0.0005% is far below typical Internet rates; scan may be impaired (NAT, loss, filtering).
- port 443: hit rate 0.0011% is far below typical Internet rates; scan may be impaired (NAT, loss, filtering).
