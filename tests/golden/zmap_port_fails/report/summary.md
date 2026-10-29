# scanner run summary

## counts
```
{
  "sample_listed": 5,
  "l4_per_port": {
    "80": 0,
    "443": 3,
    "8080": 1
  },
  "l4_endpoints": 4,
  "l4_unique_ips": 4,
  "tarpit_ips_not_probed": 0,
  "sample_targets_per_port": 370225,
  "dns_unknown_share": 0.0,
  "favicon_images_stored": 1,
  "favicon_images_indexed": 1
}
```

## protocol_by_endpoint
```
{
  "https": 3,
  "tcp_only": 1
}
```

## tls_outcome_by_endpoint
```
{
  "tls_alert_unrecognized_name": 1,
  "tls_reset": 1,
  "tls_success": 2
}
```

## final_hostname_status_by_row
```
{
  "no_hostname_evidence": 1,
  "nxdomain": 2,
  "resolved_elsewhere": 1,
  "verified": 2
}
```

## dns_status_by_row
```
{
  "nxdomain": 2,
  "resolved_elsewhere": 1,
  "verified_current_mapping": 2
}
```

## sni_confirmation_by_row
```
{
  "confirmed": 1,
  "tls_ok_cert_mismatch": 1
}
```

## favicon_direct_by_endpoint
```
{
  "image": 2
}
```

## favicon_hostname_by_row
```
{
  "image": 2
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
{
  "zmap:80": "OSError: zmap exploded"
}
```

- ips_with_verified_hostname: 2
- unique_ips: 4
- hostname_rows_with_ptr_and_certificate: 1
- tls_failed_but_sni_handshake_ok: 1
- wildcard_certificates: 2
- tarpit_suspect_ips: 0
- icons_declared_on_other_hosts: 0

## warnings
- sample list has 5 targets but the plan expected 370225; check raw/zmap/sample-*.
- port 80: hit rate 0.0000% is far below typical Internet rates; scan may be impaired (NAT, loss, filtering).
- port 443: hit rate 0.0008% is far below typical Internet rates; scan may be impaired (NAT, loss, filtering).
- 1 stage error(s) recorded; see manifest stage_errors.
