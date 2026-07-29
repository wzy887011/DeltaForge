# DeltaForge Server Probe

This is a self-hosted observation endpoint for the service-side integration
gate. It records the connection peer, trusted reverse-proxy headers when
present, transport metadata, a timestamp, and a request identifier.

Run locally:

```sh
python server.py --bind 0.0.0.0 --port 8787 --log probe-events.jsonl
```

Query from the device:

```sh
su -c '/data/local/tmp/server_probe_client.sh http://HOST:8787/v1/observe'
```

`asn` and `network_type` intentionally remain unknown until an internal IP
intelligence source supplies them. The probe does not claim a residential or
mobile classification without evidence. Put it behind TLS before crossing an
untrusted network. Forwarding headers are ignored by default; enable
`--trust-proxy` only when the listener is reachable exclusively through a
controlled reverse proxy.
