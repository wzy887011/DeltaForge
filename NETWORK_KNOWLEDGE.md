# DeltaForge 8.7 Network Knowledge

## Ownership

`cloud-agent/mihomo_control.sh` owns the runtime relationship between the
Mihomo TUN, the private `clash-config.yaml`, and Puffer resource routes.

```text
clash-config.yaml
  -> DOMAIN,puffer...gcloudsvcs.com,DIRECT
  -> Mihomo Meta TUN
  -> resolve current Puffer IPv4 set
  -> /32 routes via the real wlan0 gateway in table wlan0
```

The `/32` routes are required because table `wlan0` has `default dev Meta`.
Without the exceptions, a Mihomo `DIRECT` socket is routed back into the TUN
and reports `no route to host` or timeout.

The controller snapshots config and route state before mutation, applies mode
`0600` to the credential file, tracks only routes it owns, and supports
`apply`, `refresh`, `status`, and `rollback`.

## Change Matrix

| Change | Required nodes |
|---|---|
| Puffer domain or port | `mihomo_control.sh`, runtime config, operations guide, verification |
| TUN interface or route table | `mihomo_control.sh`, collector, `verify_identity.sh` |
| Mihomo lifecycle | `deploy.sh`, `mihomo_control.sh`, operations guide |

## Cloud Evidence

Confirmed on 2026-07-29: KDL reached general GCloud endpoints, but Puffer
initialization failed. A domain-only DIRECT rule matched correctly; the direct
socket still required real-gateway host routes. Once those routes were added,
the game resource stage loaded normally.

Root execution and concealment are separate results. UID 0 is confirmed, while
kernel, container, SELinux, GPU, root-tool, process, and TUN evidence remain
independent verification surfaces.

## Green Frame Evidence

The 2026-07-29 capture shows a thin green border around the complete UE4
surface, and the border is present in both `screenrecord` and `screencap`.
That shape matches Android's hardware-layer update visualization controlled by
`debug.hwui.show_layers_updates`; it is not drawn by DeltaForge. Deployment
also disables the related dirty-region, overdraw, and HWUI profile diagnostics.
It also clears the SurfaceFlinger update-flash flag (`debug.sf.showupdates`).
The target application must be restarted for renderer state to be recreated.
