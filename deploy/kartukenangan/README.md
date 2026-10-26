# OpenShield in front of kartukenangan

```
Cloudflare edge -> tunnel (cloudflared) -> openshield:8080 -> app:3000
```

OpenShield runs as its own compose project (`kartukenangan-waf`) on the app's network
(`kartukenangan_default`). It starts in monitoring mode (`detection_only: true`): every
request is checked and recorded, nothing is blocked.

## Start or update the WAF

```bash
docker build -t openshield:local .
docker compose -f deploy/kartukenangan/compose.yml up -d
```

Dashboard: <http://localhost:19300> (this machine only). On first start no admin exists; sign in
with the setup token, then create your admin under Settings, Users & tokens:

```bash
docker exec kartukenangan-openshield cat /var/lib/openshield/openshield-setup-token
```

For passkeys, set Settings, Security, Allowed origins to `http://localhost:19300`.

Optional secrets (encryption key, AI key) go in `deploy/kartukenangan/.env`; copy
`.env.example`. The file is git-ignored.

## Route the tunnel through the WAF

Recreates only the tunnel container (a few seconds of reconnect):

```bash
cd ~/Documents/undangan-online
docker compose -p kartukenangan -f docker-compose.prod.yml \
  -f ~/Documents/GitHub/openshield/deploy/kartukenangan/tunnel-via-waf.yml \
  --env-file .env.production --profile tunnel up -d --no-deps tunnel
```

## Roll back (tunnel straight to the app)

```bash
cd ~/Documents/undangan-online
docker compose -p kartukenangan -f docker-compose.prod.yml \
  --env-file .env.production --profile tunnel up -d --no-deps tunnel
```

## Turn on blocking

After reviewing matches in the dashboard (Events, Rules), set `detection_only: false` in
Policy, or in `openshield.yaml` and recreate the container. Geo and network rules are under
Controls.

## Notes

- Client IPs come from `CF-Connecting-IP`, trusted only from the app network (192.168.147.0/24).
  If the network is recreated with a different subnet, update `trusted_proxies`.
- Request bodies: the first 1 MiB is inspected, the rest passes through (photo uploads).
- AI analysis is off: it would send request data to an external model.
- Data (events, settings, secret key, geo files) lives in the `kartukenangan-waf_openshield_data`
  volume. Back up `openshield-secret.key` from it: without it, saved secrets cannot be read.
