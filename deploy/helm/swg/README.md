# SWG Helm Chart

A Helm chart for deploying SWG (Secure Web Gateway) on Kubernetes.

## Prerequisites

- Kubernetes 1.21+
- Helm 3.0+
- CA certificate and private key

## Installation

### 1. Generate CA Certificate

```bash
# Using the swg CLI
swg -gen-ca
```

### 2. Create CA Secret

```bash
kubectl create namespace swg
kubectl create secret generic swg-ca-cert \
  --from-file=ca.crt=ca.crt \
  --from-file=ca.key=ca.key \
  -n swg
```

### 3. Install the Chart

```bash
# From the repository
helm install swg ./deploy/helm/swg -n swg

# With custom values
helm install swg ./deploy/helm/swg -n swg \
  --set replicaCount=3 \
  --set config.filter.domains[0]="ads.example.com"
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Image repository | `ghcr.io/acmacalister/swg` |
| `image.tag` | Image tag | Chart appVersion |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `config.server.addr` | Listen address | `:8080` |
| `config.filter.enabled` | Enable filtering | `true` |
| `config.filter.domains` | Domains to block | `[]` |
| `config.filter.reloadInterval` | Rule reload interval | `5m` |
| `config.logging.level` | Log level | `info` |
| `config.logging.format` | Log format | `json` |
| `caSecret.name` | CA secret name | `swg-ca-cert` |
| `caSecret.create` | Create CA secret | `false` |

## Examples

### Block specific domains

```yaml
config:
  filter:
    enabled: true
    domains:
      - "ads.example.com"
      - "*.tracking.com"
      - "malware.bad.com"
```

### High availability setup

```yaml
replicaCount: 5

resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 512Mi
```

### Create CA secret via Helm

```yaml
caSecret:
  create: true
  caCrt: "LS0tLS1CRUdJTi..."  # base64 encoded
  caKey: "LS0tLS1CRUdJTi..."  # base64 encoded
```

## Upgrading

```bash
helm upgrade swg ./deploy/helm/swg -n swg
```

## Uninstalling

```bash
helm uninstall swg -n swg
```

## Note on GoReleaser

GoReleaser does **not** natively support publishing Helm charts. To publish this chart:

1. Use [helm/chart-releaser](https://github.com/helm/chart-releaser) to package and release
2. Use [chart-releaser-action](https://github.com/helm/chart-releaser-action) in GitHub Actions
3. Host on a chart repository (GitHub Pages, ChartMuseum, etc.)

Example GitHub Action for chart publishing:

```yaml
name: Release Charts
on:
  push:
    branches:
      - main
    paths:
      - 'deploy/helm/**'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Configure Git
        run: |
          git config user.name "$GITHUB_ACTOR"
          git config user.email "$GITHUB_ACTOR@users.noreply.github.com"
      - name: Install Helm
        uses: azure/setup-helm@v3
      - name: Run chart-releaser
        uses: helm/chart-releaser-action@v1.6.0
        with:
          charts_dir: deploy/helm
        env:
          CR_TOKEN: "${{ secrets.GITHUB_TOKEN }}"
```
