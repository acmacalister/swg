# SWG Kubernetes Deployment

This directory contains Kubernetes manifests for deploying SWG (Secure Web Gateway) in a Kubernetes cluster.

## Prerequisites

1. A Kubernetes cluster (v1.21+)
2. `kubectl` configured to access your cluster
3. SWG CA certificate and private key

## Quick Start

### 1. Generate CA Certificate

Before deploying, generate a CA certificate:

```bash
# Using the swg CLI
swg -gen-ca

# This creates ca.crt and ca.key
```

### 2. Create the CA Secret

```bash
# Create the secret from generated files
kubectl create namespace swg
kubectl create secret generic swg-ca-cert \
  --from-file=ca.crt=ca.crt \
  --from-file=ca.key=ca.key \
  -n swg
```

### 3. Deploy SWG

```bash
# Apply all manifests
kubectl apply -f deploy/kubernetes/

# Or apply individually
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl apply -f deploy/kubernetes/service.yaml
```

### 4. Verify Deployment

```bash
# Check pods are running
kubectl get pods -n swg

# Check service
kubectl get svc -n swg

# View logs
kubectl logs -f deployment/swg -n swg
```

## Configuration

### ConfigMap

Edit `configmap.yaml` to customize SWG configuration:

- **server.addr**: Listen address (default `:8080`)
- **filter.domains**: List of domains to block
- **filter.reload_interval**: How often to reload rules
- **logging.level**: Log verbosity (`debug`, `info`, `warn`, `error`)

### Scaling

Adjust replicas in `deployment.yaml`:

```yaml
spec:
  replicas: 3  # Increase for high availability
```

### Resource Limits

Modify resource requests/limits based on your traffic:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 1000m
    memory: 512Mi
```

## External Access

To expose SWG externally, uncomment the LoadBalancer service in `service.yaml`, or use an Ingress controller.

### Using NodePort

```yaml
apiVersion: v1
kind: Service
metadata:
  name: swg-external
  namespace: swg
spec:
  type: NodePort
  selector:
    app.kubernetes.io/name: swg
  ports:
    - port: 8080
      nodePort: 30080
```

## Monitoring

### Health Checks

The deployment includes liveness and readiness probes on port 8080.

### Prometheus Metrics

To add Prometheus monitoring, add annotations to the pod:

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "9090"
```

## Troubleshooting

### Pod not starting

1. Check secret exists: `kubectl get secret swg-ca-cert -n swg`
2. Check configmap: `kubectl get configmap swg-config -n swg`
3. View pod events: `kubectl describe pod -n swg`

### Connection refused

1. Verify service: `kubectl get endpoints swg -n swg`
2. Check pod logs: `kubectl logs deployment/swg -n swg`

### Certificate errors

Ensure the CA certificate is:
1. Properly base64-encoded in the secret
2. Trusted by clients connecting through the proxy

## Security Considerations

- The CA private key is stored in a Kubernetes Secret
- Consider using a secrets management solution (Vault, Sealed Secrets)
- Run with `readOnlyRootFilesystem: true`
- Run as non-root user (UID 65534)
- No privilege escalation allowed
