# Kubernetes Deployment

Deploy mcp-coroot with Streamable HTTP transport in Kubernetes.

## Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: coroot-mcp-credentials
  namespace: monitoring
type: Opaque
stringData:
  COROOT_BASE_URL: "http://coroot.monitoring.svc.cluster.local:8080"
  COROOT_USERNAME: "admin"
  COROOT_PASSWORD: "your-password"
  MCP_AUTH_TOKEN: "your-bearer-token"
```

## Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coroot-mcp-server
  namespace: monitoring
  labels:
    app: coroot-mcp-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: coroot-mcp-server
  template:
    metadata:
      labels:
        app: coroot-mcp-server
    spec:
      containers:
        - name: mcp-coroot
          image: random1st/mcp-coroot:latest
          ports:
            - containerPort: 8000
              name: http
              protocol: TCP
          env:
            - name: COROOT_BASE_URL
              valueFrom:
                secretKeyRef:
                  name: coroot-mcp-credentials
                  key: COROOT_BASE_URL
            - name: COROOT_USERNAME
              valueFrom:
                secretKeyRef:
                  name: coroot-mcp-credentials
                  key: COROOT_USERNAME
            - name: COROOT_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: coroot-mcp-credentials
                  key: COROOT_PASSWORD
            - name: MCP_AUTH_TOKEN
              valueFrom:
                secretKeyRef:
                  name: coroot-mcp-credentials
                  key: MCP_AUTH_TOKEN
          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          livenessProbe:
            tcpSocket:
              port: 8000
            initialDelaySeconds: 30
            periodSeconds: 30
          readinessProbe:
            tcpSocket:
              port: 8000
            initialDelaySeconds: 15
            periodSeconds: 10
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
```

## Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: coroot-mcp-server
  namespace: monitoring
  labels:
    app: coroot-mcp-server
spec:
  selector:
    app: coroot-mcp-server
  ports:
    - port: 8000
      targetPort: 8000
      protocol: TCP
      name: http
  type: ClusterIP
```

## Istio VirtualService (optional)

```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: coroot-mcp-server
  namespace: monitoring
spec:
  hosts:
    - crmcp.example.org
  gateways:
    - istio-system/istio-gateway
  http:
    - match:
        - uri:
            prefix: /
      route:
        - destination:
            host: coroot-mcp-server.monitoring.svc.cluster.local
            port:
              number: 8000
```

## Client Configuration

```json
{
  "mcpServers": {
    "coroot": {
      "url": "https://crmcp.example.org/mcp",
      "headers": {
        "Authorization": "Bearer your-bearer-token"
      }
    }
  }
}
```
