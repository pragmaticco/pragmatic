# Pragmatic Server on Kubernetes

These manifests run one Pragmatic Server per data volume:

- `statefulset.yaml`: a StatefulSet with `replicas: 1` and update strategy
  `OnDelete`. The server takes an exclusive lock on its data directory, so
  two pods must never share a volume; `OnDelete` means a new version starts
  only after you delete the old pod, never alongside it. The pod runs as a
  non-root user with a read-only root filesystem.
- `secret.yaml`: the Ed25519 signing key, mounted at
  `/etc/pragmatic/server.ed25519`, outside the data volume. Create it from a
  key file instead of committing one:
  `kubectl create secret generic pragmatic-signing-key --from-file=server.ed25519=./server.ed25519`.
- `configmap.yaml`: the configuration.
- `service.yaml` and `ingress.yaml`: TLS terminates at the ingress; the
  server listens on plain HTTP inside the cluster (`allow_plain_http = true`).

Apply with `kubectl apply -f .` after editing the configuration, the host
name in `ingress.yaml` and the storage class.

## Storage

The data volume holds journals, the access log, tokens (as hashes) and the
erasure ledger. Encrypting it is your responsibility, as is the region it
lives in. Use a storage class backed by a KMS-encrypted disk (for example an
AWS EBS `gp3` class with `encrypted: "true"` and a `kmsKeyId`, a GCE
persistent disk with a customer-managed encryption key, or an Azure disk
encryption set), and keep the cluster and volume in the region your data
must stay in. Backups (`pragmatic-server backup`) copy the same data and
need the same care.
