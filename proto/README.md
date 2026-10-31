# Glivela control protocol v1

`glivela/control/v1/control.proto` defines the native Glivela controller ↔ node
bidirectional gRPC stream. It uses Glivela's existing enrolled mTLS leaf identities
and private listener, independently of Vastora. The first capability is
`link-speed.v7` for eight-second measurements, live samples and independent direction results without traffic limits, including explicitly authorized IPv4/IPv6 client-chain pairs; BBR/FQ remains
owned by Glivela but is not migrated in this slice. Nodes without this capability
cannot start a task under this policy.

Client-chain tests use the existing enrolled identities, applied listener and
entry `speedPeers` policy. They create only leased test resources, never a
server-forwarding grant. The results measure entry-to-landing transport rather
than the user's full client chain. Controller and both nodes must be upgraded
together before this capability is available.

Generated files are committed under `internal/controlpb`. Reproduce using official
protoc 36.2, protoc-gen-go v1.36.12 and protoc-gen-go-grpc v1.6.2:

```sh
protoc --go_out=. --go_opt=module=github.com/petauron/glivela \
  --go-grpc_out=. --go-grpc_opt=module=github.com/petauron/glivela \
  proto/glivela/control/v1/control.proto
```

Tool binaries stay outside the repository. Runtime dependencies are pinned in
`go.mod`/`go.sum`. These add HTTP/2/gRPC/Protobuf maintenance and binary size;
no browser gRPC client, shared Vastora identity or new listener is introduced.
