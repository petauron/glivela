module github.com/petauron/glivela

go 1.26.0

toolchain go1.26.11

godebug multipathtcp=0

require (
	github.com/google/uuid v1.6.0
	golang.org/x/net v0.60.0
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260817212433-ac3dfec99bb1 // indirect
)
