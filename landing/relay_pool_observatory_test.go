package landing

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
)

type observatoryOutboundStatus = ObservatoryOutboundStatus

func queryObservatoryStatus(ctx context.Context, apiAddress string) (map[string]observatoryOutboundStatus, error) {
	return QueryObservatoryStatus(ctx, apiAddress)
}

func encodeTestObservatoryResponse() []byte {
	encodeHP := func(all, fail int64, dev, avg, maxD, minD time.Duration) []byte {
		var b []byte
		b = protowire.AppendTag(b, 1, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(all))
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(fail))
		b = protowire.AppendTag(b, 3, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(dev))
		b = protowire.AppendTag(b, 4, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(avg))
		b = protowire.AppendTag(b, 5, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(maxD))
		b = protowire.AppendTag(b, 6, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(minD))
		return b
	}
	encodeStatus := func(alive bool, delay int64, errReason, tag string, hp []byte) []byte {
		var b []byte
		b = protowire.AppendTag(b, 1, protowire.VarintType)
		b = protowire.AppendVarint(b, protowire.EncodeBool(alive))
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(delay))
		if errReason != "" {
			b = protowire.AppendTag(b, 3, protowire.BytesType)
			b = protowire.AppendString(b, errReason)
		}
		b = protowire.AppendTag(b, 4, protowire.BytesType)
		b = protowire.AppendString(b, tag)
		if len(hp) > 0 {
			b = protowire.AppendTag(b, 7, protowire.BytesType)
			b = protowire.AppendBytes(b, hp)
		}
		return b
	}
	var resultMsg []byte
	resultMsg = protowire.AppendTag(resultMsg, 1, protowire.BytesType)
	resultMsg = protowire.AppendBytes(resultMsg, encodeStatus(true, 18, "", "route-l1-r0", encodeHP(3, 0, 2*time.Millisecond, 18*time.Millisecond, 21*time.Millisecond, 15*time.Millisecond)))
	resultMsg = protowire.AppendTag(resultMsg, 1, protowire.BytesType)
	resultMsg = protowire.AppendBytes(resultMsg, encodeStatus(false, 0, "timeout", "route-l1-r1", encodeHP(3, 3, 0, 0, 0, 0)))

	var respMsg []byte
	respMsg = protowire.AppendTag(respMsg, 1, protowire.BytesType)
	respMsg = protowire.AppendBytes(respMsg, resultMsg)
	return respMsg
}

func TestDecodeObservatoryResponse(t *testing.T) {
	got, err := DecodeObservatoryResponse(encodeTestObservatoryResponse())
	if err != nil {
		t.Fatalf("DecodeObservatoryResponse failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("decoded %d items, want 2", len(got))
	}
	if !got[0].Alive || got[0].OutboundTag != "route-l1-r0" || got[0].DelayMS != 18 || got[0].HealthPing == nil || got[0].HealthPing.All != 3 || got[0].HealthPing.Fail != 0 || got[0].HealthPing.Average != 18*time.Millisecond {
		t.Fatalf("unexpected first item: %+v %+v", got[0], got[0].HealthPing)
	}
	if got[1].Alive || got[1].OutboundTag != "route-l1-r1" || got[1].LastErrorReason != "timeout" || got[1].HealthPing == nil || got[1].HealthPing.All != 3 || got[1].HealthPing.Fail != 3 {
		t.Fatalf("unexpected second item: %+v %+v", got[1], got[1].HealthPing)
	}
	empty, err := DecodeObservatoryResponse(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty decode = %v %v, want empty nil", empty, err)
	}
	if _, err := DecodeObservatoryResponse([]byte{0x0a, 0x05, 0x01}); err == nil {
		t.Fatal("truncated protobuf unexpectedly accepted")
	}
}

type mockObservatoryService interface{}

type mockObservatoryServer struct{}

func TestQueryObservatoryStatusLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	payload := observatoryRawMessage(encodeTestObservatoryResponse())
	srv := grpc.NewServer(grpc.ForceServerCodec(observatoryRawCodec{}))
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "xray.core.app.observatory.command.ObservatoryService",
		HandlerType: (*mockObservatoryService)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "GetOutboundStatus",
				Handler: func(_ any, _ context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					var req observatoryRawMessage
					if err := dec(&req); err != nil {
						return nil, err
					}
					resp := payload
					return &resp, nil
				},
			},
		},
	}, mockObservatoryServer{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = ln.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := QueryObservatoryStatus(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("QueryObservatoryStatus failed: %v", err)
	}
	r0, ok0 := got["route-l1-r0"]
	r1, ok1 := got["route-l1-r1"]
	if !ok0 || !ok1 || !r0.Alive || r0.DelayMS != 18 || r1.Alive || r1.LastErrorReason != "timeout" {
		t.Fatalf("unexpected loopback observatory map: %+v", got)
	}
}
