package landing

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
)

const xrayObservatoryStatusMethod = "/xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus"

type observatoryHealthPing struct {
	All       int64
	Fail      int64
	Deviation time.Duration
	Average   time.Duration
	Max       time.Duration
	Min       time.Duration
}

type observatoryOutboundStatus struct {
	Alive           bool
	DelayMS         int64
	LastErrorReason string
	OutboundTag     string
	LastSeenTime    int64
	LastTryTime     int64
	HealthPing      *observatoryHealthPing
}

type observatoryRawMessage []byte

type observatoryRawCodec struct{}

func (observatoryRawCodec) Marshal(v any) ([]byte, error) {
	raw, ok := v.(*observatoryRawMessage)
	if !ok {
		return nil, errors.New("observatory codec requires *observatoryRawMessage")
	}
	return append([]byte(nil), (*raw)...), nil
}

func (observatoryRawCodec) Unmarshal(data []byte, v any) error {
	raw, ok := v.(*observatoryRawMessage)
	if !ok {
		return errors.New("observatory codec requires *observatoryRawMessage")
	}
	*raw = append((*raw)[:0], data...)
	return nil
}

func (observatoryRawCodec) Name() string {
	return "proto"
}

// queryObservatoryStatus invokes Xray's local ObservatoryService gRPC API
// directly over loopback using existing gRPC/protobuf dependencies.
func queryObservatoryStatus(ctx context.Context, apiAddress string) (map[string]observatoryOutboundStatus, error) {
	conn, err := grpc.NewClient("passthrough:///"+apiAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var req, resp observatoryRawMessage
	if err := conn.Invoke(ctx, xrayObservatoryStatusMethod, &req, &resp, grpc.ForceCodec(observatoryRawCodec{})); err != nil {
		return nil, err
	}
	items, err := decodeObservatoryResponse(resp)
	if err != nil {
		return nil, err
	}
	result := make(map[string]observatoryOutboundStatus, len(items))
	for _, item := range items {
		result[item.OutboundTag] = item
	}
	return result, nil
}

func decodeObservatoryResponse(raw []byte) ([]observatoryOutboundStatus, error) {
	var out []observatoryOutboundStatus
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		raw = raw[n:]
		if num == 1 && typ == protowire.BytesType {
			msg, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
			items, err := decodeObservationResult(msg)
			if err != nil {
				return nil, err
			}
			out = append(out, items...)
			continue
		}
		skip := protowire.ConsumeFieldValue(num, typ, raw)
		if skip < 0 {
			return nil, protowire.ParseError(skip)
		}
		raw = raw[skip:]
	}
	return out, nil
}

func decodeObservationResult(raw []byte) ([]observatoryOutboundStatus, error) {
	var out []observatoryOutboundStatus
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		raw = raw[n:]
		if num == 1 && typ == protowire.BytesType {
			msg, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			raw = raw[m:]
			status, err := decodeOutboundStatus(msg)
			if err != nil {
				return nil, err
			}
			out = append(out, status)
			continue
		}
		skip := protowire.ConsumeFieldValue(num, typ, raw)
		if skip < 0 {
			return nil, protowire.ParseError(skip)
		}
		raw = raw[skip:]
	}
	return out, nil
}

func decodeOutboundStatus(raw []byte) (observatoryOutboundStatus, error) {
	var s observatoryOutboundStatus
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return observatoryOutboundStatus{}, protowire.ParseError(n)
		}
		raw = raw[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return observatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.Alive = protowire.DecodeBool(v)
			raw = raw[m:]
		case num == 2 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return observatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.DelayMS = int64(v)
			raw = raw[m:]
		case num == 3 && typ == protowire.BytesType:
			v, m := protowire.ConsumeString(raw)
			if m < 0 {
				return observatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.LastErrorReason = v
			raw = raw[m:]
		case num == 4 && typ == protowire.BytesType:
			v, m := protowire.ConsumeString(raw)
			if m < 0 {
				return observatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.OutboundTag = v
			raw = raw[m:]
		case num == 5 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return observatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.LastSeenTime = int64(v)
			raw = raw[m:]
		case num == 6 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return observatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.LastTryTime = int64(v)
			raw = raw[m:]
		case num == 7 && typ == protowire.BytesType:
			msg, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return observatoryOutboundStatus{}, protowire.ParseError(m)
			}
			hp, err := decodeHealthPingResult(msg)
			if err != nil {
				return observatoryOutboundStatus{}, err
			}
			s.HealthPing = &hp
			raw = raw[m:]
		default:
			skip := protowire.ConsumeFieldValue(num, typ, raw)
			if skip < 0 {
				return observatoryOutboundStatus{}, protowire.ParseError(skip)
			}
			raw = raw[skip:]
		}
	}
	return s, nil
}

func decodeHealthPingResult(raw []byte) (observatoryHealthPing, error) {
	var hp observatoryHealthPing
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return observatoryHealthPing{}, protowire.ParseError(n)
		}
		raw = raw[n:]
		if typ == protowire.VarintType && num >= 1 && num <= 6 {
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return observatoryHealthPing{}, protowire.ParseError(m)
			}
			switch num {
			case 1:
				hp.All = int64(v)
			case 2:
				hp.Fail = int64(v)
			case 3:
				hp.Deviation = time.Duration(int64(v))
			case 4:
				hp.Average = time.Duration(int64(v))
			case 5:
				hp.Max = time.Duration(int64(v))
			case 6:
				hp.Min = time.Duration(int64(v))
			}
			raw = raw[m:]
			continue
		}
		skip := protowire.ConsumeFieldValue(num, typ, raw)
		if skip < 0 {
			return observatoryHealthPing{}, protowire.ParseError(skip)
		}
		raw = raw[skip:]
	}
	return hp, nil
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
	got, err := decodeObservatoryResponse(encodeTestObservatoryResponse())
	if err != nil {
		t.Fatalf("decodeObservatoryResponse failed: %v", err)
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
	empty, err := decodeObservatoryResponse(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty decode = %v %v, want empty nil", empty, err)
	}
	if _, err := decodeObservatoryResponse([]byte{0x0a, 0x05, 0x01}); err == nil {
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
	got, err := queryObservatoryStatus(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("queryObservatoryStatus failed: %v", err)
	}
	r0, ok0 := got["route-l1-r0"]
	r1, ok1 := got["route-l1-r1"]
	if !ok0 || !ok1 || !r0.Alive || r0.DelayMS != 18 || r1.Alive || r1.LastErrorReason != "timeout" {
		t.Fatalf("unexpected loopback observatory map: %+v", got)
	}
}
