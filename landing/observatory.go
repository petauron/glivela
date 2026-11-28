package landing

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
)

const xrayObservatoryStatusMethod = "/xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus"

// ObservatoryHealthPing holds burstObservatory health ping metrics returned by
// Xray's ObservatoryService.
type ObservatoryHealthPing struct {
	All       int64
	Fail      int64
	Deviation time.Duration
	Average   time.Duration
	Max       time.Duration
	Min       time.Duration
}

// ObservatoryOutboundStatus holds one full-path outbound's status from Xray's
// local ObservatoryService API.
type ObservatoryOutboundStatus struct {
	Alive           bool
	DelayMS         int64
	LastErrorReason string
	OutboundTag     string
	LastSeenTime    int64
	LastTryTime     int64
	HealthPing      *ObservatoryHealthPing
}

type observatoryRawMessage []byte

type observatoryRawCodec struct{}

func (observatoryRawCodec) Marshal(v any) ([]byte, error) {
	raw, ok := v.(*observatoryRawMessage)
	if !ok {
		return nil, errors.New("landing: observatory codec requires raw message")
	}
	return append([]byte(nil), (*raw)...), nil
}

func (observatoryRawCodec) Unmarshal(data []byte, v any) error {
	raw, ok := v.(*observatoryRawMessage)
	if !ok {
		return errors.New("landing: observatory codec requires raw message")
	}
	*raw = append((*raw)[:0], data...)
	return nil
}

func (observatoryRawCodec) Name() string {
	return "proto"
}

// QueryObservatoryStatus invokes Xray's local loopback ObservatoryService gRPC
// API using existing gRPC/protobuf dependencies without adding new packages.
func QueryObservatoryStatus(ctx context.Context, apiAddress string) (map[string]ObservatoryOutboundStatus, error) {
	conn, err := grpc.NewClient(
		"passthrough:///"+apiAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithNoProxy(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1<<20)),
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var req, resp observatoryRawMessage
	if err := conn.Invoke(ctx, xrayObservatoryStatusMethod, &req, &resp, grpc.ForceCodec(observatoryRawCodec{})); err != nil {
		return nil, err
	}
	items, err := DecodeObservatoryResponse(resp)
	if err != nil {
		return nil, err
	}
	result := make(map[string]ObservatoryOutboundStatus, len(items))
	for _, item := range items {
		result[item.OutboundTag] = item
	}
	return result, nil
}

// DecodeObservatoryResponse parses a GetOutboundStatusResponse wire message.
func DecodeObservatoryResponse(raw []byte) ([]ObservatoryOutboundStatus, error) {
	var out []ObservatoryOutboundStatus
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

func decodeObservationResult(raw []byte) ([]ObservatoryOutboundStatus, error) {
	var out []ObservatoryOutboundStatus
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

func decodeOutboundStatus(raw []byte) (ObservatoryOutboundStatus, error) {
	var s ObservatoryOutboundStatus
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return ObservatoryOutboundStatus{}, protowire.ParseError(n)
		}
		raw = raw[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return ObservatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.Alive = protowire.DecodeBool(v)
			raw = raw[m:]
		case num == 2 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return ObservatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.DelayMS = int64(v)
			raw = raw[m:]
		case num == 3 && typ == protowire.BytesType:
			v, m := protowire.ConsumeString(raw)
			if m < 0 {
				return ObservatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.LastErrorReason = v
			raw = raw[m:]
		case num == 4 && typ == protowire.BytesType:
			v, m := protowire.ConsumeString(raw)
			if m < 0 {
				return ObservatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.OutboundTag = v
			raw = raw[m:]
		case num == 5 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return ObservatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.LastSeenTime = int64(v)
			raw = raw[m:]
		case num == 6 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return ObservatoryOutboundStatus{}, protowire.ParseError(m)
			}
			s.LastTryTime = int64(v)
			raw = raw[m:]
		case num == 7 && typ == protowire.BytesType:
			msg, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return ObservatoryOutboundStatus{}, protowire.ParseError(m)
			}
			hp, err := decodeHealthPingResult(msg)
			if err != nil {
				return ObservatoryOutboundStatus{}, err
			}
			s.HealthPing = &hp
			raw = raw[m:]
		default:
			skip := protowire.ConsumeFieldValue(num, typ, raw)
			if skip < 0 {
				return ObservatoryOutboundStatus{}, protowire.ParseError(skip)
			}
			raw = raw[skip:]
		}
	}
	return s, nil
}

func decodeHealthPingResult(raw []byte) (ObservatoryHealthPing, error) {
	var hp ObservatoryHealthPing
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return ObservatoryHealthPing{}, protowire.ParseError(n)
		}
		raw = raw[n:]
		if typ == protowire.VarintType && num >= 1 && num <= 6 {
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return ObservatoryHealthPing{}, protowire.ParseError(m)
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
			return ObservatoryHealthPing{}, protowire.ParseError(skip)
		}
		raw = raw[skip:]
	}
	return hp, nil
}
