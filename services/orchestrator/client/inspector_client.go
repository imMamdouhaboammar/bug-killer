package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	omniv1 "github.com/aegis/orchestrator/omniv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// InspectorClient coordinates UDS communication with the Rust Service B Inspector.
type InspectorClient struct {
	conn       *grpc.ClientConn
	grpcClient omniv1.OmniBinaryInspectorClient
	socketPath string
}

// NewInspectorClient dials the Rust inspector over a local Unix Domain Socket.
func NewInspectorClient(socketPath string) (*InspectorClient, error) {
	if socketPath == "" {
		socketPath = "/var/run/omni_inspector.sock"
	}

	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}

	conn, err := grpc.NewClient("passthrough:///unix_uds",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial inspector UDS socket %s: %w", socketPath, err)
	}

	return &InspectorClient{
		conn:       conn,
		grpcClient: omniv1.NewOmniBinaryInspectorClient(conn),
		socketPath: socketPath,
	}, nil
}

// InspectBinaryFile streams a file payload or path to the Rust Goblin binary inspector.
func (ic *InspectorClient) InspectBinaryFile(ctx context.Context, filePath string) (*omniv1.BinaryInspectionResponse, error) {
	var payload []byte
	if fi, err := os.Stat(filePath); err == nil && fi.Size() < 50*1024*1024 { // Up to 50MB payload
		payload, _ = os.ReadFile(filePath)
	}

	req := &omniv1.BinaryInspectionRequest{
		RequestId:              fmt.Sprintf("req-%d", time.Now().UnixNano()),
		FilePath:               filePath,
		BinaryPayload:          payload,
		ExpectedArch:           omniv1.TargetArchitecture_ARCH_UNSPECIFIED,
		ExtractSymbols:         true,
		VerifyHardeningFlags:   true,
	}

	return ic.grpcClient.InspectBinary(ctx, req)
}

// InspectPacketStream delegates raw payload telemetry verification to the Rust runtime engine.
func (ic *InspectorClient) InspectPacketStream(ctx context.Context, sessionID, iface, src, dst, proto string, payload []byte, headers map[string]string) (*omniv1.PacketStreamInspectionResponse, error) {
	req := &omniv1.PacketStreamInspectionRequest{
		CaptureSessionId:   sessionID,
		NetworkInterface:   iface,
		SourceEndpoint:     src,
		DestinationEndpoint: dst,
		Protocol:           proto,
		RawPayload:         payload,
		ExtractedHeaders:   headers,
	}

	return ic.grpcClient.InspectPacketStream(ctx, req)
}

// SubscribeRuntimeEvents streams real-time eBPF tracepoint signals from the Rust kernel monitor.
func (ic *InspectorClient) SubscribeRuntimeEvents(ctx context.Context, filterTypes []omniv1.RuntimeEventType) (omniv1.OmniBinaryInspector_StreamRuntimeEventsClient, error) {
	sub := &omniv1.RuntimeEventSubscription{
		SubscriberId: fmt.Sprintf("sub-orchestrator-%d", time.Now().UnixNano()),
		FilterTypes:  filterTypes,
	}
	return ic.grpcClient.StreamRuntimeEvents(ctx, sub)
}

// Close releases the gRPC connection handle.
func (ic *InspectorClient) Close() error {
	if ic.conn != nil {
		return ic.conn.Close()
	}
	return nil
}
