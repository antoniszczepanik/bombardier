package main

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go"
)

type countingConn struct {
	net.Conn
	bytesRead, bytesWritten *int64
}

func (cc *countingConn) Read(b []byte) (n int, err error) {
	n, err = cc.Conn.Read(b)

	if err == nil {
		atomic.AddInt64(cc.bytesRead, int64(n))
	}

	return
}

func (cc *countingConn) Write(b []byte) (n int, err error) {
	n, err = cc.Conn.Write(b)

	if err == nil {
		atomic.AddInt64(cc.bytesWritten, int64(n))
	}

	return
}

type countingQuicConn struct {
	quic.EarlyConnection
	bytesRead, bytesWritten *int64
}

func (cqc *countingQuicConn) ReceiveMessage() ([]byte, error) {
	b, err := cqc.EarlyConnection.ReceiveMessage()
	if err == nil {
		atomic.AddInt64(cqc.bytesRead, int64(len(b)))
	}
	return b, err
}

func (cqc *countingQuicConn) SendMessage(b []byte) error {
	err := cqc.EarlyConnection.SendMessage(b)
	if err == nil {
		atomic.AddInt64(cqc.bytesWritten, int64(len(b)))
	}
	return err
}

var fasthttpDialFunc = func(
	bytesRead, bytesWritten *int64,
) func(string) (net.Conn, error) {
	return func(address string) (net.Conn, error) {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			return nil, err
		}

		wrappedConn := &countingConn{
			Conn:         conn,
			bytesRead:    bytesRead,
			bytesWritten: bytesWritten,
		}

		return wrappedConn, nil
	}
}

var httpDialContextFunc = func(
	bytesRead, bytesWritten *int64,
) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}

		wrappedConn := &countingConn{
			Conn:         conn,
			bytesRead:    bytesRead,
			bytesWritten: bytesWritten,
		}

		return wrappedConn, nil
	}
}

var http3DialFunc = func(
	bytesRead, bytesWritten *int64,
) func(context.Context, string, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
	return func(ctx context.Context, network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		// TODO: quic.DialAddrEaryContext is incompatible with expected signature of connection in http3.RoundTripper dial.
		// Hence we pass network as well.
		_ = network
		conn, err := quic.DialAddrEarlyContext(ctx, addr, tlsCfg, cfg)
		if err != nil {
			return nil, err
		}

		wrappedConn := &countingQuicConn{
			EarlyConnection: conn,
			bytesRead:       bytesRead,
			bytesWritten:    bytesWritten,
		}

		return wrappedConn, nil
	}
}
