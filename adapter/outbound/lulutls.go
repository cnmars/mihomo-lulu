package outbound

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	lclient "lulutls/client"
)

// Lulutls is a mihomo outbound for the lulutls protocol (lulutls://).
//
// The node's carrier settings come straight from the subscription, so a Clash
// profile entry looks like:
//
//   - name: HK01
//     type: lulutls
//     server: hk01.example.com
//     port: 48311
//     psk: <64-hex>
//     lane: ws
//     sni: www.bing.com
//     path: /cdn/assets/app.js
//     shape: balanced
//     cipher: aes
//     tls-fingerprint: chrome
//     insecure: true
//
// UDP rides the tunnel's UoT framing (uint16 len || payload), so SupportUOT is
// true and the packet conn below deframes into datagrams.
type Lulutls struct {
	*Base
	option *LulutlsOption
	dialer *lclient.Dialer

	mu     sync.Mutex
	closed bool
}

// LulutlsOption is the proxy entry as parsed from the Clash profile.
type LulutlsOption struct {
	BasicOption
	Name        string `proxy:"name"`
	Server      string `proxy:"server"`
	Port        int    `proxy:"port"`
	PSK         string `proxy:"psk"`
	NodeKey     string `proxy:"node-key,omitempty"`
	Lane        string `proxy:"lane,omitempty"`
	SNI         string `proxy:"sni,omitempty"`
	Path        string `proxy:"path,omitempty"`
	Shape       string `proxy:"shape,omitempty"`
	Cipher      string `proxy:"cipher,omitempty"`
	Codec       string `proxy:"lane-c-codec,omitempty"`
	Fingerprint string `proxy:"tls-fingerprint,omitempty"`
	Insecure    bool   `proxy:"insecure,omitempty"`
	UDP         bool   `proxy:"udp,omitempty"`
}

// NewLulutls builds the outbound (the tunnel is established lazily on first use).
func NewLulutls(option LulutlsOption) (*Lulutls, error) {
	psk, err := hex.DecodeString(option.PSK)
	if err != nil || len(psk) == 0 {
		return nil, fmt.Errorf("lulutls: bad psk hex")
	}
	addr := net.JoinHostPort(option.Server, fmt.Sprint(option.Port))

	base := NewBase(BaseOption{
		Name:         option.Name,
		Addr:         addr,
		Type:         C.Lulutls,
		ProviderName: option.ProviderName,
		UDP:          option.UDP,
		TFO:          option.TFO,
		MPTCP:        option.MPTCP,
		Interface:    option.Interface,
		RoutingMark:  option.RoutingMark,
		Prefer:       option.IPVersion,
	})
	// mihomo panics if net.DefaultResolver is used (main.go installs a trap), so
	// every DNS lookup must go through mihomo's own dialer/resolver.
	cDialer := option.NewDialer(base.DialOptions())

	d, err := lclient.NewDialer(lclient.Config{
		Server:      addr,
		SNI:         option.SNI,
		Path:        option.Path,
		PSK:         psk,
		NodeKey:     []byte(option.NodeKey),
		Lane:        option.Lane,
		Cipher:      option.Cipher,
		Shape:       option.Shape,
		Fingerprint: option.Fingerprint,
		Arith:       option.Codec == "arith",
		Insecure:    option.Insecure,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return cDialer.DialContext(ctx, network, addr)
		},
		ListenPacket: func(ctx context.Context) (net.PacketConn, error) {
			return cDialer.ListenPacket(ctx, "udp", "", netip.AddrPort{})
		},
		// The QUIC lane needs the SERVER address as a *net.UDPAddr. Resolving it
		// with net.ResolveUDPAddr would hit net.DefaultResolver, which mihomo
		// replaces with a hard "should never be called" process exit — resolve
		// through mihomo's own resolver instead.
		ResolveUDP: func(ctx context.Context, addr string) (*net.UDPAddr, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, err
			}
			ip, err := resolver.ResolveIP(ctx, host)
			if err != nil {
				return nil, err
			}
			return &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: port}, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("lulutls: %w", err)
	}

	return &Lulutls{
		Base:   base,
		option: &option,
		dialer: d,
	}, nil
}

// DialContext implements C.ProxyAdapter.
func (l *Lulutls) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("lulutls: outbound closed")
	}
	c, err := l.dialer.DialTCP(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, fmt.Errorf("lulutls: dial %s: %w", metadata.RemoteAddress(), err)
	}
	return NewConn(c, l), nil
}

// ListenPacketContext implements C.ProxyAdapter. The tunnel stream carries
// length-framed datagrams; lulutlsPacketConn turns it into a net.PacketConn.
func (l *Lulutls) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := l.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	c, err := l.dialer.DialUDP(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, fmt.Errorf("lulutls: udp %s: %w", metadata.RemoteAddress(), err)
	}
	pc := &lulutlsPacketConn{conn: c, raddr: metadata.UDPAddr()}
	return newPacketConn(N.NewThreadSafePacketConn(pc), l), nil
}

// SupportUOT implements C.ProxyAdapter (UDP rides the tunnel).
func (l *Lulutls) SupportUOT() bool { return true }

// Close implements C.ProxyAdapter.
func (l *Lulutls) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.dialer.Close()
}

// lulutlsPacketConn adapts the tunnel's uint16-length-prefixed datagram stream
// to net.PacketConn.
type lulutlsPacketConn struct {
	conn  net.Conn
	raddr net.Addr

	rmu sync.Mutex
	wmu sync.Mutex
}

func (p *lulutlsPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	var hdr [2]byte
	if _, err := io.ReadFull(p.conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	buf := make([]byte, n)
	if _, err := io.ReadFull(p.conn, buf); err != nil {
		return 0, nil, err
	}
	copied := copy(b, buf)
	return copied, p.raddr, nil
}

func (p *lulutlsPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	out := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(out[:2], uint16(len(b)))
	copy(out[2:], b)
	if _, err := p.conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *lulutlsPacketConn) Close() error                       { return p.conn.Close() }
func (p *lulutlsPacketConn) LocalAddr() net.Addr                { return p.conn.LocalAddr() }
func (p *lulutlsPacketConn) SetDeadline(t time.Time) error      { return p.conn.SetDeadline(t) }
func (p *lulutlsPacketConn) SetReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *lulutlsPacketConn) SetWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }
