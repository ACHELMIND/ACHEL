package listener

import (
	"testing"
)

func TestNewGenericListener(t *testing.T) {
	l := NewGenericListener("127.0.0.1", 0)
	if l == nil {
		t.Fatal("expected non-nil GenericListener")
	}
	if l.addr != "127.0.0.1" {
		t.Errorf("expected addr 127.0.0.1, got %s", l.addr)
	}
}

func TestGenericListener_StopBeforeStart(t *testing.T) {
	l := NewGenericListener("127.0.0.1", 0)
	l.Stop()
}

func TestGenericListener_IsRunning(t *testing.T) {
	l := NewGenericListener("127.0.0.1", 0)
	if l.IsRunning() {
		t.Error("expected not running initially")
	}
}

func TestNewTCPListener(t *testing.T) {
	l := NewTCPListener(TCPListenerConfig{
		Addr: "127.0.0.1",
		Port: 0,
	})
	if l == nil {
		t.Fatal("expected non-nil TCPListener")
	}
}

func TestTCPListener_StopBeforeStart(t *testing.T) {
	l := NewTCPListener(TCPListenerConfig{
		Addr: "127.0.0.1",
		Port: 0,
	})
	l.Stop()
}

func TestTCPListener_IsRunning(t *testing.T) {
	l := NewTCPListener(TCPListenerConfig{
		Addr: "127.0.0.1",
		Port: 0,
	})
	if l.IsRunning() {
		t.Error("expected not running initially")
	}
}

func TestNewDNSListener(t *testing.T) {
	l := NewDNSListener(DNSListenerConfig{
		Addr: "127.0.0.1",
		Port: 0,
	})
	if l == nil {
		t.Fatal("expected non-nil DNSListener")
	}
}

func TestDNSListener_StopBeforeStart(t *testing.T) {
	l := NewDNSListener(DNSListenerConfig{
		Addr: "127.0.0.1",
		Port: 0,
	})
	l.Stop()
}

func TestDNSListener_ExportedType(t *testing.T) {
	l := NewDNSListener(DNSListenerConfig{
		Addr: "127.0.0.1",
		Port: 0,
	})
	if l.addr != "127.0.0.1" {
		t.Errorf("expected addr 127.0.0.1, got %s", l.addr)
	}
	if l.port != 0 {
		t.Errorf("expected port 0, got %d", l.port)
	}
}

func TestNewUDPListener(t *testing.T) {
	l := NewUDPListener(UDPListenerConfig{
		Addr: "127.0.0.1",
		Port: 0,
	})
	if l == nil {
		t.Fatal("expected non-nil UDPListener")
	}
}

func TestUDPListener_StopBeforeStart(t *testing.T) {
	l := NewUDPListener(UDPListenerConfig{
		Addr: "127.0.0.1",
		Port: 0,
	})
	l.Stop()
}

func TestUDPListener_ExportedType(t *testing.T) {
	l := NewUDPListener(UDPListenerConfig{
		Addr: "127.0.0.1",
		Port: 0,
	})
	if l.addr != "127.0.0.1" {
		t.Errorf("expected addr 127.0.0.1, got %s", l.addr)
	}
}

func TestNewHTTPListener(t *testing.T) {
	l := NewHTTPListener(HTTPListenerConfig{
		Addr: "127.0.0.1",
		Port: 0,
	})
	if l == nil {
		t.Fatal("expected non-nil HTTPListener")
	}
}

func TestHTTPListener_StopBeforeStart(t *testing.T) {
	l := NewHTTPListener(HTTPListenerConfig{
		Addr: "127.0.0.1",
		Port: 0,
	})
	l.Stop()
}

func TestHTTPListener_SSL(t *testing.T) {
	l := NewHTTPListener(HTTPListenerConfig{
		Addr:     "127.0.0.1",
		Port:     0,
		SSL:      true,
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	})
	if !l.ssl {
		t.Error("expected ssl true")
	}
}
