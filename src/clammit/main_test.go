package main

import (
	"os"
	"testing"
)

func disableIPv6(t *testing.T) bool {
	value, set := os.LookupEnv("DISABLE_IPV6")
	if set && value == "1" {
		t.Log("IPV6 Disabled, test skipped")
		return true
	}
	return false
}

func TestGetListener_TCP_HostPort(t *testing.T) {
	if l, err := getListener("tcp:0.0.0.0:9944", 0); err != nil {
		t.Fatal("getListener( tcp:0.0.0.0:9944 ) failed:", err)
	} else {
		l.Close()
	}
}

func TestGetListener_TCP_Host6Port(t *testing.T) {
	if disableIPv6(t) {
		return
	}

	if l, err := getListener("tcp:[::1]:9944", 0); err != nil {
		t.Fatal("getListener( tcp:[::1]:9944 ) failed:", err)
	} else {
		l.Close()
	}
}

func TestGetListener_TCP_Port(t *testing.T) {
	if l, err := getListener("tcp:9944", 0); err != nil {
		t.Fatal("getListener( tcp:9944 ) failed:", err)
	} else {
		l.Close()
	}
}

func TestGetListener_TCP4_HostPort(t *testing.T) {
	if l, err := getListener("tcp4:0.0.0.0:9944", 0); err != nil {
		t.Fatal("getListener( tcp4:0.0.0.0:9944 ) failed:", err)
	} else {
		l.Close()
	}
}

func TestGetListener_TCP4_Port(t *testing.T) {
	if l, err := getListener("tcp4:9944", 0); err != nil {
		t.Fatal("getListener( tcp4:9944 ) failed:", err)
	} else {
		l.Close()
	}
}

func TestGetListener_TCP6_HostPort(t *testing.T) {
	if disableIPv6(t) {
		return
	}

	if l, err := getListener("tcp6:[::]:9944", 0); err != nil {
		t.Fatal("getListener( tcp6:[::]:9944 ) failed:", err)
	} else {
		l.Close()
	}
}

func TestGetListener_TCP6_Port(t *testing.T) {
	if disableIPv6(t) {
		return
	}

	if l, err := getListener("tcp6:9944", 0); err != nil {
		t.Fatal("getListener( tcp6:9944 ) failed:", err)
	} else {
		l.Close()
	}
}

func TestGetListener_TCP6_PortWithColon(t *testing.T) {
	if disableIPv6(t) {
		return
	}

	if l, err := getListener("tcp6::9944", 0); err != nil {
		t.Fatal("getListener( tcp6::9944 ) failed:", err)
	} else {
		l.Close()
	}
}

func TestGetListener_HostPort(t *testing.T) {
	if l, err := getListener("0.0.0.0:9944", 0); err != nil {
		t.Fatal("getListener( 0.0.0.0:9944 ) failed:", err)
	} else {
		l.Close()
	}
}

func TestGetListener_Port(t *testing.T) {
	if l, err := getListener("9944", 0); err != nil {
		t.Fatal("getListener( 9944 ) failed:", err)
	} else {
		l.Close()
	}
}

func TestGetListener_PortWithColon(t *testing.T) {
	if l, err := getListener(":9944", 0); err != nil {
		t.Fatal("getListener( :9944 ) failed:", err)
	} else {
		l.Close()
	}
}

func TestGetListener_Unix(t *testing.T) {
	if l, err := getListener("unix:test.sock", 0666); err != nil {
		t.Fatal("getListener( unix:test.sock ) failed:", err)
	} else {
		l.Close()
	}
}
