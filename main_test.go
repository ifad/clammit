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

func TestConstructConfig_Env(t *testing.T) {
	os.Setenv("CLAMMIT_LISTEN", ":1234")
	os.Setenv("CLAMMIT_SOCKET_PERMS", "0444")
	os.Setenv("CLAMMIT_APPLICATION_URL", "http://foo.bar:123")
	os.Setenv("CLAMMIT_CLAMD_URL", "tcp://av.foo.bar:3310")
	os.Setenv("CLAMMIT_VIRUS_STATUS_CODE", "111")
	os.Setenv("CLAMMIT_CONTENT_MEMORY_THRESHOLD", "666")
	os.Setenv("CLAMMIT_LOGFILE", "/var/log/foo.log")
	os.Setenv("CLAMMIT_TEST_PAGES", "false")
	os.Setenv("CLAMMIT_DEBUG", "true")
	os.Setenv("CLAMMIT_NUM_THREADS", "90000")

	constructConfig()

	if ctx.Config.App.Listen != ":1234" {
		t.Errorf("Expected Listen to be ':1234', got %s", ctx.Config.App.Listen)
	}

	if ctx.Config.App.SocketPerms != "0444" {
		t.Errorf("Expected SocketPerms to be '0444', got %s", ctx.Config.App.SocketPerms)
	}

	if ctx.Config.App.ApplicationURL != "http://foo.bar:123" {
		t.Errorf("Expected ApplicationURL to be 'http://foo.bar:123', got %s", ctx.Config.App.ApplicationURL)
	}

	if ctx.Config.App.ClamdURL != "tcp://av.foo.bar:3310" {
		t.Errorf("Expected ClamdURL to be 'tcp://av.foo.bar:3310', got %s", ctx.Config.App.ClamdURL)
	}

	if ctx.Config.App.VirusStatusCode != 111 {
		t.Errorf("Expected VirusStatusCode to be 111, got %d", ctx.Config.App.VirusStatusCode)
	}

	if ctx.Config.App.ContentMemoryThreshold != 666 {
		t.Errorf("Expected ContentMemoryThreshold to be 666, got %d", ctx.Config.App.ContentMemoryThreshold)
	}

	if ctx.Config.App.Logfile != "/var/log/foo.log" {
		t.Errorf("Expected Logfile to be '/var/log/foo.log', got %s", ctx.Config.App.Logfile)
	}

	if ctx.Config.App.TestPages {
		t.Errorf("Expected TestPages to be false, got %t", ctx.Config.App.TestPages)
	}

	if !ctx.Config.App.Debug {
		t.Errorf("Expected Debug to be true, got %t", ctx.Config.App.Debug)
	}

	if ctx.Config.App.NumThreads != 90000 {
		t.Errorf("Expected NumThreads to be 90000, got %d", ctx.Config.App.NumThreads)
	}
}
