package scanner

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"testing"
)

// fakeClamd accepts one INSTREAM session, drains the chunks and replies with reply.
func fakeClamd(t *testing.T, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		cmd := make([]byte, len("nINSTREAM\n"))
		if _, err := io.ReadFull(conn, cmd); err != nil {
			return
		}
		for {
			var size uint32
			if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
				return
			}
			if size == 0 {
				break
			}
			if _, err := io.CopyN(io.Discard, conn, int64(size)); err != nil {
				return
			}
		}
		io.WriteString(conn, reply)
	}()
	return "tcp://" + ln.Addr().String()
}

func newClamav(address string) *Clamav {
	c := new(Clamav)
	c.SetLogger(log.New(io.Discard, "", 0), false)
	c.SetAddress(address)
	return c
}

func TestClamav_Clean(t *testing.T) {
	c := newClamav(fakeClamd(t, "stream: OK\n"))
	hasVirus, err := c.HasVirus(bytes.NewReader([]byte("clean")))
	if err != nil || hasVirus {
		t.Fatalf("expected clean without error, got hasVirus=%v err=%v", hasVirus, err)
	}
}

func TestClamav_Found(t *testing.T) {
	c := newClamav(fakeClamd(t, "stream: Eicar-Signature FOUND\n"))
	hasVirus, err := c.HasVirus(bytes.NewReader([]byte("virus")))
	if err != nil || !hasVirus {
		t.Fatalf("expected virus without error, got hasVirus=%v err=%v", hasVirus, err)
	}
}

func TestClamav_ClamdErrorIsAnError(t *testing.T) {
	c := newClamav(fakeClamd(t, "INSTREAM size limit exceeded. ERROR\n"))
	if _, err := c.HasVirus(bytes.NewReader([]byte("big"))); err == nil {
		t.Fatal("clamd ERROR reply must be reported as a scan error")
	}
}

func TestClamav_ClamdErrorWithPathIsAnError(t *testing.T) {
	c := newClamav(fakeClamd(t, "stream: Can't allocate memory ERROR\n"))
	result, err := c.Scan(bytes.NewReader([]byte("x")))
	if err == nil {
		t.Fatalf("clamd ERROR reply must be reported as a scan error, got result %+v", result)
	}
}

func TestClamav_UnparseableReplyIsAnError(t *testing.T) {
	c := newClamav(fakeClamd(t, "garbled reply\n"))
	if _, err := c.HasVirus(bytes.NewReader([]byte("x"))); err == nil {
		t.Fatal("an unparseable clamd reply must be reported as a scan error")
	}
}

func TestClamav_NoReplyIsAnError(t *testing.T) {
	c := newClamav(fakeClamd(t, ""))
	if _, err := c.HasVirus(bytes.NewReader([]byte("x"))); err == nil {
		t.Fatal("a closed connection without a reply must be reported as a scan error")
	}
}
