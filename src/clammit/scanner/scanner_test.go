package scanner

import (
	"testing"
)

type TestScanner struct {
	Engine
}

func TestSetAddress(t *testing.T) {
	s := new(TestScanner)
	a := s.Address()

	if a != "" {
		t.Errorf("expected an empty address, got %v", a)
	}

	s.SetAddress("foobar")
	a = s.Address()

	if a != "foobar" {
		t.Errorf("expected %v, got %v", "foobar", a)
	}
}
