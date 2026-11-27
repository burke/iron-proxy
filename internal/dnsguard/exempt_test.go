package dnsguard

import "testing"

func TestExemptLetsOneAddressAndPortThrough(t *testing.T) {
	g, err := New([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Exempt([]string{"127.0.0.1:18123"}); err != nil {
		t.Fatal(err)
	}
	if err := g.DialControl("tcp4", "127.0.0.1:18123", nil); err != nil {
		t.Fatalf("the exempt address was refused: %v", err)
	}
	for _, other := range []string{"127.0.0.1:18124", "127.0.0.2:18123", "127.0.0.1:22"} {
		if err := g.DialControl("tcp4", other, nil); !IsDenyError(err) {
			t.Fatalf("%s: got %v, want a deny", other, err)
		}
	}
	for _, bad := range []string{"127.0.0.1", "localhost:18123", ""} {
		if err := g.Exempt([]string{bad}); err == nil {
			t.Fatalf("%q was accepted as an exempt address", bad)
		}
	}
}
