package agekey

import "testing"

func TestPublicFromPrivate(t *testing.T) {
	t.Parallel()
	pair, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{pair.Private, pair.Private + "\n", "  " + pair.Private + "\r\n"} {
		got, err := PublicFromPrivate(in)
		if err != nil || got != pair.Public {
			t.Fatalf("PublicFromPrivate(%q) = %q, %v; want %q", in, got, err, pair.Public)
		}
	}
}

func TestPublicFromPrivateRejectsInvalid(t *testing.T) {
	t.Parallel()
	pair, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"", "garbage", pair.Public} {
		if _, err := PublicFromPrivate(in); err == nil {
			t.Fatalf("accepted %q", in)
		}
	}
}
