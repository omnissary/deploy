package sshkey

import (
	"bytes"
	"strings"
	"testing"
)

func generatePEM(t *testing.T) (Pair, []byte) {
	t.Helper()
	pair, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := MarshalPrivatePEM(pair)
	if err != nil {
		t.Fatal(err)
	}
	return pair, pem
}

func TestPublicFromPrivateMatchesMarshalPublic(t *testing.T) {
	t.Parallel()
	pair, pem := generatePEM(t)

	for _, comment := range []string{"", "root@m-initrd"} {
		want, err := MarshalPublicAuthorizedKey(pair, comment)
		if err != nil {
			t.Fatal(err)
		}
		got, err := PublicFromPrivate(pem, comment)
		if err != nil {
			t.Fatalf("PublicFromPrivate: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("comment %q: got %q, want %q", comment, got, want)
		}
		if err := VerifyPair(pem, got); err != nil {
			t.Fatalf("VerifyPair: %v", err)
		}
	}
}

func TestPublicFromPrivateRejectsGarbage(t *testing.T) {
	t.Parallel()
	for _, in := range [][]byte{nil, []byte("not a key"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")} {
		if _, err := PublicFromPrivate(in, ""); err == nil {
			t.Fatalf("accepted %q", in)
		}
	}
}

func TestVerifyPairRejectsOtherKey(t *testing.T) {
	t.Parallel()
	_, pem := generatePEM(t)
	other, _ := generatePEM(t)
	pub, err := MarshalPublicAuthorizedKey(other, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPair(pem, pub); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected mismatch, got %v", err)
	}
}
