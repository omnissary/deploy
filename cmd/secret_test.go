package cmd

import (
	"bytes"
	"testing"
)

func TestSecretValueFromInputPreservesTrailingNewlines(t *testing.T) {
	t.Parallel()

	value := secretValueFromInput([]byte("line1\nline2\n"))
	if value != "line1\nline2\n" {
		t.Fatalf("unexpected value %q", value)
	}
}

func TestWriteSecretValueDoesNotAppendNewline(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := writeSecretValue(&buf, "secret-without-newline"); err != nil {
		t.Fatalf("writeSecretValue: %v", err)
	}

	if got := buf.String(); got != "secret-without-newline" {
		t.Fatalf("unexpected output %q", got)
	}
}
