package logging

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
)

func TestWriter(t *testing.T) {
	tests := []struct {
		name  string
		color bool
		emit  func(zerolog.Logger)
		want  string
	}{
		{
			name: "fields are sorted and values quoted",
			emit: func(l zerolog.Logger) {
				l.Warn().Str("target", "a b").Int("attempt", 2).Msg("retrying")
			},
			want: "deploy: retrying (attempt=2 target=\"a b\")\n",
		},
		{
			name: "error without message",
			emit: func(l zerolog.Logger) {
				l.Error().Str("error", "failed").Send()
			},
			want: "deploy: failed\n",
		},
		{
			name:  "warning color",
			color: true,
			emit: func(l zerolog.Logger) {
				l.Warn().Msg("careful")
			},
			want: "\x1b[33mdeploy: careful\x1b[0m\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			logger := zerolog.New(&Writer{out: &out, name: "deploy", color: tt.color}).With().Timestamp().Logger()
			tt.emit(logger)
			if got := out.String(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
