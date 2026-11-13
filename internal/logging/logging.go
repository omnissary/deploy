package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"os"
	"slices"
	"strconv"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
)

// Writer renders structured log events as compact, deterministic CLI messages.
type Writer struct {
	out   io.Writer
	name  string
	color bool
}

func (w *Writer) Write(p []byte) (int, error) {
	var event map[string]any
	decoder := json.NewDecoder(bytes.NewReader(p))
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return 0, errors.Wrap(err, "decode log event")
	}
	if _, err := io.WriteString(w.out, w.line(event)+"\n"); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *Writer) line(event map[string]any) string {
	var parts, fields []string
	for _, key := range []string{"message", "error"} {
		if value, ok := event[key]; ok && value != "" {
			parts = append(parts, fmt.Sprint(value))
		}
	}
	for key, value := range event {
		switch key {
		case "level", "message", "error", "time", "caller":
			continue
		}
		fields = append(fields, key+"="+formatValue(value))
	}
	slices.Sort(fields)
	line := w.name + ": " + strings.Join(parts, ": ")
	if len(fields) != 0 {
		line += " (" + strings.Join(fields, " ") + ")"
	}
	if !w.color {
		return line
	}
	var color int
	switch event["level"] {
	case "error", "fatal", "panic":
		color = 31
	case "warn":
		color = 33
	case "debug", "trace":
		color = 90
	default:
		return line
	}
	return fmt.Sprintf("\x1b[%dm%s\x1b[0m", color, line)
}

func formatValue(value any) string {
	switch v := value.(type) {
	case string:
		if v == "" || strings.ContainsAny(v, " =\"\\") {
			return strconv.Quote(v)
		}
		return v
	case json.Number:
		return v.String()
	case map[string]any, []any:
		buf, err := json.Marshal(v)
		if err == nil {
			return string(buf)
		}
	}
	return fmt.Sprint(value)
}

// Configure installs the CLI format for every package using the shared logger.
func Configure(out *os.File, name string) {
	color := false
	if os.Getenv("NO_COLOR") == "" {
		info, err := out.Stat()
		color = err == nil && info.Mode()&os.ModeCharDevice != 0
	}
	*log.DefaultLogger = log.DefaultLogger.Output(&Writer{out: out, name: name, color: color})
	stdlog.SetOutput(*log.DefaultLogger)
	log.SetLevel(log.WarnLevel)
}
