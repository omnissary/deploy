package errors

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/protoadapt"
)

const (
	ErrBeginTx    = "failed to start transaction"
	ErrRollbackTx = "failed to rollback transaction"
	ErrCommitTx   = "failed to commit transaction"
)

var (
	Is     = errors.Is
	As     = errors.As
	Wrap   = errors.Wrap
	Wrapf  = errors.Wrapf
	Errorf = fmt.Errorf
	New    = errors.New
)

type RPCDetailer interface {
	ErrorDetails() []proto.Message
}

func Log(err error, fmt string, args ...any) {
	if err != nil {
		log.Error().Err(err).Msgf(fmt, args...)
	}
}

func LogCtx(ctx context.Context, err error, fmt string, args ...any) {
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msgf(fmt, args...)
	}
}

func LogCallErr(fn func() error, fmt string, args ...any) {
	Log(fn(), fmt, args...)
}

func LogCallErrCtx(ctx context.Context, fn func() error, fmt string, args ...any) {
	LogCtx(ctx, fn(), fmt, args...)
}

func Chain(err error, cause error) error {
	return Errorf("%w: %w", err, cause)
}

func RpcCode(err error, code codes.Code, format string, args ...any) error {
	if err == nil {
		return nil
	}

	log.Error().Err(err).Msgf(format, args...)
	st := status.New(code, fmt.Sprintf(format, args...))
	st = RpcDetails(err, st)
	return st.Err()
}

func RpcCodeCtx(ctx context.Context, err error, code codes.Code, format string, args ...any) error {
	if err == nil {
		return nil
	}

	log.Ctx(ctx).Error().Err(err).Msgf(format, args...)
	st := status.New(code, fmt.Sprintf(format, args...))
	st = RpcDetails(err, st)
	return st.Err()
}

func Rpc(err error, format string, args ...any) error {
	return RpcCode(err, codes.Internal, format, args...)
}

func RpcDetails(err error, st *status.Status) *status.Status {
	if err == nil || st == nil {
		return st
	}

	var detailer RPCDetailer
	if !errors.As(err, &detailer) {
		return st
	}

	details := detailer.ErrorDetails()
	if len(details) == 0 {
		return st
	}

	detailMessages := make([]protoadapt.MessageV1, 0, len(details))
	for _, detail := range details {
		detailMessages = append(detailMessages, protoadapt.MessageV1Of(detail))
	}

	st, err = st.WithDetails(detailMessages...)
	if err != nil {
		return st
	}
	return st
}
