package errs

import (
	"encoding/json"
	"fmt"
	"github.com/mousybusiness/gooseclip-backend/pkg/model"
	"github.com/pkg/errors"
)

// httpError defines an error which contains
// an http status code from an API request.
// This faciliates a more accurate API response
// for the daemon API.
type httpError interface {
	Code() int
}

type HttpError struct {
	code int
	err  error
}

func NewHttpError(code int, b []byte, fallback string) HttpError {
	e := errors.New(fallback)

	if b != nil {
		var r model.ErrorResponse
		if err := json.Unmarshal(b, &r); err == nil {
			e = errors.New(r.Error)
		}
	}

	return HttpError{
		code: code,
		err:  e,
	}
}

func (e HttpError) Error() string {
	return errors.Wrap(e.err, fmt.Sprintf("HttpError[%v]", e.code)).Error()
}

func (e HttpError) Code() int {
	return e.code
}

func ExtractHttpError(err error) (int, bool) {
	e, ok := err.(httpError)
	if !ok {
		return 0, false
	}
	return e.Code(), true
}

