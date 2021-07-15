package nxp

import (
	"errors"
)

var ErrEEPROMbusy = errors.New("EEPROM busy, access collision, memmory range cannot be mapped, execution error")
var ErrRC45x = errors.New("interface error")
var ErrReferecNumberKeyInvakid = errors.New("SAM key reference number invalid")
var ErrCounterNumberInvalid = errors.New("SAM key usage counter number invalid")
var ErrWrongLengthAPDU = errors.New("wrong length of the APDU or wrong Lc byte")
var ErrTemperature = errors.New("temperature error")

type ErrorResponse struct {
	Err error
}

func (e ErrorResponse) Error() string {
	return e.Err.Error()
}

func Error(e error) error {
	return &ErrorResponse{Err: e}
}
