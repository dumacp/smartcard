//go:build !cgo && !linux

package pcsc

import (
	"fmt"

	"github.com/dumacp/smartcard"
)

func establishContext() (backendContext, error) {
	return nil, fmt.Errorf("pcsc backend without cgo not implemented yet, %w", smartcard.ErrComm)
}

func isNoSmartcardError(err error) bool {
	return false
}

func isKnownCardError(err error) bool {
	return false
}
