/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

        https://github.com/LudovicRousseau/PCSC
        github.com/ebfe/scard

/**/
package smartcard

import (
	"errors"
	"fmt"
	"testing"
)

func TestError(t *testing.T) {

	err1 := fmt.Errorf("%w", ErrComm)

	err2 := Error(err1)

	var err3 *SmartcardError
	if errors.As(err2, &err3) {
		if errors.Is(err3.Err, ErrComm) {
			t.Log("TRUE")
		} else {
			t.Error("FALSE")
		}
	}
}
