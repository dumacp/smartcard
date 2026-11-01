//go:build cgo

package pcsc

import (
	"errors"

	"github.com/dumacp/smartcard"
	"github.com/ebfe/scard"
)

type cgoContext struct {
	ctx *scard.Context
}

func establishContext() (backendContext, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, smartcard.Error(err)
	}
	return &cgoContext{ctx: ctx}, nil
}

func (c *cgoContext) IsValid() (bool, error) {
	return c.ctx.IsValid()
}

func (c *cgoContext) ListReaders() ([]string, error) {
	return c.ctx.ListReaders()
}

func (c *cgoContext) Connect(readerName string, share shareMode, protocol protocolType) (backendCard, error) {
	card, err := c.ctx.Connect(readerName, toScardShareMode(share), toScardProtocol(protocol))
	if err != nil {
		return nil, err
	}
	return &cgoCard{card: card}, nil
}

func (c *cgoContext) Release() error {
	return c.ctx.Release()
}

type cgoCard struct {
	card *scard.Card
}

func (c *cgoCard) Disconnect(disposition dispositionType) error {
	return c.card.Disconnect(toScardDisposition(disposition))
}

func (c *cgoCard) Transmit(apdu []byte) ([]byte, error) {
	return c.card.Transmit(apdu)
}

func (c *cgoCard) Control(ioctl uint32, apdu []byte) ([]byte, error) {
	return c.card.Control(ioctl, apdu)
}

func (c *cgoCard) EndTransaction(disposition dispositionType) error {
	return c.card.EndTransaction(toScardDisposition(disposition))
}

func (c *cgoCard) Status() (*cardStatus, error) {
	status, err := c.card.Status()
	if err != nil {
		return nil, err
	}
	out := &cardStatus{Atr: make([]byte, len(status.Atr))}
	copy(out.Atr, status.Atr)
	return out, nil
}

func toScardShareMode(share shareMode) scard.ShareMode {
	switch share {
	case shareExclusive:
		return scard.ShareExclusive
	case shareShared:
		return scard.ShareShared
	case shareDirect:
		return scard.ShareDirect
	default:
		return scard.ShareExclusive
	}
}

func toScardProtocol(protocol protocolType) scard.Protocol {
	switch protocol {
	case protocolT0:
		return scard.ProtocolT0
	case protocolT1:
		return scard.ProtocolT1
	case protocolAny:
		return scard.ProtocolAny
	case protocolUndefined:
		return scard.ProtocolUndefined
	default:
		return scard.ProtocolAny
	}
}

func toScardDisposition(disposition dispositionType) scard.Disposition {
	switch disposition {
	case dispositionLeaveCard:
		return scard.LeaveCard
	case dispositionResetCard:
		return scard.ResetCard
	case dispositionUnpowerCard:
		return scard.UnpowerCard
	case dispositionEjectCard:
		return scard.EjectCard
	default:
		return scard.LeaveCard
	}
}

func isNoSmartcardError(err error) bool {
	return errors.Is(err, scard.ErrNoSmartcard) ||
		errors.Is(err, scard.ErrRemovedCard) ||
		errors.Is(err, scard.ErrUnsupportedCard) ||
		errors.Is(err, scard.ErrProtoMismatch) ||
		errors.Is(err, scard.ErrUnpoweredCard)
}

func isKnownCardError(err error) bool {
	return errors.Is(err, scard.ErrNoSmartcard) ||
		errors.Is(err, scard.ErrCardUnsupported) ||
		errors.Is(err, scard.ErrRemovedCard) ||
		errors.Is(err, scard.ErrUnsupportedCard) ||
		errors.Is(err, scard.ErrResetCard) ||
		errors.Is(err, scard.ErrNotTransacted)
}
