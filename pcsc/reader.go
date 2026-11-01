/*
*
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

	https://github.com/LudovicRousseau/PCSC
	https://github.com/ebfe/scard

/*
*/
package pcsc

import (
	"fmt"
	"time"

	"github.com/dumacp/smartcard"
)

type Context struct {
	ctx backendContext
}

// Interface to Reader device
type Reader interface {
	smartcard.IReader
	Name() string
	ConnectDirect() (Card, error)
	ConnectCardPCSC() (Card, error)
	ConnectCardPCSC_T0() (Card, error)
	ConnectCardPCSC_Tany() (Card, error)
}

type reader struct {
	Context    *Context
	ReaderName string
}

// Establish Context to Reader in pcscd
func NewContext() (*Context, error) {
	ctx, err := establishContext()
	if err != nil {
		return nil, err
	}
	context := &Context{ctx: ctx}
	return context, nil
}

func (c *Context) IsValid() (bool, error) {
	return c.ctx.IsValid()
}

func (c *Context) ListReaders() ([]string, error) {
	return c.ctx.ListReaders()
}

// List Readers in a Context
func ListReaders(ctx *Context) ([]string, error) {
	rs, err := ctx.ctx.ListReaders()
	if err != nil {
		return nil, smartcard.Error(err)
	}
	return rs, nil
}

// Create New Reader interface
func NewReader(ctx *Context, readerName string) Reader {
	r := &reader{
		Context:    ctx,
		ReaderName: readerName,
	}
	return r
}

func newReader(ctx *Context, readerName string) *reader {
	r := &reader{
		Context:    ctx,
		ReaderName: readerName,
	}
	return r
}

func (r *reader) Close() error {
	err := r.Context.Release()
	return err
}

func (r *reader) Name() string {
	return r.ReaderName
}

// ConnectCardPCSC Create New Card interface
func (r *reader) ConnectCardPCSC() (Card, error) {
	if ok, err := r.Context.ctx.IsValid(); err != nil && !ok {
		return nil, fmt.Errorf("context err = %w, %w", err, smartcard.ErrComm)
	}

	c, err := r.Context.ctx.Connect(r.ReaderName, shareExclusive, protocolT1)
	if err != nil {
		switch {
		case isNoSmartcardError(err):
			return nil, fmt.Errorf("connect card err = %s, %w", err, smartcard.ErrNoSmartcard)
		default:
			return nil, fmt.Errorf("connect card err = %s, %w", err, smartcard.ErrComm)
		}
	}
	sak := byte(0xFF)
	cardS := &Scard{
		State:   CONNECTED,
		timeout: 3 * time.Second,
		card:    c,
		sak:     sak,
		atr:     nil,
	}
	return cardS, nil
}

// ConnectCardPCSCT0 Create New Card interface
func (r *reader) ConnectCardPCSC_T0() (Card, error) {
	if ok, err := r.Context.ctx.IsValid(); err != nil && !ok {
		return nil, fmt.Errorf("context err = %s, %w", err, smartcard.ErrComm)
	}

	c, err := r.Context.ctx.Connect(r.ReaderName, shareExclusive, protocolT0)
	if err != nil {
		return nil, err
	}
	sak := byte(0xFF)
	cardS := &Scard{
		State:   CONNECTED,
		timeout: 3 * time.Second,
		card:    c,
		sak:     sak,
		atr:     nil,
	}
	return cardS, nil
}

// ConnectCardPCSCT0 Create New Card interface
func (r *reader) ConnectCardPCSC_Tany() (Card, error) {
	if ok, err := r.Context.ctx.IsValid(); err != nil && !ok {
		return nil, fmt.Errorf("context err = %s, %w", err, smartcard.ErrComm)
	}

	c, err := r.Context.ctx.Connect(r.ReaderName, shareShared, protocolAny)
	if err != nil {
		return nil, err
	}
	sak := byte(0xFF)
	cardS := &Scard{
		State:   CONNECTED,
		timeout: 3 * time.Second,
		card:    c,
		sak:     sak,
		atr:     nil,
	}
	return cardS, nil
}

// Create New Card interface
func (r *reader) ConnectCard() (smartcard.ICard, error) {
	if ok, err := r.Context.ctx.IsValid(); err != nil && !ok {
		return nil, fmt.Errorf("context err = %s, %w", err, smartcard.ErrComm)
	}

	c, err := r.Context.ctx.Connect(r.ReaderName, shareExclusive, protocolT1)
	if err != nil {
		switch {
		case isNoSmartcardError(err):
			return nil, fmt.Errorf("connect card err = %s, %w", err, smartcard.ErrNoSmartcard)
		default:
			return nil, fmt.Errorf("connect card err = %s, %w", err, smartcard.ErrComm)
		}
	}
	sak := byte(0xFF)
	cardS := &Scard{
		State:   CONNECTED,
		timeout: 3 * time.Second,
		card:    c,
		sak:     sak,
		atr:     nil,
	}
	return cardS, nil
}

// Create New Card interface
func (r *reader) ConnectSamCard() (smartcard.ICard, error) {
	return r.ConnectCardPCSC()
}
func (r *reader) ConnectSamCard_T0() (smartcard.ICard, error) {
	return r.ConnectCardPCSC_T0()
}
func (r *reader) ConnectSamCard_Tany() (smartcard.ICard, error) {
	return r.ConnectCardPCSC_Tany()
}

func (r *reader) connectCard() (*Scard, error) {
	if ok, err := r.Context.ctx.IsValid(); err != nil && !ok {
		return nil, fmt.Errorf("context err = %w, %w", err, smartcard.ErrComm)
	}

	c, err := r.Context.ctx.Connect(r.ReaderName, shareExclusive, protocolT1)
	if err != nil {
		return nil, err
	}
	sak := byte(0xFF)
	cardS := &Scard{
		State:   CONNECTED,
		timeout: 3 * time.Second,
		card:    c,
		sak:     sak,
		atr:     nil,
	}
	return cardS, nil
}

func (r *reader) ConnectDirect() (Card, error) {
	if ok, err := r.Context.ctx.IsValid(); err != nil && !ok {
		return nil, fmt.Errorf("context err = %w, %w", err, smartcard.ErrComm)
	}

	c, err := r.Context.ctx.Connect(r.ReaderName, shareDirect, protocolUndefined)
	if err != nil {
		return nil, err
	}
	sak := byte(0xFF)
	cardS := &Scard{
		State:   CONNECTEDDirect,
		timeout: 3 * time.Second,
		card:    c,
		sak:     sak,
		atr:     nil,
	}
	return cardS, nil
}

// Release Context in pcscd
func (c *Context) Release() error {
	err := c.ctx.Release()
	return err
}
