/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

	https://github.com/LudovicRousseau/PCSC
	https://github.com/ebfe/scard

/**/
package pcsc

import (
	"fmt"

	"github.com/dumacp/smartcard"
	"github.com/ebfe/scard"
)

type Context struct {
	*scard.Context
}

//Interface to Reader device
type Reader interface {
	smartcard.IReader
	ConnectDirect() (Card, error)
	ConnectCardPCSC() (Card, error)
	ConnectCardPCSC_T0() (Card, error)
}

type reader struct {
	Context    *Context
	ReaderName string
}

//Establish Context to Reader in pcscd
func NewContext() (*Context, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, smartcard.Error(err)
	}
	context := &Context{ctx}
	return context, nil
}

//List Readers in a Context
func ListReaders(ctx *Context) ([]string, error) {
	rs, err := ctx.ListReaders()
	if err != nil {
		return nil, smartcard.Error(err)
	}
	return rs, nil
}

//Create New Reader interface
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

//ConnectCardPCSC Create New Card interface
func (r *reader) ConnectCardPCSC() (Card, error) {
	if ok, err := r.Context.IsValid(); err != nil && !ok {
		return nil, fmt.Errorf("context err = %w, %w", err, smartcard.ErrComm)
	}

	c, err := r.Context.Connect(r.ReaderName, scard.ShareExclusive, scard.ProtocolT1)
	if err != nil {
		return nil, err
	}
	cardS := &card{
		CONNECTED,
		c,
	}
	return cardS, nil
}

//ConnectCardPCSCT0 Create New Card interface
func (r *reader) ConnectCardPCSC_T0() (Card, error) {
	if ok, err := r.Context.IsValid(); err != nil && !ok {
		return nil, fmt.Errorf("context err = %w, %w", err, smartcard.ErrComm)
	}

	c, err := r.Context.Connect(r.ReaderName, scard.ShareExclusive, scard.ProtocolT0)
	if err != nil {
		return nil, err
	}
	cardS := &card{
		CONNECTED,
		c,
	}
	return cardS, nil
}

//Create New Card interface
func (r *reader) ConnectCard() (smartcard.ICard, error) {
	if ok, err := r.Context.IsValid(); err != nil && !ok {
		return nil, fmt.Errorf("context err = %w, %w", err, smartcard.ErrComm)
	}

	c, err := r.Context.Connect(r.ReaderName, scard.ShareExclusive, scard.ProtocolT1)
	if err != nil {
		return nil, err
	}
	cardS := &card{
		CONNECTED,
		c,
	}
	return cardS, nil
}

//Create New Card interface
func (r *reader) ConnectSamCard() (smartcard.ICard, error) {
	return r.ConnectCardPCSC()
}

func (r *reader) connectCard() (*card, error) {
	if ok, err := r.Context.IsValid(); err != nil && !ok {
		return nil, fmt.Errorf("context err = %w, %w", err, smartcard.ErrComm)
	}

	c, err := r.Context.Connect(r.ReaderName, scard.ShareExclusive, scard.ProtocolT1)
	if err != nil {
		return nil, err
	}
	cardS := &card{
		CONNECTED,
		c,
	}
	return cardS, nil
}

func (r *reader) ConnectDirect() (Card, error) {
	if ok, err := r.Context.IsValid(); err != nil && !ok {
		return nil, fmt.Errorf("context err = %w, %w", err, smartcard.ErrComm)
	}

	c, err := r.Context.Connect(r.ReaderName, scard.ShareDirect, scard.ProtocolUndefined)
	if err != nil {
		return nil, err
	}
	cardS := &card{
		CONNECTEDDirect,
		c,
	}
	return cardS, nil
}

//Release Context in pcscd
func (c *Context) Release() error {
	err := c.Context.Release()
	return err
}
