package acs

import (
	"fmt"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/pcsc"
)

type Reader struct {
	r           pcsc.Reader
	pollManuall bool
}

func NewReader(ctx *pcsc.Context, readerName string) *Reader {

	r := &Reader{
		r: pcsc.NewReader(ctx, readerName),
	}
	return r

}

func NewReaderFromPcscReader(r pcsc.Reader) *Reader {

	reader := &Reader{
		r: r,
	}
	return reader

}

func (r *Reader) SetAutomaticPoll(a bool) error {

	p, err := r.r.ConnectDirect()
	if err != nil {
		return err
	}
	defer p.DisconnectCard()

	// TODO why?
	if _, err := p.ControlApdu(0x42000000+2079, []byte{0x22, 0x01, 0x01}); err != nil {
		return err
	}

	resp, err := p.ControlApdu(0x42000000+2079, []byte{0x23, 0x00})
	if err != nil {
		return err
	}
	if len(resp) <= 0 {
		return fmt.Errorf("error in response, nil response")
	}
	var apdu1 []byte
	if a {
		apdu1 = []byte{0x23, 0x01, resp[len(resp)-1] | 0x01}
	} else {
		apdu1 = []byte{0x23, 0x01, resp[len(resp)-1] & 0xFE}
	}
	if _, err := p.ControlApdu(0x42000000+2079, apdu1); err != nil {
		return err
	}
	r.pollManuall = !a
	return nil
}

func (r *Reader) SetEnforceISO14443A_4(a bool) error {

	p, err := r.r.ConnectDirect()
	if err != nil {
		return err
	}
	defer p.DisconnectCard()

	resp, err := p.ControlApdu(0x42000000+2079, []byte{0x23, 0x00})
	if err != nil {
		return err
	}
	if len(resp) <= 0 {
		return fmt.Errorf("error in response, nil response")
	}
	var apdu1 []byte
	if a {
		apdu1 = []byte{0x23, 0x01, resp[len(resp)-1] | 0x80}
	} else {
		apdu1 = []byte{0x23, 0x01, resp[len(resp)-1] & 0x7F}
	}
	if _, err := p.ControlApdu(0x42000000+2079, apdu1); err != nil {
		return err
	}
	r.pollManuall = !a
	return nil
}

// ConnectCard connect card with protocol T=1
func (r *Reader) ConnectCard() (smartcard.ICard, error) {

	if r.pollManuall {
		p, err := r.r.ConnectDirect()
		if err != nil {
			return nil, err
		}
		defer p.DisconnectCard()
		apdu := []byte{0x25, 0x00}
		if resp, err := p.ControlApdu(0x42000000+2079, apdu); err != nil {
			return nil, err
		} else if len(resp) > 0 && resp[len(resp)-1] > 0x01 {
			return r.r.ConnectCard()
		}
		return nil, smartcard.ErrNoSmartcard
	}
	return r.r.ConnectCard()
}

// ConnectCard connect card with protocol T=1.
// Some readers distinguish between the flow to connect a contact-based smart card and a contactless smart card.
func (r *Reader) ConnectSamCard() (smartcard.ICard, error) {
	return r.r.ConnectCard()
}

// ConnectSamCard_T0 ConnectCard connect card with protocol T=1.
func (r *Reader) ConnectSamCard_T0() (smartcard.ICard, error) {
	return r.r.ConnectSamCard_T0()
}

// ConnectSamCard_Tany ConnectCard connect card with protocol T=any.
func (r *Reader) ConnectSamCard_Tany() (smartcard.ICard, error) {
	return r.r.ConnectSamCard_Tany()
}

func (r *Reader) Name() string {
	return r.r.Name()
}

func (r *Reader) ConnectDirect() (pcsc.Card, error) {
	return r.r.ConnectDirect()
}

func (r *Reader) ConnectCardPCSC() (pcsc.Card, error) {
	return r.r.ConnectCardPCSC()
}

func (r *Reader) ConnectCardPCSC_T0() (pcsc.Card, error) {
	return r.r.ConnectCardPCSC_T0()
}

func (r *Reader) ConnectCardPCSC_Tany() (pcsc.Card, error) {
	return r.r.ConnectCardPCSC_Tany()
}
