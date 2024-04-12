package acs

import (
	"fmt"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/pcsc"
)

type Reader struct {
	PcscReader  pcsc.Reader
	pollManuall bool
}

func NewReader(ctx *pcsc.Context, readerName string) *Reader {

	r := &Reader{
		PcscReader: pcsc.NewReader(ctx, readerName),
	}
	return r

}

func NewReaderFromPcscReader(r pcsc.Reader) *Reader {

	reader := &Reader{
		PcscReader: r,
	}
	return reader

}

func (r *Reader) SetAutomaticPoll(a bool) error {

	p, err := r.PcscReader.ConnectDirect()
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

func (r *Reader) SpeedControl(a byte) error {

	p, err := r.PcscReader.ConnectDirect()
	if err != nil {
		return err
	}
	defer p.DisconnectCard()

	resp, err := p.ControlApdu(0x42000000+2079, []byte{0x09, 0x00})
	if err != nil {
		return err
	}
	if len(resp) <= 0 {
		return fmt.Errorf("error in response, nil response")
	}
	var apdu1 []byte
	if resp[len(resp)-1] != a {
		apdu1 = []byte{0x09, 0x01, a}
	}
	if _, err := p.ControlApdu(0x42000000+2079, apdu1); err != nil {
		return err
	}
	return nil
}

func (r *Reader) BuzzerControl(a byte) error {

	p, err := r.PcscReader.ConnectDirect()
	if err != nil {
		return err
	}
	defer p.DisconnectCard()

	resp, err := p.ControlApdu(0x42000000+2079, []byte{0x21, 0x00})
	if err != nil {
		return err
	}
	if len(resp) <= 0 {
		return fmt.Errorf("error in response, nil response")
	}
	var apdu1 []byte
	if resp[len(resp)-1] != a {
		apdu1 = []byte{0x21, 0x01, a}
	}
	if _, err := p.ControlApdu(0x42000000+2079, apdu1); err != nil {
		return err
	}
	return nil
}

func (r *Reader) SetEnforceISO14443A_4(a bool) error {

	p, err := r.PcscReader.ConnectDirect()
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
		if err := func() error {
			p, err := r.PcscReader.ConnectDirect()
			if err != nil {
				return err
			}
			defer p.DisconnectCard()
			// TODO why?
			if _, err := p.ControlApdu(0x42000000+2079, []byte{0x22, 0x01, 0x01}); err != nil {
				// if _, err := p.ControlApdu(0x42000000+2079, []byte{0x22, 0x00}); err != nil {
				return err
			}
			apdu := []byte{0x25, 0x00}
			if resp, err := p.ControlApdu(0x42000000+2079, apdu); err != nil {
				return err
			} else if len(resp) > 0 && resp[len(resp)-1] > 0x01 {
				return nil
			}
			return smartcard.ErrNoSmartcard
		}(); err != nil {
			return nil, err
		}
	}

	return r.PcscReader.ConnectCard()
}

// ConnectCard connect card with protocol T=1.
// Some readers distinguish between the flow to connect a contact-based smart card and a contactless smart card.
func (r *Reader) ConnectSamCard() (smartcard.ICard, error) {
	return r.PcscReader.ConnectCard()
}

// ConnectSamCard_T0 ConnectCard connect card with protocol T=1.
func (r *Reader) ConnectSamCard_T0() (smartcard.ICard, error) {
	return r.PcscReader.ConnectSamCard_T0()
}

// ConnectSamCard_Tany ConnectCard connect card with protocol T=any.
func (r *Reader) ConnectSamCard_Tany() (smartcard.ICard, error) {
	return r.PcscReader.ConnectSamCard_Tany()
}

func (r *Reader) Name() string {
	return r.PcscReader.Name()
}

func (r *Reader) ConnectDirect() (pcsc.Card, error) {
	return r.PcscReader.ConnectDirect()
}

func (r *Reader) ConnectCardPCSC() (pcsc.Card, error) {
	return r.PcscReader.ConnectCardPCSC()
}

func (r *Reader) ConnectCardPCSC_T0() (pcsc.Card, error) {
	return r.PcscReader.ConnectCardPCSC_T0()
}

func (r *Reader) ConnectCardPCSC_Tany() (pcsc.Card, error) {
	return r.PcscReader.ConnectCardPCSC_Tany()
}
