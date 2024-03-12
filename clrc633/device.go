package clrc633

import (
	"time"

	"periph.io/x/conn/v3/spi"
)

type Device struct {
	portcloser spi.PortCloser
	conn       spi.Conn
}

func NewDevice(path string) (*Device, error) {

	closer, conn, err := connect(path)
	if err != nil {
		return nil, err
	}

	if err := reset(conn); err != nil {
		return nil, err
	}

	if err := init_iso14443_Dev(conn); err != nil {
		return nil, err
	}

	return &Device{
		portcloser: closer,
		conn:       conn,
	}, nil
}

func (d *Device) Close() error {
	return d.portcloser.Close()
}

func (d *Device) Request(tagType byte, timeout time.Duration) (byte, error) {
	return request(d.conn, tagType, timeout)
}

func (d *Device) Anticoll(timeout time.Duration) ([]byte, error) {
	return anticoll(d.conn, timeout)
}

func (d *Device) Anticoll2(timeout time.Duration) ([]byte, error) {
	return anticoll2(d.conn, timeout)
}

func (d *Device) Select(data []byte, timeout time.Duration) (byte, error) {
	return selectTag(d.conn, data, timeout)
}

func (d *Device) Select2(data []byte, timeout time.Duration) (byte, error) {
	return select2Tag(d.conn, data, timeout)
}

func (d *Device) Transceive(data []byte, timeout time.Duration) ([]byte, error) {
	// fmt.Printf("send apdu: [% X]\n", data)
	resp, err := sendApdu(d.conn, data, timeout)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("response sw: [% X]\n", resp)
	return resp, nil
}

func (d *Device) LoadKey(key []byte, timeout time.Duration) error {
	// fmt.Printf("load key: [% X]\n", key)
	return loadKey(d.conn, key, timeout)
}

func (d *Device) Auth(keyType int, block int, uid []byte, timeout time.Duration) error {
	// fmt.Printf("send %q auth (%d) apdu: [% X]\n", keyType, block, uid)
	return auth(d.conn, byte(keyType), byte(block), uid, timeout)
}
