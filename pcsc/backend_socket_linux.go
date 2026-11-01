//go:build linux && !cgo

package pcsc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dumacp/smartcard"
)

const (
	defaultPCSCDSocketPath1 = "/run/pcscd/pcscd.comm"
	defaultPCSCDSocketPath2 = "/var/run/pcscd/pcscd.comm"
	defaultDialTimeout      = 2 * time.Second
	defaultIOTimeout        = 3 * time.Second

	protocolVersionMajor = int32(4)
	protocolVersionMinor = int32(5)
	protocolBackwardMin  = int32(4)

	pcscSuccess = uint32(0x00000000)

	pcscScopeSystem = uint32(0x0002)

	pcscShareExclusive = uint32(0x0001)
	pcscShareShared    = uint32(0x0002)
	pcscShareDirect    = uint32(0x0003)

	pcscProtocolUndefined = uint32(0x0000)
	pcscProtocolT0        = uint32(0x0001)
	pcscProtocolT1        = uint32(0x0002)
	pcscProtocolAny       = uint32(0x0003)

	pcscLeaveCard   = uint32(0x0000)
	pcscResetCard   = uint32(0x0001)
	pcscUnpowerCard = uint32(0x0002)
	pcscEjectCard   = uint32(0x0003)

	pcscErrNoSmartcard   = uint32(0x8010000C)
	pcscErrRemovedCard   = uint32(0x80100069)
	pcscErrUnpoweredCard = uint32(0x80100067)
	pcscErrUnsupported   = uint32(0x8010001F)
	pcscErrProtoMismatch = uint32(0x8010000F)
	pcscErrServiceStop   = uint32(0x8010001E)

	pcscAttrATRString = uint32(0x00090303)

	maxReaderName              = 128
	maxATRSize                 = 33
	maxReadersContexts         = 16
	maxShortBufferSize         = 264
	maxExtendedBufferSize      = 4 + 3 + (1 << 16) + 3 + 2
	readerStateWireSize        = 184
	transmitStructSize         = 32
	controlStructSize          = 24
	connectStructSize          = 152
	disconnectStructSize       = 12
	endTransactionStructSize   = 12
	releaseContextStructSize   = 8
	establishContextStructSize = 12
	versionStructSize          = 12
	getsetStructSize           = 280
)

const (
	cmdEstablishContext = uint32(0x01)
	cmdReleaseContext   = uint32(0x02)
	cmdConnect          = uint32(0x04)
	cmdDisconnect       = uint32(0x06)
	cmdEndTransaction   = uint32(0x08)
	cmdTransmit         = uint32(0x09)
	cmdControl          = uint32(0x0A)
	cmdGetAttrib        = uint32(0x0F)
	cmdVersion          = uint32(0x11)
	cmdGetReadersState  = uint32(0x12)
)

func establishContext() (backendContext, error) {
	client, err := newPCSCDClient()
	if err != nil {
		return nil, smartcard.Error(fmt.Errorf("pcsc socket backend connect failed: %w", err))
	}
	if err := client.negotiateProtocol(); err != nil {
		_ = client.close()
		return nil, smartcard.Error(fmt.Errorf("pcsc protocol negotiation failed: %w", err))
	}
	hContext, err := client.establishContext(pcscScopeSystem)
	if err != nil {
		_ = client.close()
		return nil, smartcard.Error(fmt.Errorf("pcsc establish context failed: %w", err))
	}
	return &socketContext{
		client:   client,
		hContext: hContext,
		valid:    true,
	}, nil
}

type socketContext struct {
	client   *pcscdClient
	hContext uint32
	valid    bool
}

func (c *socketContext) IsValid() (bool, error) {
	if c == nil || c.client == nil {
		return false, smartcard.Error(fmt.Errorf("nil socket context, %w", smartcard.ErrComm))
	}
	if !c.valid {
		return false, smartcard.Error(fmt.Errorf("socket context closed, %w", smartcard.ErrComm))
	}
	if c.hContext == 0 {
		return false, smartcard.Error(fmt.Errorf("socket context not established, %w", smartcard.ErrComm))
	}
	if err := c.client.ping(); err != nil {
		return false, smartcard.Error(fmt.Errorf("pcsc socket not reachable: %w", err))
	}
	return true, nil
}

func (c *socketContext) ListReaders() ([]string, error) {
	states, err := c.client.getReadersState()
	if err != nil {
		return nil, smartcard.Error(fmt.Errorf("ListReaders failed: %w", err))
	}
	readers := make([]string, 0, len(states))
	for _, s := range states {
		if s.name != "" {
			readers = append(readers, s.name)
		}
	}
	if len(readers) == 0 {
		return nil, smartcard.Error(fmt.Errorf("no readers available, %w", smartcard.ErrNoSmartcard))
	}
	return readers, nil
}

func (c *socketContext) Connect(readerName string, share shareMode, protocol protocolType) (backendCard, error) {
	if ok, err := c.IsValid(); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, smartcard.Error(fmt.Errorf("context invalid, %w", smartcard.ErrComm))
	}
	hCard, activeProtocol, err := c.client.connect(c.hContext, readerName, toWireShareMode(share), toWireProtocol(protocol))
	if err != nil {
		return nil, err
	}
	return &socketCard{
		client:         c.client,
		hCard:          hCard,
		activeProtocol: activeProtocol,
	}, nil
}

func (c *socketContext) Release() error {
	if c == nil || c.client == nil {
		return nil
	}
	if c.hContext != 0 {
		_ = c.client.releaseContext(c.hContext)
	}
	c.valid = false
	c.hContext = 0
	return c.client.close()
}

// socketCard is the linux !cgo implementation backed by pcsc-lite socket calls.
type socketCard struct {
	client         *pcscdClient
	hCard          int32
	activeProtocol uint32
}

func (c *socketCard) Disconnect(disposition dispositionType) error {
	err := c.client.disconnect(c.hCard, toWireDisposition(disposition))
	if err != nil {
		return smartcard.Error(fmt.Errorf("Disconnect failed: %w", err))
	}
	return nil
}

func (c *socketCard) Transmit(apdu []byte) ([]byte, error) {
	resp, err := c.client.transmit(c.hCard, c.activeProtocol, apdu)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *socketCard) Control(ioctl uint32, apdu []byte) ([]byte, error) {
	resp, err := c.client.control(c.hCard, ioctl, apdu)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *socketCard) EndTransaction(disposition dispositionType) error {
	err := c.client.endTransaction(c.hCard, toWireDisposition(disposition))
	if err != nil {
		return smartcard.Error(fmt.Errorf("EndTransaction failed: %w", err))
	}
	return nil
}

func (c *socketCard) Status() (*cardStatus, error) {
	atr, err := c.client.getAttrib(c.hCard, pcscAttrATRString)
	if err != nil {
		return nil, err
	}
	return &cardStatus{Atr: atr}, nil
}

type pcscdClient struct {
	conn net.Conn
	mu   sync.Mutex

	path string
}

func newPCSCDClient() (*pcscdClient, error) {
	paths := socketPaths()
	var dialErrs []string

	for _, p := range paths {
		if p == "" {
			continue
		}
		conn, err := net.DialTimeout("unix", p, defaultDialTimeout)
		if err != nil {
			dialErrs = append(dialErrs, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(defaultIOTimeout))
		_ = conn.SetDeadline(time.Time{})
		return &pcscdClient{conn: conn, path: p}, nil
	}

	if len(dialErrs) == 0 {
		return nil, fmt.Errorf("no pcscd socket paths configured")
	}
	return nil, fmt.Errorf("cannot connect to pcscd socket (%s)", strings.Join(dialErrs, "; "))
}

func (c *pcscdClient) ping() error {
	if c == nil || c.conn == nil {
		return fmt.Errorf("pcsc client disconnected")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.conn.SetDeadline(time.Now().Add(defaultIOTimeout)); err != nil {
		return err
	}
	if err := c.conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	return nil
}

func (c *pcscdClient) negotiateProtocol() error {
	minor := protocolVersionMinor
	for attempt := 0; attempt < 2; attempt++ {
		payload := make([]byte, versionStructSize)
		binary.LittleEndian.PutUint32(payload[0:4], uint32(protocolVersionMajor))
		binary.LittleEndian.PutUint32(payload[4:8], uint32(minor))
		binary.LittleEndian.PutUint32(payload[8:12], pcscSuccess)

		resp, err := c.request(cmdVersion, payload, versionStructSize)
		if err != nil {
			return err
		}
		serverMajor := int32(binary.LittleEndian.Uint32(resp[0:4]))
		serverMinor := int32(binary.LittleEndian.Uint32(resp[4:8]))
		rv := binary.LittleEndian.Uint32(resp[8:12])

		if rv == pcscSuccess {
			return nil
		}

		if rv == pcscErrServiceStop &&
			serverMajor == protocolVersionMajor &&
			serverMinor >= protocolBackwardMin &&
			serverMinor < minor {

			minor = serverMinor
			continue
		}

		return pcscRVError("CMD_VERSION", rv)
	}

	return pcscRVError("CMD_VERSION", pcscErrServiceStop)
}

func (c *pcscdClient) establishContext(scope uint32) (uint32, error) {
	payload := make([]byte, establishContextStructSize)
	binary.LittleEndian.PutUint32(payload[0:4], scope)
	binary.LittleEndian.PutUint32(payload[4:8], 0)
	binary.LittleEndian.PutUint32(payload[8:12], pcscSuccess)

	resp, err := c.request(cmdEstablishContext, payload, establishContextStructSize)
	if err != nil {
		return 0, err
	}
	hContext := binary.LittleEndian.Uint32(resp[4:8])
	rv := binary.LittleEndian.Uint32(resp[8:12])
	if err := pcscRVError("SCARD_ESTABLISH_CONTEXT", rv); err != nil {
		return 0, err
	}
	return hContext, nil
}

func (c *pcscdClient) releaseContext(hContext uint32) error {
	payload := make([]byte, releaseContextStructSize)
	binary.LittleEndian.PutUint32(payload[0:4], hContext)
	binary.LittleEndian.PutUint32(payload[4:8], pcscSuccess)

	resp, err := c.request(cmdReleaseContext, payload, releaseContextStructSize)
	if err != nil {
		return err
	}
	rv := binary.LittleEndian.Uint32(resp[4:8])
	return pcscRVError("SCARD_RELEASE_CONTEXT", rv)
}

func (c *pcscdClient) getReadersState() ([]readerState, error) {
	resp, err := c.request(cmdGetReadersState, nil, maxReadersContexts*readerStateWireSize)
	if err != nil {
		return nil, err
	}
	out := make([]readerState, 0, maxReadersContexts)
	for i := 0; i < maxReadersContexts; i++ {
		off := i * readerStateWireSize
		entry := resp[off : off+readerStateWireSize]
		name := cString(entry[:maxReaderName])
		if name == "" {
			continue
		}
		atrLen := binary.LittleEndian.Uint32(entry[176:180])
		if atrLen > maxATRSize {
			atrLen = maxATRSize
		}
		atr := make([]byte, atrLen)
		copy(atr, entry[140:140+atrLen])
		out = append(out, readerState{
			name:     name,
			atr:      atr,
			protocol: binary.LittleEndian.Uint32(entry[180:184]),
		})
	}
	return out, nil
}

func (c *pcscdClient) connect(hContext uint32, reader string, share uint32, preferredProtocol uint32) (int32, uint32, error) {
	payload := make([]byte, connectStructSize)
	binary.LittleEndian.PutUint32(payload[0:4], hContext)
	copy(payload[4:4+maxReaderName], []byte(reader))
	binary.LittleEndian.PutUint32(payload[132:136], share)
	binary.LittleEndian.PutUint32(payload[136:140], preferredProtocol)
	binary.LittleEndian.PutUint32(payload[140:144], 0)
	binary.LittleEndian.PutUint32(payload[144:148], 0)
	binary.LittleEndian.PutUint32(payload[148:152], pcscSuccess)

	resp, err := c.request(cmdConnect, payload, connectStructSize)
	if err != nil {
		return 0, 0, err
	}
	hCard := int32(binary.LittleEndian.Uint32(resp[140:144]))
	activeProtocol := binary.LittleEndian.Uint32(resp[144:148])
	rv := binary.LittleEndian.Uint32(resp[148:152])
	if err := pcscRVError("SCARD_CONNECT", rv); err != nil {
		return 0, 0, err
	}
	return hCard, activeProtocol, nil
}

func (c *pcscdClient) disconnect(hCard int32, disposition uint32) error {
	payload := make([]byte, disconnectStructSize)
	binary.LittleEndian.PutUint32(payload[0:4], uint32(hCard))
	binary.LittleEndian.PutUint32(payload[4:8], disposition)
	binary.LittleEndian.PutUint32(payload[8:12], pcscSuccess)

	resp, err := c.request(cmdDisconnect, payload, disconnectStructSize)
	if err != nil {
		return err
	}
	rv := binary.LittleEndian.Uint32(resp[8:12])
	return pcscRVError("SCARD_DISCONNECT", rv)
}

func (c *pcscdClient) endTransaction(hCard int32, disposition uint32) error {
	payload := make([]byte, endTransactionStructSize)
	binary.LittleEndian.PutUint32(payload[0:4], uint32(hCard))
	binary.LittleEndian.PutUint32(payload[4:8], disposition)
	binary.LittleEndian.PutUint32(payload[8:12], pcscSuccess)

	resp, err := c.request(cmdEndTransaction, payload, endTransactionStructSize)
	if err != nil {
		return err
	}
	rv := binary.LittleEndian.Uint32(resp[8:12])
	return pcscRVError("SCARD_END_TRANSACTION", rv)
}

func (c *pcscdClient) transmit(hCard int32, protocol uint32, apdu []byte) ([]byte, error) {
	headerPayload := make([]byte, transmitStructSize)
	binary.LittleEndian.PutUint32(headerPayload[0:4], uint32(hCard))
	binary.LittleEndian.PutUint32(headerPayload[4:8], protocol)
	binary.LittleEndian.PutUint32(headerPayload[8:12], uint32(ioRequestLength()))
	binary.LittleEndian.PutUint32(headerPayload[12:16], uint32(len(apdu)))
	binary.LittleEndian.PutUint32(headerPayload[16:20], pcscProtocolAny)
	binary.LittleEndian.PutUint32(headerPayload[20:24], uint32(ioRequestLength()))
	binary.LittleEndian.PutUint32(headerPayload[24:28], maxExtendedBufferSize)
	binary.LittleEndian.PutUint32(headerPayload[28:32], pcscSuccess)

	respHeader, respPayload, err := c.requestWithOptionalPayload(cmdTransmit, headerPayload, apdu, transmitStructSize)
	if err != nil {
		return nil, err
	}
	rv := binary.LittleEndian.Uint32(respHeader[28:32])
	if err := pcscRVError("SCARD_TRANSMIT", rv); err != nil {
		return nil, err
	}
	return respPayload, nil
}

func (c *pcscdClient) control(hCard int32, ioctl uint32, apdu []byte) ([]byte, error) {
	headerPayload := make([]byte, controlStructSize)
	binary.LittleEndian.PutUint32(headerPayload[0:4], uint32(hCard))
	binary.LittleEndian.PutUint32(headerPayload[4:8], ioctl)
	binary.LittleEndian.PutUint32(headerPayload[8:12], uint32(len(apdu)))
	binary.LittleEndian.PutUint32(headerPayload[12:16], maxExtendedBufferSize)
	binary.LittleEndian.PutUint32(headerPayload[16:20], 0)
	binary.LittleEndian.PutUint32(headerPayload[20:24], pcscSuccess)

	respHeader, respPayload, err := c.requestWithOptionalPayload(cmdControl, headerPayload, apdu, controlStructSize)
	if err != nil {
		return nil, err
	}
	rv := binary.LittleEndian.Uint32(respHeader[20:24])
	if err := pcscRVError("SCARD_CONTROL", rv); err != nil {
		return nil, err
	}
	return respPayload, nil
}

func (c *pcscdClient) getAttrib(hCard int32, attrID uint32) ([]byte, error) {
	payload := make([]byte, getsetStructSize)
	binary.LittleEndian.PutUint32(payload[0:4], uint32(hCard))
	binary.LittleEndian.PutUint32(payload[4:8], attrID)
	binary.LittleEndian.PutUint32(payload[272:276], maxShortBufferSize)
	binary.LittleEndian.PutUint32(payload[276:280], pcscSuccess)

	resp, err := c.request(cmdGetAttrib, payload, getsetStructSize)
	if err != nil {
		return nil, err
	}
	cbAttrLen := binary.LittleEndian.Uint32(resp[272:276])
	rv := binary.LittleEndian.Uint32(resp[276:280])
	if err := pcscRVError("SCARD_GET_ATTRIB", rv); err != nil {
		return nil, err
	}
	if cbAttrLen > maxShortBufferSize {
		cbAttrLen = maxShortBufferSize
	}
	out := make([]byte, cbAttrLen)
	copy(out, resp[8:8+cbAttrLen])
	return out, nil
}

func (c *pcscdClient) request(command uint32, payload []byte, respLen int) ([]byte, error) {
	var out []byte
	err := c.withExchange(func() error {
		if err := c.writeMessage(command, payload); err != nil {
			return err
		}
		resp, err := c.readExact(respLen)
		if err != nil {
			return err
		}
		out = resp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pcscdClient) requestWithOptionalPayload(command uint32, headerPayload []byte, extraPayload []byte, respHeaderLen int) ([]byte, []byte, error) {
	var respHeader []byte
	var respPayload []byte
	err := c.withExchange(func() error {
		if err := c.writeMessage(command, headerPayload); err != nil {
			return err
		}
		if len(extraPayload) > 0 {
			if err := c.writeRaw(extraPayload); err != nil {
				return err
			}
		}
		hdr, err := c.readExact(respHeaderLen)
		if err != nil {
			return err
		}
		respHeader = hdr

		var payloadLen uint32
		switch command {
		case cmdTransmit:
			payloadLen = binary.LittleEndian.Uint32(hdr[24:28])
			if payloadLen > maxExtendedBufferSize {
				payloadLen = maxExtendedBufferSize
			}
			if binary.LittleEndian.Uint32(hdr[28:32]) != pcscSuccess {
				payloadLen = 0
			}
		case cmdControl:
			payloadLen = binary.LittleEndian.Uint32(hdr[16:20])
			if payloadLen > maxExtendedBufferSize {
				payloadLen = maxExtendedBufferSize
			}
			if binary.LittleEndian.Uint32(hdr[20:24]) != pcscSuccess {
				payloadLen = 0
			}
		}

		if payloadLen > 0 {
			data, err := c.readExact(int(payloadLen))
			if err != nil {
				return err
			}
			respPayload = data
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return respHeader, respPayload, nil
}

func (c *pcscdClient) withExchange(fn func() error) error {
	if c == nil {
		return fmt.Errorf("nil pcsc client")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("pcsc client disconnected")
	}
	if err := c.conn.SetDeadline(time.Now().Add(defaultIOTimeout)); err != nil {
		return err
	}
	defer func() {
		_ = c.conn.SetDeadline(time.Time{})
	}()
	return fn()
}

func (c *pcscdClient) writeMessage(command uint32, payload []byte) error {
	header := make([]byte, 8)
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint32(header[4:8], command)
	if err := c.writeRaw(header); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	return c.writeRaw(payload)
}

func (c *pcscdClient) writeRaw(data []byte) error {
	for len(data) > 0 {
		n, err := c.conn.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func (c *pcscdClient) readExact(n int) ([]byte, error) {
	if n <= 0 {
		return []byte{}, nil
	}
	b := make([]byte, n)
	_, err := io.ReadFull(c.conn, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (c *pcscdClient) close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.conn.Close()
	c.conn = nil
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func socketPaths() []string {
	if path := os.Getenv("PCSCD_SOCKET"); path != "" {
		return []string{path, defaultPCSCDSocketPath1, defaultPCSCDSocketPath2}
	}
	return []string{defaultPCSCDSocketPath1, defaultPCSCDSocketPath2}
}

type readerState struct {
	name     string
	atr      []byte
	protocol uint32
}

type pcscWireError struct {
	op string
	rv uint32
}

func (e *pcscWireError) Error() string {
	return fmt.Sprintf("%s failed: %s (0x%08X)", e.op, pcscErrorName(e.rv), e.rv)
}

func pcscRVError(op string, rv uint32) error {
	if rv == pcscSuccess {
		return nil
	}
	return &pcscWireError{op: op, rv: rv}
}

func pcscErrorName(rv uint32) string {
	switch rv {
	case pcscErrNoSmartcard:
		return "SCARD_E_NO_SMARTCARD"
	case pcscErrRemovedCard:
		return "SCARD_W_REMOVED_CARD"
	case pcscErrUnpoweredCard:
		return "SCARD_W_UNPOWERED_CARD"
	case pcscErrUnsupported:
		return "SCARD_E_UNSUPPORTED_FEATURE"
	case pcscErrProtoMismatch:
		return "SCARD_E_PROTO_MISMATCH"
	default:
		return "PCSC_ERROR"
	}
}

func extractPCSCRV(err error) (uint32, bool) {
	if err == nil {
		return 0, false
	}
	if pe, ok := err.(*pcscWireError); ok {
		return pe.rv, true
	}
	if se, ok := err.(*smartcard.SmartcardError); ok {
		if pe, ok := se.Err.(*pcscWireError); ok {
			return pe.rv, true
		}
	}
	return 0, false
}

func isNoSmartcardError(err error) bool {
	rv, ok := extractPCSCRV(err)
	if !ok {
		return false
	}
	return rv == pcscErrNoSmartcard || rv == pcscErrRemovedCard || rv == pcscErrUnpoweredCard
}

func isKnownCardError(err error) bool {
	_, ok := extractPCSCRV(err)
	return ok
}

func cString(b []byte) string {
	idx := bytesIndexByte(b, 0)
	if idx < 0 {
		return string(b)
	}
	return string(b[:idx])
}

func bytesIndexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

func ioRequestLength() int {
	// SCARD_IO_REQUEST uses unsigned long fields in pcsclite.
	if is64Bit() {
		return 16
	}
	return 8
}

func is64Bit() bool {
	return (32 << (^uint(0) >> 63)) == 64
}

func toWireShareMode(share shareMode) uint32 {
	switch share {
	case shareExclusive:
		return pcscShareExclusive
	case shareShared:
		return pcscShareShared
	case shareDirect:
		return pcscShareDirect
	default:
		return pcscShareShared
	}
}

func toWireProtocol(protocol protocolType) uint32 {
	switch protocol {
	case protocolT0:
		return pcscProtocolT0
	case protocolT1:
		return pcscProtocolT1
	case protocolAny:
		return pcscProtocolAny
	case protocolUndefined:
		return pcscProtocolUndefined
	default:
		return pcscProtocolAny
	}
}

func toWireDisposition(disposition dispositionType) uint32 {
	switch disposition {
	case dispositionLeaveCard:
		return pcscLeaveCard
	case dispositionResetCard:
		return pcscResetCard
	case dispositionUnpowerCard:
		return pcscUnpowerCard
	case dispositionEjectCard:
		return pcscEjectCard
	default:
		return pcscLeaveCard
	}
}
