package samfarm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/nmelo/smartcard/nxp/mifare"
	"github.com/nmelo/smartcard/nxp/mifare/samav2"
	"github.com/nmelo/smartcard/pcsc"
)

type SamDevice samav2.SamAv2

type Context struct {
	*pcsc.Context
}

var (
	regexReader = []string{"SAM", "00 00"}
)

func NewContext() (*Context, error) {
	ctx, err := pcsc.NewContext()
	if err != nil {
		return nil, err
	}
	return &Context{ctx}, nil
}

func GetSamDevices(ctx *Context) (map[uint64]SamDevice, error) {
	//ctx, err := mifare.NewContext()
	readers, err := pcsc.ListReaders(ctx.Context)
	if err != nil {
		return nil, err
	}

	samReaders := make(map[uint64]SamDevice)
	for _, r := range readers {
		for _, regx := range regexReader {
			if strings.Contains(strings.ToUpper(r), regx) {
				reader := pcsc.NewReader(ctx.Context, r)

				sam, err := samav2.ConnectSamAv2(reader)
				if err != nil {
					log.Println(err)
					break
				}
				atr, _ := sam.ATR()
				log.Printf("sam ATR: %q", atr)

				samVersion, err := sam.GetVersion()
				log.Printf("sam Version: [% X]", samVersion)
				if err != nil || len(samVersion) < 20 {
					break
				}

				serialBytes := []byte{0, 0}
				serialBytes = append(serialBytes, samVersion[14:20]...)
				serial := binary.BigEndian.Uint64(serialBytes)
				samReaders[serial] = sam
				break
			}
		}
	}
	return samReaders, nil
}

func ReaderChannel(sam samav2.SamAv2, input, output chan []byte) {
	//	log.Printf("readerChannel: in => %v, out => %v\n", input, output)
	defer func() {
		close(output)
		log.Printf("exit to readerChannel: in => %v, out => %v\n", input, output)
		sam.DisconnectCard()
	}()
	for {
		dataIn, ok := <-input
		if !ok {
			log.Printf("channel %v is not OK\n", output)
			return
		}
		//fmt.Printf("send to SAM: %v\n", dataIn)
		last := false
		var resp []byte
		var err error
		for {
			var dataSub []byte
			lenT := int(dataIn[4]) + 5
			if len(dataIn) > 5 && (lenT+1 < len(dataIn)) {
				dataSub = dataIn[0:lenT]
				if dataIn[lenT+1] == 0x00 {
					dataSub = append(dataIn, 0x00)
				}
			} else {
				dataSub = dataIn
				last = true
			}
			resp, err = sam.Apdu(dataSub)
			if err != nil {
				log.Printf("SAM error: %s\n", err)
				return
			}
			if mifare.VerifyResponseIso7816(resp) != nil {
				break
			}
			if last {
				break
			}
			dataIn = dataIn[len(dataSub):]
		}

		//fmt.Printf("output to SAM: %v\n", resp)
		timeout := 10
		if dataIn[1] == byte(mifare.SamAuthMFP) {
			timeout = 5000
		}

		select {
		case output <- resp:
		case <-time.After(time.Millisecond * time.Duration(timeout)):
			continue
			//default:
		}
		if dataIn[1] == byte(mifare.SamAuthMFP) {
			select {
			case dataIn2, ok := <-output:
				if !ok {
					log.Printf("channel %v is not OK\n", output)
					return
				}
				resp2, err := sam.Apdu(dataIn2)
				if err != nil {
					log.Printf("SAM error: %s\n", err)
					return
				}
				if err := mifare.VerifyResponseIso7816(resp2); err != nil {
					log.Println(err)
					continue
				}
				resp3, err := sam.DumpSessionKey()
				if err != nil {
					log.Printf("SAM error: %s\n", err)
					return
				}
				if err := mifare.VerifyResponseIso7816(resp2); err != nil {
					log.Println(err)
					continue
				}
				select {
				case output <- resp3:
				case <-time.After(time.Millisecond * time.Duration(timeout)):
					continue
					//default:
				}
			case <-time.After(time.Millisecond * time.Duration(timeout)):
				//				log.Println("channel free!!!")
				sam.Apdu(samav2.ApduSamKillAuthPICC())
				continue
			}
		}
	}
}

func SendCmd(input []byte, chns []chan []byte) (int, error) {
	//	log.Printf("sendCmd: in => %v\n", chns)
	timeout := time.After(20 * time.Millisecond)

	cases := make([]reflect.SelectCase, len(chns)+1)
	for i, ch := range chns {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectSend, Chan: reflect.ValueOf(ch), Send: reflect.ValueOf(input)}
	}

	cases[len(chns)] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timeout)}

	chosen, value, ok := reflect.Select(cases)

	/**
	only true for all Recv channels
	if !ok {
		return -1, errors.New(fmt.Sprintf("channel %v is closed, %v", chosen, chns[chosen]))
	}
	/**/

	if !value.IsValid() {
		return chosen, nil
	}
	switch value.Interface().(type) {
	case time.Time:
		log.Printf("SendCmd timeOut!!!; value: %v; isOK?: %v\n", value, ok)
		return -2, errors.New(fmt.Sprintf("timeout"))
	default:
		//		log.Printf("channel: %#v\n", cases[chosen])
	}

	return -3, nil

	//fmt.Printf("SendCmd channel: %#v; value: %v\n", cases[chosen], value)
}

func RecvResp(chns []chan []byte) ([]byte, int, error) {
	//	log.Printf("RecvResp: out => %v\n", chns)
	timeout := time.After(120 * time.Millisecond)

	cases := make([]reflect.SelectCase, len(chns)+1)
	for i, ch := range chns {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}
	}

	cases[len(chns)] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timeout)}

	chosen, value, ok := reflect.Select(cases)

	if !ok {
		return nil, chosen, errors.New(fmt.Sprintf("channel %v is closed", chosen))
	}

	switch value.Interface().(type) {
	case time.Time:
		log.Printf("RecvResp timeOut!!!; value: %v; isOK?: %v\n", value, ok)
		return nil, -1, errors.New("timeout")
	default:
		//		log.Printf("channel: %#v; value: [% X]\n", chns[chosen], value)
		return value.Bytes(), chosen, nil
	}

	return nil, chosen, nil
}
