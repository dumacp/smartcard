package samfarm


import (
	"fmt"
	"errors"
	"reflect"
	"log"
	"strings"
	"time"
	"encoding/binary"
	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

type SamDevice mifare.SamAv2

type Context struct{
	*smartcard.Context
}

func NewContext() (*Context, error) {
	ctx, err := smartcard.NewContext()
	if err != nil {
                return nil, err
        }
	return &Context{ctx}, nil
}

func GetSamDevices(ctx *Context) (map[uint64]SamDevice, error) {
	//ctx, err := mifare.NewContext()
	readers, err := smartcard.ListReaders(ctx.Context)
	if err != nil {
		return nil, err
	}

	samReaders := make(map[uint64]SamDevice)
	for _, r := range readers {
		if strings.Contains(strings.ToUpper(r), "SAM") {
			reader := smartcard.NewReader(ctx.Context, r)
			sam, err := mifare.ConnectSamAv2(reader)
			if  err != nil {
				log.Println(err)
				continue
			}
			samVersion, err := sam.GetVersion()
			if err != nil || len(samVersion) < 20 {
				continue
			}
			serialBytes := []byte{0, 0}
			serialBytes = append(serialBytes, samVersion[14:20]...)
			serial := binary.BigEndian.Uint64(serialBytes)
			samReaders[serial] = sam
		}
	}
	return samReaders, nil
}

func ReaderChannel(sam mifare.SamAv2, input, output chan []byte) {
	fmt.Printf("readerChannel: in => %v, out => %v\n", input, output)
	defer func() {
		close(output)
		log.Printf("exit to readerChannel: in => %v, out => %v\n", input, output)
		sam.DisconnectCard()
	}()
	for {
		dataIn, ok := <-input
		if !ok {
			return
		}
		//fmt.Printf("send to SAM: %v\n", dataIn)
		resp, err := sam.Apdu(dataIn)
		if err != nil {
			return
		}

		//fmt.Printf("output to SAM: %v\n", resp)
		select {
		case output <- resp:
		default:
		}
	}
}

func SendCmd(input []byte, chns []chan []byte) (int, error) {
	fmt.Printf("sendCmd: in => %v\n", chns)
	timeout := time.After(20 * time.Millisecond)

	cases := make([]reflect.SelectCase, len(chns) +1)
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
		fmt.Printf("SendCmd timeOut!!!; value: %v; isOK?: %v\n", value, ok)
		return -2, errors.New(fmt.Sprintf("timeout"))
	default:
		fmt.Printf("channel: %#v\n", cases[chosen])
	}

	return -3, nil

	//fmt.Printf("SendCmd channel: %#v; value: %v\n", cases[chosen], value)
}

func RecvResp(chns []chan []byte) ([]byte, int, error) {
	fmt.Printf("RecvResp: out => %v\n", chns)
	timeout := time.After(120 * time.Millisecond)

        cases := make([]reflect.SelectCase, len(chns) +1)
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
		fmt.Printf("RecvResp timeOut!!!; value: %v; isOK?: %v\n", value, ok)
		return nil, -1, errors.New("timeout")
        default:
		fmt.Printf("channel: %#v; value: %v\n", chns[chosen], value)
		return value.Bytes(), chosen, nil
        }

	return nil, chosen, nil
}


