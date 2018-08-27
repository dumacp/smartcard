package samfarm


import (
        "fmt"
        "testing"
	"time"
	"math/rand"
)

func processorTest(input <-chan []byte, output chan<- []byte ) {
	for {
		data := <-input
		output <- data
		time.Sleep(time.Duration(rand.Intn(3)) * time.Second)
	}
}

func TestSendRecv(t *testing.T) {
	t.Log("Start Logs")

	chnsInput := make([]chan []byte, 10)
	chnsOutput := make([]chan []byte, 10)

	for i, _ := range chnsInput {
		chnsInput[i] = make(chan []byte)
		chnsOutput[i] = make(chan []byte)
		go processorTest(chnsInput[i], chnsOutput[i])
	}

				//fmt.Printf("job channel: %#v, value", ch, <-ch)

	input := []byte{0x00, 0x01, 0x02, 0x03}

	for i:=0; i<30; i++ {
		SendCmd(input, chnsInput)
		RecvResp(chnsOutput)
	}
}

func TestListReaders(t *testing.T) {
	t.Log("Start Logs")

	ctx, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}

	for i:=0; i<10; i++ {
		devs, err := GetSamDevices(ctx)
		if err != nil {
			t.Fatal(err)
		}

		for i, dev := range devs {
			fmt.Printf("device %v: %+v\n", i, dev)
			//dev.DisconnectCard()
		}
		time.Sleep(time.Second * 3)
	}
}

