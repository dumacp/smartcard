package main

import (
	"fmt"
	"log"
	"flag"
	"time"
	"github.com/dumacp/smartcard/samfarm"
	MQTT "github.com/eclipse/paho.mqtt.golang"
)


var ctx *samfarm.Context
var samDevices map[uint64]samfarm.SamDevice
var samInputChannels map[uint64]chan []byte
var samOutputChannels map[uint64]chan []byte

var urlBroker string
var topicNameInputs string
var topicNameOutputs string

func init() {
	flag.StringVar(&urlBroker, "urlBroker", "tcp://127.0.0.1:1883", "MQTT url broker")
	flag.StringVar(&topicNameInputs, "topicNameInputs", "SAMFARM/CMD/#", "MQTT topic name to cmd requests")
	flag.StringVar(&topicNameOutputs, "topicNameOutputs", "SAMFARM/RESP/#", "MQTT topic name to cmd responses")

	samDevices = make(map[uint64]samfarm.SamDevice)
	samInputChannels = make(map[uint64]chan []byte)
	samOutputChannels = make(map[uint64]chan []byte)
}

func(client MQTT.Client, msg MQTT.Message) {

var f MQTT.MessageHandler = func(client MQTT.Client, msg MQTT.Message) {
	fmt.Printf("TOPIC: %s\n", msg.Topic())
	fmt.Printf("MSG: %s\n", msg.Payload())


	samInputs := make([]chan []byte,0)
	samInKeys := make([]uint64,0)
	samOutputs := make([]chan []byte,0)
	samOutKeys := make([]uint64,0)

	for k, input := range samInputChannels {
		samInputs = append(samInputs, input)
		samInKeys = append(samInKeys,k)
	}
	for k, output := range samOutputChannels {
		samOutputs = append(samOutputs,output)
		samOutKeys = append(samOutKeys,k)
	}

	if len(samInputs) > 0 && len(samOutputs) > 0 {
		fmt.Printf("SEND DATA\n")
		go func() {
			data, chosen2, err2 := samfarm.RecvResp(samOutputs)
			if err2 != nil {
				log.Printf("%s; channel: %v\n", err2, chosen2)
				//if chosen2 >= 0 {
				//	close(samInputs[chosen2])
				//}
				if chosen2 >= 0 && chosen2 < len(samOutKeys) {
					k := samOutKeys[chosen2]
					log.Printf("delete sam: %v, %v\n", k, chosen2)
					delete(samInputChannels, k)
					delete(samOutputChannels, k)
				}
				return
			}
			fmt.Printf("DATA: %+v\n", data)
		}()
		go func() {
			chosen1, err1 := samfarm.SendCmd(msg.Payload(), samInputs)
			if err1 != nil {
				log.Printf("%s\n", err1)
			}
			if chosen1 < 0 {
				return
			}
		}()
	}
}

func verifyCreateSamChannels(ctx *samfarm.Context) {
	sams, err := samfarm.GetSamDevices(ctx)
	if err != nil {
		log.Println(err)
		return
	}

	for k, sam := range sams {
		/**
		isn't necesary
		if chOld, ok := samInputChannels[k]; ok {
			close(chOld)
		}
		/**/
		fmt.Printf("device %v: %+v\n",k, sam)
		samDevices[k] = sam
		inCh := make(chan []byte)
                outCh := make(chan []byte)
                go samfarm.ReaderChannel(sam, inCh, outCh)
                samInputChannels[k] = inCh
                samOutputChannels[k] = outCh
		fmt.Printf("devices: %+v\n", samDevices)
	}
}




func main() {

	flag.Parse()

	clientId := fmt.Sprintf("go-samfarm-client-%s", time.Now().UnixNano())

	opts := MQTT.NewClientOptions().AddBroker(urlBroker)
	opts.SetClientID(clientId)
	opts.SetDefaultPublishHandler(f)

	c := MQTT.NewClient(opts)
	if token := c.Connect(); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}

	if token := c.Subscribe(topicNameInputs, 0, nil); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}

	ctx, err := samfarm.NewContext()
	if err != nil {
		log.Fatal(err)
	}

	verifyCreateSamChannels(ctx)

	timeout := time.Tick(time.Second * 10)


	for {
		select {
		case <-timeout:
			verifyCreateSamChannels(ctx)
		}
	}
}
