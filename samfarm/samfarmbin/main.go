/**
this app implements a SAMav2 cluster through MQTT topics


The messages are APDU Commands ([]byte) sent to "<topicName*Inputs>",
and APDU Responses ([]byte) that are left in "<topicNameOutput>"


* <topicNameAsyncInputs> is the prefix of topic to generic command (sent to any SAM device).
* <topicNameSyncInputs> is the prefix of topic to especific command (sent to especific SAM device).
* <topicNameOutput> is the prefix of topic to responses.

The "<topicNameAsyncInputs/*>" should end with suffix "/id1/id2". Where "id1" (hexstring) is a
identifier for transaction, and "id2" (hexstring) is the identifier for app client who sent the
command and will be receiver of the response.

The "<topicNameSyncInputs/*> should end with suffix "/id3/id1/id2". Where "id3" (hexstring) is the
identifier for the SAM device that should reciver the APDU command, and "id2" (hexstring) is the
identifier for app client who sent the command and will be receiver of the response and "id1"
(hexstring) is the identifier of the transaction.

The "<topicNameOutput/*>" end with suffix "/id2/id1/id3". Where "id3" (hexstring) is the identifier
for the SAM device that left the response, "id2" (hexstring) is the identifier for app client who
will be receiver of the response and "id1" (hexstring) is the identifier of the transaction.



Usage of ./samfarmbin:
  -clientName string
    	Client Name conecction mqtt (default "go-samfarm-client-1541166125194006904")
  -isShared
    	is shared subcription?
  -key string
    	key aes128 (default "00000000000000000000000000000000")
  -password string
    	MQTT Password broker
  -topicNameAsyncInputs string
    	MQTT topic name to cmd requests Async (default "SAMFARM/ASYN/")
  -topicNameOutputs string
    	MQTT topic name to cmd responses (default "SAMFARM/RESP/")
  -topicNameSyncInputs string
    	MQTT topic name to cmd request Sync (default "SAMFARM/SYN/")
  -urlBroker string
    	MQTT url broker (default "tcp://127.0.0.1:1883")
  -username string
    	MQTT Username broker

/**/
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net/url"
	"time"

	_ "github.com/nmelo/smartcard/nxp/mifare"
	"github.com/nmelo/smartcard/samfarm"
	MQTT "github.com/eclipse/paho.mqtt.golang"
)

var ctx *samfarm.Context
var samDevices map[uint64]samfarm.SamDevice
var samInputChannels map[uint64]chan []byte
var samOutputChannels map[uint64]chan []byte

var urlBroker string
var username string
var password string
var topicNameAsyncInputs string
var topicNameSyncInputs string
var topicNameOutputs string
var keyS string
var clientName string
var isShared bool

func init() {
	flag.StringVar(&urlBroker, "urlBroker", "tcp://127.0.0.1:1883", "MQTT url broker")
	flag.StringVar(&username, "username", "", "MQTT Username broker")
	flag.StringVar(&password, "password", "", "MQTT Password broker")
	flag.StringVar(&topicNameAsyncInputs, "topicNameAsyncInputs", "SAMFARM/ASYN/", "MQTT topic name to cmd requests Async")
	flag.StringVar(&topicNameSyncInputs, "topicNameSyncInputs", "SAMFARM/SYN/", "MQTT topic name to cmd request Sync")
	flag.StringVar(&topicNameOutputs, "topicNameOutputs", "SAMFARM/RESP/", "MQTT topic name to cmd responses")
	flag.StringVar(&keyS, "key", "00000000000000000000000000000000", "key aes128")
	flag.StringVar(&clientName, "clientName", fmt.Sprintf("go-samfarm-client-%v", time.Now().UnixNano()), "Client Name conecction mqtt")
	flag.BoolVar(&isShared, "isShared", false, "is shared subcription? ")

	samDevices = make(map[uint64]samfarm.SamDevice)
	samInputChannels = make(map[uint64]chan []byte)
	samOutputChannels = make(map[uint64]chan []byte)
}

func main() {

	flag.Parse()

	var strTopicName bytes.Buffer
	if isShared {
		strTopicName.WriteString("$share/SAMS01/")
	}
	strTopicName.WriteString(topicNameAsyncInputs)
	strTopicName.WriteString("#")

	errDisconnect := make(chan error)
	var fDisconnect MQTT.ConnectionLostHandler = func(client MQTT.Client, err error) {
		log.Println(err)
		client.Disconnect(100)
		errDisconnect <- err
	}

	fmt.Printf("go-samfarm-client: %s\n", clientName)
	fmt.Printf("go-samfarm-client topic: %s\n", strTopicName.String())
	fmt.Printf("go-samfarm-client url: %s\n", urlBroker)

	uri, err := url.Parse(urlBroker)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf(fmt.Sprintf("%s://%s%s", uri.Scheme, uri.Host, uri.Path))
	/**/
	opts := MQTT.NewClientOptions().AddBroker(fmt.Sprintf("%s://%s%s", uri.Scheme, uri.Host, uri.Path))
	if uri.User != nil {
		opts.SetUsername(uri.User.Username())
		password, _ := uri.User.Password()
		opts.SetPassword(password)
	}
	/**/

	opts.SetClientID(clientName)
	opts.SetDefaultPublishHandler(f)
	opts.SetConnectionLostHandler(fDisconnect)

	var client MQTT.Client
	var ctx *samfarm.Context
	for {
		if client != nil {
			client.Disconnect(300)
		}
		client, err := createClientMQTT(opts, strTopicName.String())
		if err != nil {
			log.Printf("error: %s", err)
			time.Sleep(time.Second * 5)
			continue
		}
		defer client.Disconnect(100)

		if ctx != nil {
			ctx.Release()
		}
		ctx, err := samfarm.NewContext()
		if err != nil {
			log.Println(err)
			break
		}

		verifyCreateSamChannels(ctx)

		timeout := time.NewTicker(time.Second * 10)
		defer timeout.Stop()

		func() {
			for {
				select {
				case <-errDisconnect:
					return
				case <-timeout.C:
					verifyCreateSamChannels(ctx)
				}
			}
		}()
		time.Sleep(time.Second * 5)
	}
}
