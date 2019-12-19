package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"time"

	"github.com/dumacp/smartcard/nxp/mifare"

	"github.com/dumacp/smartcard/multiiso"
)

type tagprueba struct {
	uuid uint32
	name string
	doc  uint32
}

var tags = []uint32{
	2444651779,
	2444661075,
	2444660531,
	2444657219,
	2444657843,
	2444647555,
	2444668467,
	2444660371,
	2444648595,
	1766745858,
}

var names = []string{
	"Tarjeta prueba 1",
	"Tarjeta prueba 2",
	"Tarjeta prueba 3",
	"Tarjeta prueba 4",
	"Tarjeta prueba 5",
	"Tarjeta prueba 6",
	"Tarjeta prueba 7",
	"Tarjeta prueba 8",
	"Tarjeta prueba 9",
	"Tarjeta prueba X",
}

var docs = []uint32{
	797853581,
	797853582,
	797853583,
	797853584,
	797853585,
	797853586,
	797853587,
	797853588,
	797853589,
	777777777,
}

func builddata() map[uint32]*tagprueba {

	if len(tags) != len(names) || len(tags) != len(docs) {
		return nil
	}
	cards := make(map[uint32]*tagprueba)
	for i, v := range tags {

		cards[v] = &tagprueba{
			uuid: v,
			name: names[i],
			doc:  docs[i],
		}

	}

	return cards

}

func main() {
	dev, err := multiiso.NewDevice("/dev/ttymxc4", 460800, 300*time.Millisecond)
	if err != nil {
		log.Fatalln(err)
	}

	reader := multiiso.NewMifareClassicReader(dev, "multiiso", 1)

	cards := builddata()
	if cards == nil {
		log.Fatalln("database error!")
	}

	pin0 := []byte("0")
	pin1 := []byte("1")
	for {
		ioutil.WriteFile("/sys/class/leds/picto-go-gren/brightness", pin0, 0644)
		ioutil.WriteFile("/sys/class/leds/picto-stop-red/brightness", pin0, 0644)
		time.Sleep(1 * time.Second)
		fmt.Print("\033c\033[3J")
		card, err := mifare.ConnectMclassic(reader)
		// card, err := reader.ConnectMifareClassic()
		if err != nil {
			log.Printf("\n\n\nERROR CODE: %s", err)

			continue
		}
		uuid, _ := card.UID()

		uuidu := binary.LittleEndian.Uint32(uuid)

		log.Printf("\n\n\n\tUID: [% X], int: %v", uuid, uuidu)

		if _, ok := cards[uuidu]; !ok {

			ioutil.WriteFile("/sys/class/leds/picto-stop-red/brightness", pin1, 0644)
			log.Println("tarjeta no registrada en la base de datos")
			cmd1 := exec.Command("/usr/sbin/omvz7/buzzer", "800", "2")
			if err := cmd1.Run(); err != nil {
				log.Println(err)
			}

			continue

		}

		keyA1, _ := hex.DecodeString("FFFFFFFFFFFF")

		if _, err := card.Auth(8, 0, keyA1); err != nil {

			card2, err := mifare.ConnectMclassic(reader)
			if err != nil {
				log.Println(err)
				continue
			}

			keyA2, _ := hex.DecodeString("665544332211")

			if _, err := card2.Auth(8, 0, keyA2); err != nil {
				log.Printf("Auth error: %v", err)
				continue
			}
			if resp1, err := card2.ReadBlocks(8, 1); err != nil {
				log.Println(err)
				continue
			} else {
				fmt.Printf("bloque 8: %q\n", resp1)
			}
			if resp1, err := card2.ReadBlocks(9, 1); err != nil {
				log.Println(err)
				continue
			} else {
				// fmt.Printf("bloque 9: %q\n", resp1)
				fmt.Printf("bloque 9: %d\n", binary.LittleEndian.Uint32(resp1[0:4]))
			}

			ioutil.WriteFile("/sys/class/leds/picto-go-gren/brightness", pin1, 0644)
			cmd2 := exec.Command("/usr/sbin/omvz7/buzzer", "100", "3")
			if err := cmd2.Run(); err != nil {
				log.Println(err)
			}
			continue
		}

		_, err = card.WriteBlock(8, []byte(cards[uuidu].name)[0:16])
		if err != nil {
			log.Println(err)
			continue
		}
		buff := make([]byte, 16)
		binary.LittleEndian.PutUint64(buff, uint64(cards[uuidu].doc))
		// log.Printf("doc: %d, buffer: [% X]", cards[uuidu].doc, buff)
		_, err = card.WriteBlock(9, buff)
		if err != nil {
			log.Println(err)
			continue
		}

		aclbytes, err := hex.DecodeString("6655443322117F0788FF112233445566")
		// log.Printf("aclBloque: [% X]", aclbytes)
		_, err = card.WriteBlock(11, aclbytes)
		if err != nil {
			log.Println(err)
			continue
		}

		ioutil.WriteFile("/sys/class/leds/picto-go-gren/brightness", pin1, 0644)
		cmd3 := exec.Command("/usr/sbin/omvz7/buzzer", "100", "5")
		if err := cmd3.Run(); err != nil {
			log.Println(err)
		}
		fmt.Printf("\t\t\tOK\n")
		time.Sleep(5 * time.Second)
	}
}
