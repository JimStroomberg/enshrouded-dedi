package a2s

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestQueryHandlesChallengeAndParsesInfo(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1400)
		_, peer, err := listener.ReadFrom(buf)
		if err != nil {
			serverErr <- err
			return
		}
		challenge := []byte{1, 2, 3, 4}
		if _, err := listener.WriteTo(append([]byte{0xff, 0xff, 0xff, 0xff, 'A'}, challenge...), peer); err != nil {
			serverErr <- err
			return
		}
		n, peer, err := listener.ReadFrom(buf)
		if err != nil {
			serverErr <- err
			return
		}
		if n < len(challenge) || !bytes.Equal(buf[n-len(challenge):n], challenge) {
			serverErr <- &testError{"challenge was not echoed"}
			return
		}
		if _, err := listener.WriteTo(testInfoResponse(), peer); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	info, err := Query(listener.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if info.Name != "Goodfellas" || info.Map != "Embervale" || info.Players != 3 || info.MaxPlayers != 16 || info.Version != "1.2.3" {
		t.Fatalf("unexpected info: %#v", info)
	}
}

func testInfoResponse() []byte {
	var out bytes.Buffer
	out.Write([]byte{0xff, 0xff, 0xff, 0xff, 'I', 17})
	for _, value := range []string{"Goodfellas", "Embervale", "enshrouded", "Enshrouded"} {
		out.WriteString(value)
		out.WriteByte(0)
	}
	_ = binary.Write(&out, binary.LittleEndian, uint16(2278520%65536))
	out.Write([]byte{3, 16, 0, 'd', 'l', 0, 1})
	out.WriteString("1.2.3")
	out.WriteByte(0)
	return out.Bytes()
}

type testError struct{ message string }

func (e *testError) Error() string { return e.message }
