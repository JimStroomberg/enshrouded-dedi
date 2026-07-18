package a2s

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

// Info is the subset of an A2S_INFO response used by the control plane.
type Info struct {
	Name       string `json:"name"`
	Map        string `json:"map"`
	Players    int    `json:"players"`
	MaxPlayers int    `json:"max_players"`
	Bots       int    `json:"bots"`
	Version    string `json:"version"`
	VAC        bool   `json:"vac"`
}

// Query asks a Source-compatible game server for its public status.
func Query(addr string, timeout time.Duration) (*Info, error) {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	payload := append([]byte{0xFF, 0xFF, 0xFF, 0xFF}, []byte("TSource Engine Query\x00")...)
	buf := make([]byte, 1400)
	readResponse := func(message []byte) ([]byte, error) {
		if _, err := conn.Write(message); err != nil {
			return nil, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 5 {
			return nil, fmt.Errorf("short A2S response")
		}
		return append([]byte(nil), buf[:n]...), nil
	}

	response, err := readResponse(payload)
	if err != nil {
		return nil, err
	}
	if response[4] == 'A' {
		if len(response) < 9 {
			return nil, fmt.Errorf("short A2S challenge")
		}
		challengedPayload := append(append([]byte(nil), payload...), response[5:9]...)
		response, err = readResponse(challengedPayload)
		if err != nil {
			return nil, err
		}
	}
	if response[4] != 'I' {
		return nil, fmt.Errorf("invalid A2S response")
	}

	data := response[5:]
	offset := 0
	if len(data) < 1 {
		return nil, fmt.Errorf("short A2S response")
	}
	offset++ // protocol byte
	name, err := readCString(data, &offset)
	if err != nil {
		return nil, err
	}
	mapName, err := readCString(data, &offset)
	if err != nil {
		return nil, err
	}
	for range 2 { // folder and game strings
		if _, err := readCString(data, &offset); err != nil {
			return nil, err
		}
	}
	if offset+7 > len(data) {
		return nil, fmt.Errorf("short A2S response")
	}
	offset += 2 // app ID
	players := int(data[offset])
	offset++
	maxPlayers := int(data[offset])
	offset++
	bots := int(data[offset])
	offset++
	offset += 3 // server type, environment, visibility
	if offset >= len(data) {
		return nil, fmt.Errorf("short A2S response")
	}
	vac := data[offset] == 1
	offset++
	version := ""
	if offset < len(data) {
		version, _ = readCString(data, &offset)
	}

	return &Info{
		Name:       name,
		Map:        mapName,
		Players:    players,
		MaxPlayers: maxPlayers,
		Bots:       bots,
		Version:    version,
		VAC:        vac,
	}, nil
}

func readCString(data []byte, offset *int) (string, error) {
	if *offset >= len(data) {
		return "", fmt.Errorf("short A2S string")
	}
	index := bytes.IndexByte(data[*offset:], 0)
	if index == -1 {
		return "", fmt.Errorf("unterminated A2S string")
	}
	start := *offset
	*offset += index + 1
	return string(data[start : start+index]), nil
}
