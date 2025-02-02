package handshake

import (
	"fmt"
	"io"
)

type Handshake struct {
	Pstr     string
	InfoHash [20]byte
	PeerID   [20]byte
}

func NewHandShake(infoHash, peerID [20]byte) *Handshake {
	return &Handshake{
		Pstr:     "BitTorrent protocol",
		InfoHash: infoHash,
		PeerID:   peerID,
	}
}

func (h *Handshake) Serialize() []byte {
	buf := make([]byte, 1+len(h.Pstr)+8+20+20) // 1 (length byte) + len(h.Pstr) + 8 (reserved bytes) + 20 (infohash) + 20 (peer ID)
	buf[0] = byte(len(h.Pstr))
	idx := 1
	idx += copy(buf[idx:], h.Pstr)
	idx += copy(buf[idx:], make([]byte, 8)) // 8 reserved bytes
	idx += copy(buf[idx:], h.InfoHash[:])
	idx += copy(buf[idx:], h.PeerID[:])
	return buf
}

func Deserialize(r io.Reader) (*Handshake, error) {
	lengthBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, lengthBuf); err != nil {
		return nil, err
	}
	pstrLen := int(lengthBuf[0])
	if pstrLen == 0 {
		return nil, fmt.Errorf("pstr length can not be 0")
	}
	handshakeBuf := make([]byte, 48+pstrLen)
	if _, err := io.ReadFull(r, handshakeBuf); err != nil {
		return nil, err
	}

	var infoHash, peerID [20]byte

	copy(infoHash[:], handshakeBuf[pstrLen+8:pstrLen+8+20])
	copy(peerID[:], handshakeBuf[pstrLen+8+20:])

	h := Handshake{
		Pstr:     string(handshakeBuf[0:pstrLen]),
		InfoHash: infoHash,
		PeerID:   peerID,
	}

	return &h, nil
}
