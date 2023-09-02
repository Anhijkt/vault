package tkey 

import (
	"fmt"

	"github.com/tillitis/tkeyclient"
)

var (
	cmdGetNameVersion = appCmd{0x01, "cmdGetNameVersion", tkeyclient.CmdLen1}
	rspGetNameVersion = appCmd{0x02, "rspGetNameVersion", tkeyclient.CmdLen32}
	cmdPutSecret	  = appCmd{0x03, "cmdPutSecret", tkeyclient.CmdLen128}
	rspPutSecret	  = appCmd{0x04, "rspPutSecret", tkeyclient.CmdLen4}
	cmdSendShare	  = appCmd{0x05, "cmdSendShare", tkeyclient.CmdLen4}
	rspSendShare	  = appCmd{0x06, "rspSendShare", tkeyclient.CmdLen128}
	cmdRecieveShare   = appCmd{0x07, "cmdRecieveShare", tkeyclient.CmdLen128}
	rspRecieveShare   = appCmd{0x08, "rspRecieveShare", tkeyclient.CmdLen4}
	cmdSendKey		  = appCmd{0x09, "cmdSendKey", tkeyclient.CmdLen4}
	rspSendKey		  = appCmd{0x0a, "rspSendKey", tkeyclient.CmdLen128}
	cmdSendPubKey	  = appCmd{0x0b, "cmdSendPubKey", tkeyclient.CmdLen1}
	rspSendPubKey	  = appCmd{0x0c, "rspSendPubKey", tkeyclient.CmdLen128}
	cmdRecievePubKey  = appCmd{0x0d, "cmdRecievePubKey", tkeyclient.CmdLen128}
	rspRecievePubKey  = appCmd{0x0e, "rspRecievePubKey", tkeyclient.CmdLen1}
)

type Tkey struct {
	tk *tkeyclient.TillitisKey
}

type appCmd struct {
	code   byte
	name   string
	cmdLen tkeyclient.CmdLen
}

func (c appCmd) Code() byte {
	return c.code
}

func (c appCmd) CmdLen() tkeyclient.CmdLen {
	return c.cmdLen
}

func (c appCmd) Endpoint() tkeyclient.Endpoint {
	return tkeyclient.DestApp
}

func (c appCmd) String() string {
	return c.name
}

func New(tk *tkeyclient.TillitisKey) Tkey {
	var tkey Tkey

	tkey.tk = tk

	return tkey
}

func (t Tkey) Close() error {
	if err := t.tk.Close(); err != nil {
		return fmt.Errorf("tk.Close: %w", err)
	}
	return nil
}

func (t Tkey) PutPubKey(pubKey []byte) error {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdRecievePubKey, id)
	if err != nil {
		return fmt.Errorf("NewFrameBuf: %w", err)
	}

	payload := make([]byte, cmdRecievePubKey.CmdLen().Bytelen()-1)
	copied := copy(payload, pubKey)

	// Add padding if not filling the payload buffer.
	if copied < len(payload) {
		padding := make([]byte, len(payload)-copied)
		copy(payload[copied:], padding)
	}

	copy(tx[2:], payload)

	tkeyclient.Dump("PutPubKey tx", tx)
	if err = t.tk.Write(tx); err != nil {
		return fmt.Errorf("Write: %w", err)
	}

	// Wait for reply
	rx, _, err := t.tk.ReadFrame(rspRecievePubKey, id)
	tkeyclient.Dump("rx", rx)
	if err != nil {
		return fmt.Errorf("ReadFrame: %w", err)
	}
	return nil

}

func (t Tkey) GetPubKey() ([]byte, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdSendPubKey, id)
	if err != nil {
		return nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	tkeyclient.Dump("GetPubkey tx", tx)
	if err = t.tk.Write(tx); err != nil {
		return nil, fmt.Errorf("Write: %w", err)
	}

	rx, _, err := t.tk.ReadFrame(rspSendPubKey, id)
	tkeyclient.Dump("GetPubKey rx", rx)
	if err != nil {
		return nil, fmt.Errorf("ReadFrame: %w", err)
	}

	return rx[2 : 2+32], nil
}

func (t Tkey) Combine(parts [][]byte) ([]byte, error) {
	var k int

	if len(parts) < 2 {
		return nil, fmt.Errorf("less than two parts cannot be used to reconstruct the secret")
	}

	// Verify the parts are all the same length
	firstPartLen := len(parts[0])
	if firstPartLen < 2 {
		return nil, fmt.Errorf("parts must be at least two bytes")
	}

	for i := 1; i < len(parts); i++ {
		if len(parts[i]) != firstPartLen {
			return nil, fmt.Errorf("all parts must be the same length")
		}
	}

	for k = 0; k < len(parts); k++ {
		err := t.PutShare(k, parts[k])
		if err != nil {
			return nil, fmt.Errorf("unable to put share on tkey: %w", err)
		}
	}

	restoredKey, err := t.GetSecret(k)
	if err != nil {
		return nil, fmt.Errorf("unable to get secret from tkey: %w", err)
	}

	return restoredKey, nil
}

func (t Tkey) Split(secret []byte, parts, threshold int) ([][]byte, error) {
	// Sanity check the input
	if parts < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, fmt.Errorf("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, fmt.Errorf("threshold cannot exceed 255")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("cannot split an empty secret")
	}

	err := t.PutSecret(parts, threshold, secret)
	if err != nil {
		return nil, fmt.Errorf("could not put secret: %w", err)
	}

	out := make([][]byte, parts)
	for i := 0; i < parts; i++ {
		out[i], err = t.GetShare(i)
		if err != nil {
			return nil, fmt.Errorf("could not get share: %w", err)
		}
	}

	return out, nil
}

func (t Tkey) PutSecret(n_shares, k_shares int, secret []byte) error {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdPutSecret, id)
	if err != nil {
		return fmt.Errorf("NewFrameBuf: %w", err)
	}

	payload := make([]byte, cmdPutSecret.CmdLen().Bytelen()-1)
	copied := copy(payload, secret)

	// Add padding if not filling the payload buffer.
	if copied < len(payload) {
		padding := make([]byte, len(payload)-copied)
		copy(payload[copied:], padding)
	}

	tx[2] = byte(n_shares)
	tx[3] = byte(k_shares)

	copy(tx[4:], payload)

	tkeyclient.Dump("PutSecret tx", tx)
	if err = t.tk.Write(tx); err != nil {
		return fmt.Errorf("Write: %w", err)
	}

	// Wait for reply
	rx, _, err := t.tk.ReadFrame(rspPutSecret, id)
	tkeyclient.Dump("rx", rx)
	if err != nil {
		return fmt.Errorf("ReadFrame: %w", err)
	}

	if rx[2] != tkeyclient.StatusOK {
		return fmt.Errorf("PutSecret NOK")
	}
	return nil
}

func (t Tkey) GetSecret(k_shares int) ([]byte, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdSendKey, id)
	if err != nil {
		return nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	tx[2] = byte(k_shares) //number of k_shares

	tkeyclient.Dump("GetSecret tx", tx)
	if err = t.tk.Write(tx); err != nil {
		return nil, fmt.Errorf("Write: %w", err)
	}

	rx, _, err := t.tk.ReadFrame(rspSendKey, id)
	tkeyclient.Dump("GetSecret rx", rx)
	if err != nil {
		return nil, fmt.Errorf("ReadFrame: %w", err)
	}
	if rx[2] != tkeyclient.StatusOK {
		return nil, fmt.Errorf("rspSendKey NOK")
	}

	return rx[3: 3+32], nil
}

func (t Tkey) GetShare(n_share int) ([]byte, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdSendShare, id)
	if err != nil {
		return nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	tx[2] = byte(n_share) //number of share

	tkeyclient.Dump("GetShare tx", tx)
	if err = t.tk.Write(tx); err != nil {
		return nil, fmt.Errorf("Write: %w", err)
	}

	rx, _, err := t.tk.ReadFrame(rspSendShare, id)
	tkeyclient.Dump("GetPubGetShareKey rx", rx)
	if err != nil {
		return nil, fmt.Errorf("ReadFrame: %w", err)
	}
	if rx[2] != tkeyclient.StatusOK {
		return nil, fmt.Errorf("rspSendShare NOK")
	}

	return rx[3: 3+33], nil
}

func (t Tkey) PutShare(n_share int, share []byte) (error) {
	id := 2 
	tx, err := tkeyclient.NewFrameBuf(cmdRecieveShare, id)
	if err != nil {
		return fmt.Errorf("NewFrameBuf: %w", err)
	}

	payload := make([]byte, cmdRecieveShare.CmdLen().Bytelen()-1)
	copied := copy(payload, share)

	// Add padding if not filling the payload buffer.
	if copied < len(payload) {
		padding := make([]byte, len(payload)-copied)
		copy(payload[copied:], padding)
	}

	tx[2] = byte(n_share)
	copy(tx[3:], payload)

	tkeyclient.Dump("PutShare tx", tx)
	if err = t.tk.Write(tx); err != nil {
		return fmt.Errorf("Write: %w", err)
	}

	// Wait for reply
	rx, _, err := t.tk.ReadFrame(rspRecieveShare, id)
	tkeyclient.Dump("rx", rx)
	if err != nil {
		return fmt.Errorf("ReadFrame: %w", err)
	}
	if rx[2] != tkeyclient.StatusOK {
		return fmt.Errorf("rspRecieveShare NOK")
	}
	return nil
}


func (t Tkey) GetAppNameVersion() (*tkeyclient.NameVersion, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdGetNameVersion, id)
	if err != nil {
		return nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	tkeyclient.Dump("GetAppNameVersion tx", tx)
	if err = t.tk.Write(tx); err != nil {
		return nil, fmt.Errorf("Write: %w", err)
	}

	err = t.tk.SetReadTimeout(2)
	if err != nil {
		return nil, fmt.Errorf("SetReadTimeout: %w", err)
	}

	rx, _, err := t.tk.ReadFrame(rspGetNameVersion, id)
	if err != nil {
		return nil, fmt.Errorf("ReadFrame: %w", err)
	}

	err = t.tk.SetReadTimeout(0)
	if err != nil {
		return nil, fmt.Errorf("SetReadTimeout: %w", err)
	}

	nameVer := &tkeyclient.NameVersion{}
	nameVer.Unpack(rx[2:])

	return nameVer, nil
}