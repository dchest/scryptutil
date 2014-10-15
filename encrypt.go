// Copyright 2012 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
)

func makeHeader(p *params, keyHmac []byte) []byte {
	b := bytes.NewBuffer(make([]byte, 0, 96))
	b.WriteString(headerMagic)
	b.WriteByte(headerVersion)
	b.WriteByte(p.logN)
	binary.Write(b, binary.BigEndian, uint32(p.r))
	binary.Write(b, binary.BigEndian, uint32(p.p))
	b.Write(p.salt)

	h := sha256.New()
	h.Write(b.Bytes())
	b.Write(h.Sum(nil)[0:16])

	m := hmac.New(sha256.New, keyHmac)
	m.Write(b.Bytes())
	b.Write(m.Sum(nil))
	return b.Bytes()
}

func encrypt(r io.Reader, w io.Writer, password []byte) error {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	p := &params{
		logN: 18, //TODO(dchest) implement detection of optimal logN.
		r:    8,
		p:    1,
		salt: salt,
	}
	keyEnc, keyHmac, err := deriveKeys(password, p)
	if err != nil {
		return err
	}
	defer func() {
		// Clear key data.
		clearBytes(keyEnc)
		clearBytes(keyHmac)
	}()
	header := makeHeader(p, keyHmac)
	mac := hmac.New(sha256.New, keyHmac)
	mac.Write(header)
	if _, err := w.Write(header); err != nil {
		return err
	}
	block, err := aes.NewCipher(keyEnc)
	if err != nil {
		return err
	}
	sw := cipher.StreamWriter{
		S: cipher.NewCTR(block, make([]byte, aes.BlockSize)),
		W: io.MultiWriter(w, mac),
	}
	if _, err := io.Copy(sw, r); err != nil {
		return err
	}
	if sw.Err != nil {
		return sw.Err
	}
	if _, err := w.Write(mac.Sum(nil)); err != nil {
		return err
	}
	return nil
}
