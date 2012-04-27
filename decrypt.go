// Copyright 2012 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

func parseHeader(header []byte) (p *params, err error) {
	p = new(params)
	p.logN = header[7]
	if p.logN < 1 || p.logN > 31 {
		return nil, fmt.Errorf("N parameter is too large: %d", p.logN)
	}
	r := binary.BigEndian.Uint32(header[8:12])
	if r > math.MaxInt32 {
		return nil, fmt.Errorf("r parameter is too large: %d", r)
	}
	p.r = int(r)
	_p := binary.BigEndian.Uint32(header[12:16])
	if _p > math.MaxInt32 {
		return nil, fmt.Errorf("p parameter is too large: %d", _p)
	}
	p.p = int(_p)
	p.salt = header[16:48]

	// Verify hash.
	hash := header[48:64]
	h := sha256.New()
	h.Write(header[0:48])
	if !bytes.Equal(hash, h.Sum(nil)[:16]) {
		return nil, errors.New("header corrupted")
	}
	return
}

func verifyHeader(header []byte, keyHmac []byte) error {
	mac := header[64:96]
	m := hmac.New(sha256.New, keyHmac)
	m.Write(header[0:64])
	if !bytes.Equal(mac, m.Sum(nil)) {
		return errors.New("wrong passphrase")
	}
	return nil
}

func decrypt(r io.Reader, w io.Writer, password []byte) error {
	// Read first 7 bytes of header.
	header := make([]byte, 96)
	if _, err := io.ReadFull(r, header[0:7]); err != nil {
		return err
	}
	// Check magic and version.
	if string(header[0:6]) != headerMagic {
		return errors.New("not an scrypt file")
	}
	if header[6] != headerVersion {
		return errors.New("unsupported scrypt version")
	}
	// Read the rest of the header.
	if _, err := io.ReadFull(r, header[7:]); err != nil {
		return err
	}

	p, err := parseHeader(header)
	if err != nil {
		return err
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
	if err := verifyHeader(header, keyHmac); err != nil {
		return err
	}
	// Initialize HMAC. It starts with header.
	mac := hmac.New(sha256.New, keyHmac)
	mac.Write(header)
	// Initialize cipher.
	block, err := aes.NewCipher(keyEnc)
	if err != nil {
		return err
	}
	enc := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	// Decrypt.
	buf := make([]byte, 65535+32)
	buflen := 0
	for {
		n, err := r.Read(buf[buflen:])
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		buflen += int(n)
		if buflen <= 32 {
			continue
		}
		// Hash and decrypt everything except the last 32 bytes.
		mac.Write(buf[:buflen-32])
		enc.XORKeyStream(buf, buf[:buflen-32])
		_, err = w.Write(buf[:buflen-32])
		if err != nil {
			return err
		}
		// Copy last 32 bytes to the beginning of the buffer.
		copy(buf, buf[buflen-32:])
		buflen = 32
	}
	// Verify.
	if buflen < 32 || !bytes.Equal(mac.Sum(nil), buf[0:32]) {
		return errors.New("can't verify data")
	}
	return nil
}
