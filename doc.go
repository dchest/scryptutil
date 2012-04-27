// Copyright 2012 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*

scryptutil encrypts and decrypts files.

Files are encrypted with AES-256 in CTR mode and authenticated with HMAC-SHA256.
Encryption and HMAC keys are derived from passphrase using scrypt key derivation
function.

Usage:
    scryptutil {enc | dec} infile [outfile]

If outfile is not given, the program writes to the standard output.

scryptutil is a Go reimplementation of Colin Percival's scrypt utility, which is
used to encrypt key files for his Tarsnap backup service (see
http://www.tarsnap.com/scrypt.html). The file format is the same: files
encrypted by this utility can be decrypted with the original scrypt, and vice
versa.

*/
package main

//BUG(dchest): Parameters for KDF during encryption are hardcoded to N=2¹⁵, r=8, p=1.

//BUG(dchest): Passwords are echoed to terminal when entering them.

//BUG(dchest): None of the original scrypt utility flags are supported.
