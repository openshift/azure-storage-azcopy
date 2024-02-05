// Copyright 2015 Jesse Sipprell. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

// A Go interface to linux kernel keyrings (keyctl interface)
package keyctl

// All Keys and Keyrings have unique 32-bit serial number identifiers.
type Id interface {
	Id() int32

	private()
}

// Basic interface to a linux keyctl keyring.
type Keyring interface {
	Id
	Add(string, []byte) (*Key, error)
	Search(string) (*Key, error)
}

// Named keyrings are user-created keyrings linked to a parent keyring. The
// parent can be either named or one of the in-built keyrings (session, group
// etc). The in-built keyrings have no parents. Keyring searching is performed
// hierarchically.
type NamedKeyring interface {
	Keyring
	Name() string
}

type keyring struct {
	id keyId
}

func (kr *keyring) private() {}

// Returns the 32-bit kernel identifier of a keyring
func (kr *keyring) Id() int32 {
	return int32(kr.id)
}

// Add a new key to a keyring. The key can be searched for later by name.
func (kr *keyring) Add(name string, key []byte) (*Key, error) {
	r, err := add_key("user", name, key, int32(kr.id))
	if err == nil {
		key := &Key{Name: name, id: keyId(r), ring: kr.id}
		return key, err
	}

	return nil, err
}

// Search for a key by name, this also searches child keyrings linked to this
// one. The key, if found, is linked to the top keyring that Search() was called
// from.
func (kr *keyring) Search(name string) (*Key, error) {
	id, err := searchKeyring(kr.id, name, "user")
	if err == nil {
		return &Key{Name: name, id: id, ring: kr.id}, nil
	}
	return nil, err
}

// Return the current login session keyring
func SessionKeyring() (Keyring, error) {
	return newKeyring(keySpecSessionKeyring)
}

// Unlink an object from a keyring
func Unlink(parent Keyring, child Id) error {
	_, _, err := keyctl(keyctlUnlink, uintptr(parent.Id()), uintptr(child.Id()))
	return err
}
