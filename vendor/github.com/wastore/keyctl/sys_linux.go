package keyctl

import (
	"log"
	"syscall"
	"unsafe"
)

type keyctlCommand int

type keyId int32

const (
	keySpecThreadKeyring      keyId = -1
	keySpecProcessKeyring     keyId = -2
	keySpecSessionKeyring     keyId = -3
	keySpecUserKeyring        keyId = -4
	keySpecUserSessionKeyring keyId = -5
	keySpecGroupKeyring       keyId = -6
	keySpecReqKeyAuthKey      keyId = -7
)

const (
	keyctlGetKeyringId keyctlCommand = iota
	keyctlJoinSessionKeyring
	keyctlUpdate
	keyctlRevoke
	keyctlChown
	keyctlSetPerm
	keyctlDescribe
	keyctlClear
	keyctlLink
	keyctlUnlink
	keyctlSearch
	keyctlRead
	keyctlInstantiate
	keyctlNegate
	keyctlSetReqKeyKeyring
	keyctlSetTimeout
	keyctlAssumeAuthority
)

var debugSyscalls bool

func (id keyId) Id() int32 {
	return int32(id)
}

func (cmd keyctlCommand) String() string {
	switch cmd {
	case keyctlGetKeyringId:
		return "keyctlGetKeyringId"
	case keyctlJoinSessionKeyring:
		return "keyctlJoinSessionKeyring"
	case keyctlUpdate:
		return "keyctlUpdate"
	case keyctlRevoke:
		return "keyctlRevoke"
	case keyctlChown:
		return "keyctlChown"
	case keyctlSetPerm:
		return "keyctlSetPerm"
	case keyctlDescribe:
		return "keyctlDescribe"
	case keyctlClear:
		return "keyctlClear"
	case keyctlLink:
		return "keyctlLink"
	case keyctlUnlink:
		return "keyctlUnlink"
	case keyctlSearch:
		return "keyctlSearch"
	case keyctlRead:
		return "keyctlRead"
	case keyctlInstantiate:
		return "keyctlInstantiate"
	case keyctlNegate:
		return "keyctlNegate"
	case keyctlSetReqKeyKeyring:
		return "keyctlSetReqKeyKeyring"
	case keyctlSetTimeout:
		return "keyctlSetTimeout"
	case keyctlAssumeAuthority:
		return "keyctlAssumeAuthority"
	}
	panic("bad arg")
}

// keyctl is a general-purpose kyctl wrapper for calls that need on unsafe.Pointers.
// Don't cast UnsafePointers and pass them in here. Use keyctlOnePtr and keyctlTwoPtr for cases with unsafe.Pointer args.
// This is to avoid the risks of converting unsafe.Pointer to unitptr before the actual sys call (as would be
// necessary if using only this routine). The risks are as follows (the first is the most likely to affect this code):
// (a) pointer is to stack-allocated object, and runtime has to grow the stack (moving everything on it, and invalidating any unintptrs into it)
// (b) pointer is to something with no remaining references, so it gets GC'd before use
// (c) theoretical possibility of a moving GC (for heap objects) in the future. Unlikely, but is one reason why converting to unitptr "early" is not supported
// References:
//      https://golang.org/pkg/unsafe/#Pointer
// 		https://stackoverflow.com/a/22209698
//      https://grokbase.com/t/gg/golang-nuts/157f2q8g9x/go-nuts-possible-misuse-of-unsafe-pointer
//		(out of date? but informative) https://grokbase.com/t/gg/golang-nuts/147qqaky1h/go-nuts-uintptr-to-go-object-unsafe-to-pass-to-any-function-including-syscalls-c-functions
func keyctl(cmd keyctlCommand, args ...uintptr) (r1 int32, r2 int32, err error) {
	a := make([]uintptr, 6)
	l := len(args)
	if l > 5 {
		l = 5
	}
	a[0] = uintptr(cmd)
	for idx, v := range args[:l] {
		a[idx+1] = v
	}
	if debugSyscalls {
		log.Printf("%v: %v %v\n", syscall_keyctl, cmd, a[1:])
	}
	v1, v2, errno := syscall.Syscall6(syscall_keyctl, a[0], a[1], a[2], a[3], a[4], a[5])
	if errno != 0 {
		err = errno
		return
	}

	r1 = int32(v1)
	r2 = int32(v2)
	return
}

// see comments on keyctl
func keyctlOnePtr(cmd keyctlCommand, id uintptr, ptr unsafe.Pointer, extra uintptr) (r1 int32, r2 int32, err error) {
	if debugSyscalls {
		log.Printf("%v: %v %v %v %v\n", syscall_keyctl, id, cmd, ptr, extra)
	}
	v1, v2, errno := syscall.Syscall6(syscall_keyctl, uintptr(cmd), id, uintptr(ptr), extra, 0, 0)
	if errno != 0 {
		err = errno
		return
	}

	r1 = int32(v1)
	r2 = int32(v2)
	return
}

// see comments on keyctl
func keyctlTwoPtr(cmd keyctlCommand, id uintptr, ptr1, ptr2 unsafe.Pointer) (r1 int32, r2 int32, err error) {
	if debugSyscalls {
		log.Printf("%v: %v %v %v %v\n", syscall_keyctl, id, cmd, ptr1, ptr2)
	}
	v1, v2, errno := syscall.Syscall6(syscall_keyctl, uintptr(cmd), id, uintptr(ptr1), uintptr(ptr2), 0, 0)
	if errno != 0 {
		err = errno
		return
	}

	r1 = int32(v1)
	r2 = int32(v2)
	return
}


func add_key(keyType, keyDesc string, payload []byte, id int32) (int32, error) {
	var (
		err    error
		errno  syscall.Errno
		b1, b2 *byte
		r1     uintptr
		pptr   unsafe.Pointer
	)

	if b1, err = syscall.BytePtrFromString(keyType); err != nil {
		return 0, err
	}

	if b2, err = syscall.BytePtrFromString(keyDesc); err != nil {
		return 0, err
	}

	if len(payload) > 0 {
		pptr = unsafe.Pointer(&payload[0])
	}
	r1, _, errno = syscall.Syscall6(syscall_add_key,
		uintptr(unsafe.Pointer(b1)),
		uintptr(unsafe.Pointer(b2)),
		uintptr(pptr),
		uintptr(len(payload)),
		uintptr(id),
		0)

	if errno != 0 {
		err = errno
		return 0, err
	}
	return int32(r1), nil
}

func newKeyring(id keyId) (*keyring, error) {
	r1, _, err := keyctl(keyctlGetKeyringId, uintptr(id), uintptr(1))
	if err != nil {
		return nil, err
	}

	if id < 0 {
		r1 = int32(id)
	}
	return &keyring{id: keyId(r1)}, nil
}

func searchKeyring(id keyId, name, keyType string) (keyId, error) {
	var (
		r1     int32
		b1, b2 *byte
		err    error
	)

	if b1, err = syscall.BytePtrFromString(keyType); err != nil {
		return 0, err
	}
	if b2, err = syscall.BytePtrFromString(name); err != nil {
		return 0, err
	}

	r1, _, err = keyctlTwoPtr(keyctlSearch, uintptr(id), unsafe.Pointer(b1), unsafe.Pointer(b2))
	return keyId(r1), err
}

func updateKey(id keyId, payload []byte) error {
	size := len(payload)
	if size == 0 {
		payload = make([]byte, 1)
	}
	_, _, err := keyctlOnePtr(keyctlUpdate, uintptr(id), unsafe.Pointer(&payload[0]), uintptr(size))
	return err
}
