package merkle

// Value represents a OTS sk and pk
type Value struct {
	sk []byte
	pk []byte
}

func (v Value) GetSk() []byte {
	tmp := make([]byte, len(v.sk))
	copy(tmp, v.sk)
	return tmp
}

func (v Value) GetPk() []byte {
	tmp := make([]byte, len(v.pk))
	copy(tmp, v.pk)
	return tmp
}
