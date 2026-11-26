package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var b bytes.Buffer
	in := Request{Type: Vote, ID: 7, Text: "no\n", Data: []byte{0, 1, 0xff}}
	if err := Write(&b, in); err != nil {
		t.Fatal(err)
	}
	var out Request
	if err := Read(&b, MaxRequest, &out); err != nil || out.Type != in.Type || out.ID != 7 || out.Text != in.Text || !bytes.Equal(out.Data, in.Data) {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestTooLarge(t *testing.T) {
	// The length is checked before anything is allocated or read.
	h := binary.BigEndian.AppendUint32(nil, 4097)
	var q Request
	if err := Read(bytes.NewReader(h), 4096, &q); err != errSize {
		t.Fatal(err)
	}
}

// FuzzRead feeds the decoder what a peer might send. It must not panic, and
// what it accepts must survive being sent again.
func FuzzRead(f *testing.F) {
	for _, s := range []string{`{"Type":"key","Data":"AAE="}`, `{"Type":"vote","ID":1,"Text":"x"}`, `{"Rows":65535,"Cols":0}`, `[]`, `{"Size":-1}`, `{"Data":null}`} {
		f.Add(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s)
	}
	f.Fuzz(func(t *testing.T, head []byte, body string) {
		in := append(append([]byte{}, head...), body...)
		var q Request
		if Read(bytes.NewReader(in), 4096, &q) != nil {
			return
		}
		var b bytes.Buffer
		if err := Write(&b, q); err != nil {
			t.Fatal(err)
		}
		var again Request
		if err := Read(&b, MaxReply, &again); err != nil {
			t.Fatal(err)
		}
	})
}
