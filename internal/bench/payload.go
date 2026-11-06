package bench

import "io"

func fillPayload(b []byte, offset int64) {
	for i := range b {
		b[i] = byte(((offset+int64(i))%251*31 + 17) % 251)
	}
}

func validPayload(b []byte, offset int64) bool {
	for i, v := range b {
		if v != byte(((offset+int64(i))%251*31+17)%251) {
			return false
		}
	}
	return true
}

type payloadReader struct {
	left   int64
	offset int64
}

func (r *payloadReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	fillPayload(p, r.offset)
	r.offset += int64(len(p))
	r.left -= int64(len(p))
	return len(p), nil
}
