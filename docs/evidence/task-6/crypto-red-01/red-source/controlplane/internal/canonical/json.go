// Package canonical defines Warden JSON v1: UTF-8 JSON, unique object keys,
// lexicographically sorted keys, Go encoding/json string escaping, no whitespace.
// Numbers preserve their valid JSON token spelling (1 and 1.0 are distinct).
// This is deliberately not RFC 8785. Arrays preserve order; nesting is <=64.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

func JSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON must be UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := read(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return json.Marshal(value)
}
func read(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("JSON nesting exceeds 64")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		obj := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			s, ok := key.(string)
			if !ok {
				return nil, errors.New("object key must be string")
			}
			if _, exists := obj[s]; exists {
				return nil, fmt.Errorf("duplicate JSON key %q", s)
			}
			obj[s], err = read(d, depth+1)
			if err != nil {
				return nil, err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid object")
		}
		return obj, nil
	case json.Delim('['):
		arr := []any{}
		for d.More() {
			v, err := read(d, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid array")
		}
		return arr, nil
	default:
		if _, ok := token.(json.Delim); ok {
			return nil, errors.New("unexpected JSON delimiter")
		}
		return token, nil
	}
}
