//go:build !darwin && !windows

package desktop

import "errors"

func icnsNative() ([]byte, error) {
	return nil, errors.New("no native icns")
}
