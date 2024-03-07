package commons

import (
	"strings"
)

// StringInSlice ...
func StringInSlice(a string, list []string, ignore bool) bool {
	for _, b := range list {
		if b == a && !ignore {
			return true
		}
		if ignore && strings.EqualFold(b, a) {
			return true
		}
	}
	return false
}

// StringContainsInSlice ...
func StringContainsInSlice(a string, list []string, ignore bool) bool {
	for _, b := range list {
		if strings.Contains(a, b) && !ignore {
			return true
		}
		if ignore && strings.Contains(strings.ToLower(a), strings.ToLower(b)) {
			return true
		}
	}
	return false
}
