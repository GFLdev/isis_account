package utils

import (
	"net"

	"github.com/go-playground/validator/v10"
)

// ValidateIPWithLocalHost is a custom validation for IP addresses, either IPV4
// and IPV6, including localhost (127.0.0.1 and ::1).
func ValidateIPWithLocalHost(fl validator.FieldLevel) bool {
	ip, ok := fl.Field().Interface().(net.IP)
	if !ok || ip == nil || ip.IsUnspecified() {
		return false
	}
	return ip.To4() != nil || ip.To16() != nil // includes "::1"
}
