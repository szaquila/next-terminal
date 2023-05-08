package common

import (
	"time"

	"github.com/pquerna/otp"
	otp_t "github.com/pquerna/otp"
	totp_t "github.com/pquerna/otp/totp"
)

type GenerateOpts totp_t.GenerateOpts

func NewTOTP(opt GenerateOpts) (*otp_t.Key, error) {
	return totp_t.Generate(totp_t.GenerateOpts(opt))
}

func Validate(code string, secret string) bool {
	if secret == "" {
		return true
	}
	rv, _ := totp_t.ValidateCustom(code, secret, time.Now(), totp_t.ValidateOpts{
		Period:    180,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return rv
}
