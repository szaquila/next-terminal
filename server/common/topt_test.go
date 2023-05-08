package common

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"image/png"
	"os"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func display(key *otp.Key, data []byte) {
	fmt.Printf("Issuer:       %s\n", key.Issuer())
	fmt.Printf("Account Name: %s\n", key.AccountName())
	fmt.Printf("Secret:       %s\n", key.Secret())
	fmt.Println("Writing PNG to qr-code.png....")
	// ioutil.WriteFile("qr-code.png", data, 0644)
	fmt.Println("")
	fmt.Println("Please add your TOTP to your OTP Application now!")
	fmt.Println("")
}

func promptForPasscode() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Passcode: ")
	text, _ := reader.ReadString('\n')
	return text
}

// Demo function, not used in main
// Generates Passcode using a UTF-8 (not base32) secret and custom parameters
func GenerateCodeCustom(secret string) string {
	// secret := base32.StdEncoding.EncodeToString([]byte(utf8string))
	passcode, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    180,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		panic(err)
	}
	return passcode
}

func Test_Totp(t *testing.T) {
	// utf8string := "3VRKNWL4YUN446766B4CXUUUCRTAGOUI"
	hexStr := "dd62a6d97cc51bce7bfef0782bd2941466033a88"
	keyStr, err := hex.DecodeString(hexStr)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "yjidc.com",
		AccountName: "admin@yjidc.com",
		Period:      180,
		// SecretSize:  40,
		Secret:    keyStr,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		panic(err)
	}

	passcode := GenerateCodeCustom(key.Secret())

	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)

	// display the QR code to the user.
	display(key, buf.Bytes())

	// Now Validate that the user's successfully added the passcode.
	fmt.Println("Validating TOTP...", passcode, len(passcode), key.URL())
	// passcode := promptForPasscode()
	valid, err := totp.ValidateCustom(passcode, key.Secret(), time.Now(), totp.ValidateOpts{
		Period:    180,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		panic(err)
	}
	if valid {
		println("Valid passcode!")
		// os.Exit(0)
	} else {
		println("Invalid passcode!")
		os.Exit(1)
	}
}
