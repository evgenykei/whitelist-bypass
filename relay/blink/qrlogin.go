package blink

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"rsc.io/qr"
)

const (
	loginPollInterval  = 5 * time.Second
	loginDefaultTTL    = 600
	loginRenewFraction = 0.8
	qrQuietZone        = 2
	qrDarkCell         = "\x1b[40m  \x1b[0m"
	qrLightCell        = "\x1b[47m  \x1b[0m"
)

func LoginToFile(path string, client *http.Client, out io.Writer, logFn func(string, ...any)) error {
	tokens, err := LoginWithQR(client, out, logFn)
	if err != nil {
		return err
	}
	if err := SaveTokens(path, tokens); err != nil {
		return fmt.Errorf("save tokens to %s: %w", path, err)
	}
	logFn("[login] approved, tokens saved to %s", path)
	return nil
}

func LoginWithQR(client *http.Client, out io.Writer, logFn func(string, ...any)) (TokenPair, error) {
	for {
		request, err := RequestLogin(client)
		if err != nil {
			return TokenPair{}, err
		}
		link := LoginLink(request.WAT)
		if err := WriteQR(out, link); err != nil {
			return TokenPair{}, err
		}
		fmt.Fprintf(out, "\n  Scan the QR with the Blink app, or open this link on the phone:\n  %s\n\n", link)
		ttl := request.TTL
		if ttl <= 0 {
			ttl = loginDefaultTTL
		}
		renewAt := time.Now().Add(time.Duration(float64(ttl)*loginRenewFraction) * time.Second)
		for time.Now().Before(renewAt) {
			time.Sleep(loginPollInterval)
			tokens, err := PollLogin(client, request.WAT)
			if err == nil {
				return tokens, nil
			}
			if !errors.Is(err, ErrLoginPending) {
				logFn("[login] poll: %v", err)
			}
		}
		logFn("[login] QR expired, requesting a new one")
	}
}

func WriteQR(out io.Writer, text string) error {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	var builder strings.Builder
	for y := -qrQuietZone; y < code.Size+qrQuietZone; y++ {
		for x := -qrQuietZone; x < code.Size+qrQuietZone; x++ {
			if code.Black(x, y) {
				builder.WriteString(qrDarkCell)
			} else {
				builder.WriteString(qrLightCell)
			}
		}
		builder.WriteString("\n")
	}
	_, err = io.WriteString(out, builder.String())
	return err
}
