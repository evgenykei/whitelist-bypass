package blink

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"whitelist-bypass/relay/common"
)

const (
	AccessTokenEntry          = "blink_access_token"
	AccessTokenExpiresAtEntry = "blink_access_token_expires_at"
	RefreshTokenEntry         = "blink_refresh_token"

	accessTokenRefreshMargin = time.Hour
)

type Credentials struct {
	path   string
	client *http.Client
	logFn  func(string, ...any)
	tokens TokenPair
}

func LoadCredentials(path string, client *http.Client, logFn func(string, ...any)) (*Credentials, error) {
	tokens, err := readTokens(path)
	if err != nil {
		return nil, err
	}
	if tokens.RefreshToken == "" {
		return nil, fmt.Errorf("%s has no %s, run with --login first", path, RefreshTokenEntry)
	}
	return &Credentials{path: path, client: client, logFn: logFn, tokens: tokens}, nil
}

func SaveTokens(path string, tokens TokenPair) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
			return err
		}
	}
	return common.UpdateCookieFile(path, map[string]string{
		AccessTokenEntry:          tokens.Token,
		AccessTokenExpiresAtEntry: strconv.FormatInt(tokens.TokenExpiresAt, 10),
		RefreshTokenEntry:         tokens.RefreshToken,
	})
}

func (c *Credentials) AccessToken() (string, error) {
	if accessTokenFresh(c.tokens) {
		return c.tokens.Token, nil
	}
	if err := c.refresh(); err != nil {
		return "", err
	}
	return c.tokens.Token, nil
}

func (c *Credentials) ConnectCall(chatID int64) (CallConnection, error) {
	accessToken, err := c.AccessToken()
	if err != nil {
		return CallConnection{}, err
	}
	connection, err := ConnectCall(c.client, accessToken, chatID)
	if !IsUnauthorized(err) {
		return connection, err
	}
	c.logFn("[auth] calls connect returned 401, refreshing tokens")
	if err := c.refresh(); err != nil {
		return CallConnection{}, err
	}
	return ConnectCall(c.client, c.tokens.Token, chatID)
}

func (c *Credentials) refresh() error {
	staleRefreshToken := c.tokens.RefreshToken
	stored, err := readTokens(c.path)
	if err != nil {
		c.logFn("[auth] could not re-read %s, refreshing with the tokens in memory: %v", c.path, err)
	} else if stored.RefreshToken != "" {
		c.tokens = stored
	}
	if c.tokens.RefreshToken != staleRefreshToken && accessTokenFresh(c.tokens) {
		c.logFn("[auth] tokens were already refreshed by another process, loaded them from %s", c.path)
		return nil
	}
	fresh, err := RefreshTokens(c.client, c.tokens.RefreshToken)
	if err != nil {
		return err
	}
	c.tokens = fresh
	if err := SaveTokens(c.path, fresh); err != nil {
		return fmt.Errorf("tokens refreshed but not saved to %s: %w", c.path, err)
	}
	c.logFn("[auth] tokens refreshed and saved, access expires %s",
		time.Unix(fresh.TokenExpiresAt, 0).UTC().Format(time.RFC3339))
	return nil
}

func readTokens(path string) (TokenPair, error) {
	var tokens TokenPair
	raw, err := os.ReadFile(path)
	if err != nil {
		return tokens, err
	}
	var entries []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return tokens, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, entry := range entries {
		switch entry.Name {
		case AccessTokenEntry:
			tokens.Token = entry.Value
		case AccessTokenExpiresAtEntry:
			tokens.TokenExpiresAt, _ = strconv.ParseInt(entry.Value, 10, 64)
		case RefreshTokenEntry:
			tokens.RefreshToken = entry.Value
		}
	}
	return tokens, nil
}

func accessTokenFresh(tokens TokenPair) bool {
	expiresIn := time.Until(time.Unix(tokens.TokenExpiresAt, 0))
	return tokens.Token != "" && expiresIn > accessTokenRefreshMargin
}
