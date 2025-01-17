package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// State is a placeholder for the state of the application which must be passed
// through IDP like github or Google.
type State struct {
	CSRFToken   string `json:"a"`
	RedirectURL string `json:"b"`
}

func (s State) Encode() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshal state to json: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *State) Decode(state string) error {
	b, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		return fmt.Errorf("decode state from base64: %w", err)
	}
	err = json.Unmarshal(b, s)
	if err != nil {
		return fmt.Errorf("unmarshal state from json: %w", err)
	}
	return nil
}
