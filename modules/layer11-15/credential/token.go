package credential

import (
	"fmt"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type TokenImpersonationThief struct{}

func NewTokenImpersonationThief() *TokenImpersonationThief {
	return &TokenImpersonationThief{}
}

func (t *TokenImpersonationThief) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "token_impersonation",
		Username:  "SYSTEM",
		Domain:    "NT AUTHORITY",
		Hash:      "ImpersonatedToken",
		Source:    "Token Impersonation",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (t *TokenImpersonationThief) Name() string {
	return "TokenImpersonation"
}

type TokenDelegationThief struct{}

func NewTokenDelegationThief() *TokenDelegationThief {
	return &TokenDelegationThief{}
}

func (t *TokenDelegationThief) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "token_delegation",
		Username:  "Administrator",
		Domain:    "WORKGROUP",
		Hash:      "DelegationToken",
		Source:    "Token Delegation",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (t *TokenDelegationThief) Name() string {
	return "TokenDelegation"
}

type TokenPrimaryThief struct{}

func NewTokenPrimaryThief() *TokenPrimaryThief {
	return &TokenPrimaryThief{}
}

func (t *TokenPrimaryThief) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "token_primary",
		Username:  "LOCAL SERVICE",
		Domain:    "NT AUTHORITY",
		Hash:      "PrimaryToken",
		Source:    "Token Primary",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (t *TokenPrimaryThief) Name() string {
	return "TokenPrimary"
}

func getTokenMethods() []TokenMethod {
	return []TokenMethod{
		TokenImpersonation,
		TokenDelegation,
		TokenPrimary,
	}
}

func validateTokenMethod(method TokenMethod) error {
	validMethods := getTokenMethods()
	for _, m := range validMethods {
		if m == method {
			return nil
		}
	}
	return fmt.Errorf("invalid token method: %s", method)
}
