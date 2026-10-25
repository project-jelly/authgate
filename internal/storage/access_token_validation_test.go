package storage

import (
	"context"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestTokenCallbacksRequireVerifiedClaims(t *testing.T) {
	store := new(Storage) // No DB access is allowed before token verification.
	if err := store.SetUserinfoFromToken(context.Background(), &oidc.UserInfo{}, "jti", "sub", ""); err == nil {
		t.Fatal("unverified userinfo accepted")
	}
	if err := store.SetIntrospectionFromToken(context.Background(), &oidc.IntrospectionResponse{}, "jti", "sub", "client"); err == nil {
		t.Fatal("unverified introspection accepted")
	}
}
