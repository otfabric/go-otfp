// SPDX-License-Identifier: MIT

package openadr

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The tokenURL of /auth/server reaches the identity as text only.
func TestTokenURLIsText(t *testing.T) {
	body, err := json.Marshal(map[string]string{"tokenURL": "https://vtn.example/" + fuzzkit.NonText[:len(fuzzkit.NonText)-1] + "auth/token"})
	if err != nil {
		t.Fatal(err)
	}
	tg := target(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	r, err := New().Detect(context.Background(), tg, core.Options{})
	fuzzkit.Check(t, proto, r, err)
	if !r.Matched || r.Identity == nil || r.Identity.Attributes["tokenUrl"] != "https://vtn.example/auth/token" {
		t.Fatalf("%v, identity %+v", r, r.Identity)
	}
}
