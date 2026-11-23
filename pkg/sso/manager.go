package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

const statePrefix = "state"

// pendingLogin is the server-side context bound to an issued state value.
type pendingLogin struct {
	ProviderID   string `json:"provider_id"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
}

// Manager coordinates providers, signed state, PKCE and the login/callback flow.
type Manager struct {
	mu        sync.RWMutex
	providers map[string]Provider
	cache     Cache
	signer    *StateSigner
	stateTTL  time.Duration
}

// NewManager creates a Manager. stateTTL bounds how long a login may remain pending.
func NewManager(cache Cache, signer *StateSigner, stateTTL time.Duration) *Manager {
	return &Manager{
		providers: map[string]Provider{},
		cache:     cache,
		signer:    signer,
		stateTTL:  stateTTL,
	}
}

// Register adds a provider under its ID.
func (m *Manager) Register(p Provider) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.providers[p.ID()]; exists {
		return ErrInvalidConfig("provider already registered: "+p.ID(), nil)
	}
	m.providers[p.ID()] = p
	return nil
}

// Get returns a registered provider.
func (m *Manager) Get(id string) (Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.providers[id]
	if !ok {
		return nil, ErrNotFound("provider not found: " + id)
	}
	return p, nil
}

// Providers lists registered provider IDs in sorted order.
func (m *Manager) Providers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.providers))
	for id := range m.providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// BeginLogin generates signed state, nonce and PKCE verifier, persists them, and
// returns the provider authorization URL.
func (m *Manager) BeginLogin(ctx context.Context, providerID string, req AuthURLRequest) (*AuthURLResponse, error) {
	p, err := m.Get(providerID)
	if err != nil {
		return nil, err
	}
	state, err := m.signer.Sign()
	if err != nil {
		return nil, err
	}
	nonce, err := RandomString(16)
	if err != nil {
		return nil, NewError(ErrCodeInternal, "nonce generation failed", http.StatusInternalServerError, err)
	}
	verifier, err := NewCodeVerifier()
	if err != nil {
		return nil, NewError(ErrCodeInternal, "pkce generation failed", http.StatusInternalServerError, err)
	}

	data, err := json.Marshal(pendingLogin{ProviderID: providerID, Nonce: nonce, CodeVerifier: verifier})
	if err != nil {
		return nil, NewError(ErrCodeInternal, "encode pending login failed", http.StatusInternalServerError, err)
	}
	if err := m.cache.Set(ctx, CacheKey(statePrefix, state), data, m.stateTTL); err != nil {
		return nil, NewError(ErrCodeInternal, "store pending login failed", http.StatusInternalServerError, err)
	}

	req.State, req.Nonce, req.CodeVerifier = state, nonce, verifier
	return p.GetAuthURL(ctx, req)
}

// CompleteLogin validates the callback state (signature, expiry, one-time use,
// provider binding) and delegates the code exchange to the provider.
func (m *Manager) CompleteLogin(ctx context.Context, providerID string, cb CallbackRequest) (*IdentityResult, error) {
	p, err := m.Get(providerID)
	if err != nil {
		return nil, err
	}
	if cb.Error != "" {
		return nil, NewError(ErrCodeIdPRejected, cb.Error+": "+cb.ErrorDesc, http.StatusUnauthorized, nil)
	}
	if err := m.signer.Verify(cb.State); err != nil {
		return nil, err
	}

	key := CacheKey(statePrefix, cb.State)
	data, found, err := m.cache.Get(ctx, key)
	if err != nil {
		return nil, NewError(ErrCodeInternal, "load pending login failed", http.StatusInternalServerError, err)
	}
	if !found {
		return nil, ErrStateInvalid("unknown or already used state")
	}
	// One-time use: delete before exchanging the code to defeat replays.
	if err := m.cache.Delete(ctx, key); err != nil {
		return nil, NewError(ErrCodeInternal, "consume pending login failed", http.StatusInternalServerError, err)
	}

	var pending pendingLogin
	if err := json.Unmarshal(data, &pending); err != nil {
		return nil, NewError(ErrCodeInternal, "decode pending login failed", http.StatusInternalServerError, err)
	}
	if pending.ProviderID != providerID {
		return nil, ErrStateInvalid("state issued for a different provider")
	}

	cb.CodeVerifier, cb.Nonce = pending.CodeVerifier, pending.Nonce
	return p.HandleCallback(ctx, cb)
}
