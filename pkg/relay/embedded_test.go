package relay

import "testing"

func TestEmbeddedRelaysParsesAllEntries(t *testing.T) {
	t.Parallel()

	relays := EmbeddedRelays()
	if len(relays) == 0 {
		t.Fatal("EmbeddedRelays returned empty list")
	}

	if len(relays) != len(embeddedRelayURLs) {
		t.Fatalf("expected %d relays, got %d (some URLs may be malformed)", len(embeddedRelayURLs), len(relays))
	}

	for _, r := range relays {
		if r.Host == "" || r.Port == "" || r.ID == "" {
			t.Fatalf("embedded relay missing fields: %+v", r)
		}
	}
}
