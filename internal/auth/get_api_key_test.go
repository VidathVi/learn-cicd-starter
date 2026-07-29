// auth_test.go
package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error
		errMessage string // for checking non-sentinel error messages
	}{
		{
			name: "valid api key header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			wantKey: "my-secret-api-key",
			wantErr: nil,
		},
		{
			name:    "missing authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed - wrong prefix (Bearer)",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-api-key"},
			},
			wantKey:    "",
			errMessage: "malformed authorization header",
		},
		{
			name: "malformed - missing key after scheme",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:    "",
			errMessage: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			// Check sentinel error match
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if tt.errMessage != "" {
				// Check dynamically created error message
				if err == nil || err.Error() != tt.errMessage {
					t.Fatalf("GetAPIKey() error = %v, want message %q", err, tt.errMessage)
				}
			} else if err != nil {
				t.Fatalf("GetAPIKey() unexpected error = %v", err)
			}

			// Check extracted key
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() gotKey = %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}