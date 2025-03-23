// auth_test.go

package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "No authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Malformed header - wrong prefix",
			headers: http.Header{"Authorization": []string{"Bearer 12345"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "Malformed header - no key value",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "Valid header",
			headers: http.Header{"Authorization": []string{"ApiKey 12345"}},
			wantKey: "12345",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() got = %q, want %q", gotKey, tt.wantKey)
			}

			if err == nil && tt.wantErr != nil {
				t.Errorf("GetAPIKey() error = nil, want %q", tt.wantErr)
			} else if err != nil && tt.wantErr == nil {
				t.Errorf("GetAPIKey() error = %q, want nil", err)
			} else if err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %q, want %q", err.Error(), tt.wantErr.Error())
			}
		})
	}
}
