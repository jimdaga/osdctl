package jumphost

import (
	"testing"
)

func TestFindIP(t *testing.T) {
	tests := []struct {
		name      string
		c         cmdArgs
		expectErr bool
	}{
		{
			name:      "set manual ip",
			c:         cmdArgs{subnetId: "", setIp: "10.0.0.1", setSelfIp: false},
			expectErr: false,
		},
		{
			name:      "set invalid manual ip",
			c:         cmdArgs{subnetId: "", setIp: "invalidSyntax", setSelfIp: true},
			expectErr: true,
		},
		{
			name:      "set discovered ip",
			c:         cmdArgs{subnetId: "", setIp: "", setSelfIp: true},
			expectErr: false,
		},
		{
			name:      "set invalid discovered and manual ip",
			c:         cmdArgs{subnetId: "", setIp: "10.0.0.2", setSelfIp: true},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := findIP(test.c)
			if err != nil {
				if !test.expectErr {
					t.Errorf("expected no err, got %s", err)
				}
			} else {
				if test.expectErr {
					t.Errorf("expected err, got none")
				}
			}
		})
	}
}
