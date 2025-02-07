package jumphost

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type mockAuthorizeSecurityGroupIngress struct {
	jumphostAWSClient
}

func (m mockAuthorizeSecurityGroupIngress) AuthorizeSecurityGroupIngress(ctx context.Context, params *ec2.AuthorizeSecurityGroupIngressInput, optFns ...func(options *ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
	return &ec2.AuthorizeSecurityGroupIngressOutput{}, nil
}

func TestUpdateIpList(t *testing.T) {
	tests := []struct {
		name           string
		jumphostConfig *jumphostConfig
		group          string
		ip             string
		expectErr      bool
	}{
		{
			name: "test mock update to jumphost",
			jumphostConfig: &jumphostConfig{
				awsClient: &mockAuthorizeSecurityGroupIngress{},
			},
			group: "abc123",
			ip:    "1.2.3.4",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.jumphostConfig.allowJumphostSshFromIp(context.TODO(), "group", "123")
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
