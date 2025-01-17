package jumphost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
)

type jumphostConfig struct {
	awsClient jumphostAWSClient
	cluster   *cmv1.Cluster
	subnetId  string
	tags      []types.Tag

	keyFilepath string
	ec2PublicIp string
}

type jumphostAWSClient interface {
	CreateKeyPair(ctx context.Context, params *ec2.CreateKeyPairInput, optFns ...func(options *ec2.Options)) (*ec2.CreateKeyPairOutput, error)
	DeleteKeyPair(ctx context.Context, params *ec2.DeleteKeyPairInput, optFns ...func(options *ec2.Options)) (*ec2.DeleteKeyPairOutput, error)
	DescribeKeyPairs(ctx context.Context, params *ec2.DescribeKeyPairsInput, optFns ...func(options *ec2.Options)) (*ec2.DescribeKeyPairsOutput, error)

	AuthorizeSecurityGroupIngress(ctx context.Context, params *ec2.AuthorizeSecurityGroupIngressInput, optFns ...func(options *ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error)
	CreateSecurityGroup(ctx context.Context, params *ec2.CreateSecurityGroupInput, optFns ...func(options *ec2.Options)) (*ec2.CreateSecurityGroupOutput, error)
	ModifySecurityGroupRules(ctx context.Context, params *ec2.ModifySecurityGroupRulesInput, optFns ...func(options *ec2.Options)) (*ec2.ModifySecurityGroupRulesOutput, error)
	DeleteSecurityGroup(ctx context.Context, params *ec2.DeleteSecurityGroupInput, optFns ...func(options *ec2.Options)) (*ec2.DeleteSecurityGroupOutput, error)
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(options *ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)

	DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(options *ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(options *ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(options *ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	RunInstances(ctx context.Context, params *ec2.RunInstancesInput, optFns ...func(options *ec2.Options)) (*ec2.RunInstancesOutput, error)
	TerminateInstances(ctx context.Context, params *ec2.TerminateInstancesInput, optFns ...func(options *ec2.Options)) (*ec2.TerminateInstancesOutput, error)

	// CreateTags (ec2:CreateTags) is not used explicitly, but all AWS resources will be created with tags
	CreateTags(ctx context.Context, params *ec2.CreateTagsInput, optFns ...func(options *ec2.Options)) (*ec2.CreateTagsOutput, error)
}

// findVpcId returns the AWS VPC ID of a provided jumphostConfig.
// Currently, requires that subnetId be defined.
func (j *jumphostConfig) findVpcId(ctx context.Context) (string, error) {
	if j.subnetId == "" {
		return "", errors.New("could not determine VPC; subnet id must not be empty")
	}

	log.Printf("searching for subnets by id: %s", j.subnetId)
	resp, err := j.awsClient.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		SubnetIds: []string{j.subnetId},
	})
	if err != nil {
		var awsErr smithy.APIError
		if errors.As(err, &awsErr) {
			// Check if it's a RequestExpired error
			if awsErr.ErrorCode() == "RequestExpired" {
				log.Fatal("AWS request expired. Ensure your AWS credentials are valid and you're logged in.")
			}
		}
		return "", err
	}

	if len(resp.Subnets) == 0 {
		return "", fmt.Errorf("found 0 subnets matching %s", j.subnetId)
	}

	return *resp.Subnets[0].VpcId, nil
}

// validateIP checks if the given IP address is valid.
func validateIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}
	return nil
}

// determinePublicIp returns the public IP determined by a GET request to https://checkip.amazonaws.com
func determinePublicIp() (string, error) {
	resp, err := http.Get("https://checkip.amazonaws.com")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received error code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// The response has a trailing \n, so trim it off before validating the IP is valid
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip != nil {
		return ip.String(), nil
	}

	return "", fmt.Errorf("received an invalid ip: %s", ip)
}

// getSecurityGroup queries AWS for a Security Group for the given VPC ID and returns SG details if found
func (j *jumphostConfig) getSecurityGroup(ctx context.Context, vpcId string) (*ec2.DescribeSecurityGroupsOutput, error) {
	log.Printf("searching for security groups associated with subnet id: %s", vpcId)
	resp, err := j.awsClient.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: append(generateTagFilters(j.tags), []types.Filter{
			{
				Name:   aws.String("group-name"),
				Values: []string{awsResourceName},
			},
			{
				Name:   aws.String("vpc-id"),
				Values: []string{vpcId},
			},
		}...),
	})

	if err != nil {
		// return fmt.Errorf("failed to describe security groups: %w", err)
		return resp, err
	}

	return resp, nil
}

// allowJumphostSshFromIp uses ec2:AuthorizeSecurityGroupIngress to create an inbound rule to allow
// TCP traffic on port 22 from the user's public IP.
func (j *jumphostConfig) allowJumphostSshFromIp(ctx context.Context, groupId string, ip string) error {
	_, err := j.awsClient.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		CidrIp:     aws.String(fmt.Sprintf("%s/32", ip)),
		FromPort:   aws.Int32(22),
		GroupId:    aws.String(groupId),
		IpProtocol: aws.String("tcp"),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeSecurityGroupRule,
				Tags:         j.tags,
			},
		},
		ToPort: aws.Int32(22),
	})

	// Handle specific error for duplicate rule
	if err != nil {
		var awsErr smithy.APIError
		if errors.As(err, &awsErr) {
			// Check if it's a Duplicate error
			if awsErr.ErrorCode() == "InvalidPermission.Duplicate" {
				log.Printf("Security group rule already exists for IP %s, skipping creation.", ip)
				return nil // Treat as a non-fatal condition
			}
		}
		return err // Return other errors
	}

	log.Printf("authorized security group ingress updated for IP Address %s", ip)

	return nil
}
