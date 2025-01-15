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
)

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
		return "", err
	}

	if len(resp.Subnets) == 0 {
		return "", fmt.Errorf("found 0 subnets matching %s", j.subnetId)
	}

	return *resp.Subnets[0].VpcId, nil
}

// DeterminePublicIp returns the public IP determined by a GET request to https://checkip.amazonaws.com
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

// getSecurityGroup
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
func (j *jumphostConfig) allowJumphostSshFromIp(ctx context.Context, groupId string) error {
	ip, err := determinePublicIp()
	if err != nil {
		log.Printf("skipping modifying security group rule - failed to determine public ip: %s", err)
		return nil
	}

	if _, err := j.awsClient.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
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
	}); err != nil {
		return err
	}
	log.Printf("authorized security group ingress for %s", ip)

	return nil
}
