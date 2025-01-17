package jumphost

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/osdctl/pkg/utils"
	"github.com/spf13/cobra"
)

const (
	awsResourceName     = "red-hat-sre-jumphost"
	publicSubnetTagKey  = "kubernetes.io/role/elb"
	privateSubnetTagKey = "kubernetes.io/role/internal-elb"
)

// cmdArgs holds the arguments for the update command.
type cmdArgs struct {
	// clusterId string
	subnetId  string
	setIp     string
	setSelfIp bool
}

func NewCmdJumphost() *cobra.Command {
	jumphost := &cobra.Command{
		Use:  "jumphost",
		Args: cobra.NoArgs,
	}

	jumphost.AddCommand(
		newCmdCreateJumphost(),
		newCmdDeleteJumphost(),
		newCmdUpdateJumphost(),
	)

	return jumphost
}

// initJumphostConfig initializes a jumphostConfig struct for use with jumphost commands.
// Generally, this function should always be used as opposed to initializing the struct by hand.
func initJumphostConfig(ctx context.Context, a cmdArgs) (*jumphostConfig, error) {
	ocm, err := utils.CreateConnection()
	if err != nil {
		return nil, err
	}
	defer ocm.Close()

	//cluster, err := utils.GetClusterAnyStatus(ocm, clusterId)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to get OCM cluster info for %s: %s", clusterId, err)
	//}

	//if err := validateCluster(cluster); err != nil {
	//	return nil, fmt.Errorf("cluster not supported yet - %s", err)
	//}
	//
	//log.Printf("getting AWS credentials from backplane-api for %s (%s)", cluster.Name(), cluster.ID())
	//cfg, err := osdCloud.CreateAWSV2Config(ctx, cluster.ID())
	//if err != nil {
	//	return nil, err
	//}

	// TODO: When --cluster-id is supported, only do this as a fallback
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	return &jumphostConfig{
		awsClient: ec2.NewFromConfig(cfg),
		subnetId:  a.subnetId,
		tags: []types.Tag{
			//{
			//	// This tag will allow the uninstaller to clean up orphaned resources in worst-case scenarios
			//	Key:   aws.String(fmt.Sprintf("kubernetes.io/cluster/%s", cluster.InfraID())),
			//	Value: aws.String("owned"),
			//},
			{
				Key:   aws.String("red-hat-managed"),
				Value: aws.String("true"),
			},
			{
				Key:   aws.String("Name"),
				Value: aws.String("red-hat-sre-jumphost"),
			},
		},
	}, nil
}

// validateCluster is currently unused as the --cluster-id flag is not supported yet.
// Eventually, it will gate the usage of the --cluster-id flag based on types of supported clusters.
func validateCluster(cluster *cmv1.Cluster) error {
	if cluster != nil {
		if cluster.CloudProvider().ID() != "aws" {
			return fmt.Errorf("only supports aws, got %s", cluster.CloudProvider().ID())
		}

		if !cluster.AWS().STS().Empty() {
			return errors.New("only supports non-STS clusters")
		}

		return nil
	}

	return errors.New("unexpected error, nil cluster provided")
}
