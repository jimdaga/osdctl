package jumphost

import (
	"context"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

func newCmdUpdateJumphost() *cobra.Command {
	var (
		clusterId string
		subnetId  string
		setIp     bool
	)

	update := &cobra.Command{
		Use:          "update",
		SilenceUsage: true,
		Short:        "Update a running jumphost config for emergency SSH access to a cluster's VMs",
		Long: `Update a running jumphost config for emergency SSH access to a cluster's VMs'

  TODO: UPDATE THIS>>>>
  This command automates the process of creating a jumphost in order to gain SSH
  access to a cluster's EC2 instances and should generally only be used as a last
  resort when the cluster's API server is otherwise inaccessible. It requires valid
  AWS credentials to be already set and a subnet ID in the associated AWS account.
  The provided subnet ID must be a public subnet.

  When the cluster's API server is accessible, prefer "oc debug node".
  >>>>
  `,
		Example: `
  # Update a jumphost IP allow list
  osdctl jumphost update --subnet-id public-subnet-id --set-ip`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			j, err := initJumphostConfig(context.TODO(), clusterId, subnetId)
			if err != nil {
				return err
			}

			return j.runUpdate(context.TODO())
		},
	}

	update.Flags().StringVar(&subnetId, "subnet-id", "", "public subnet id to create a jumphost in")
	update.MarkFlagRequired("subnet-id")
	update.Flags().BoolVarP(&setIp, "set-ip", "", false, "Update AWS Security Group to allow your egress IP")

	return update
}

func (j *jumphostConfig) runUpdate(ctx context.Context) error {
	vpcId, err := j.findVpcId(ctx)
	if err != nil {
		return err
	}

	securityGroupId, err := j.getSecurityGroup(ctx, vpcId)
	if err != nil {
		return err
	}

	if len(securityGroupId.SecurityGroups) == 0 {
		log.Printf("Unable to find security group matching name %s", []string{awsResourceName})
	}

	if err := j.allowJumphostSshFromIp(ctx, *securityGroupId.SecurityGroups[0].GroupId); err != nil {
		return fmt.Errorf("failed to allow SSH to jumphost: %w", err)
	}

	return nil
}
