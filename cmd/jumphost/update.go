package jumphost

import (
	"context"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

func newCmdUpdateJumphost() *cobra.Command {
	cmdArgs := &cmdArgs{}

	updateCmd := &cobra.Command{
		Use:          "update",
		SilenceUsage: true,
		Short:        "Update an existing jumphost AWS Security Group",
		Long: `  Update an existing jumphost AWS Security Group for emergency SSH access to a cluster's VMs:

  This command updates the IP allow list of a running jumphost. To use this command, 
  the jumphost must already be set up using the "create" command. It requires valid 
  AWS credentials and a subnet ID associated with the existing jumphost.

  When the cluster's API server is accessible, prefer "oc debug node".

  `,
		Example: `
  # Update a jumphost IP allow list
  osdctl jumphost update --subnet-id {public-subnet-id} --set-self-ip
  osdctl jumphost update --subnet-id {public-subnet-id} --set-ip 1.2.3.4`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			j, err := initJumphostConfig(context.TODO(), *cmdArgs)
			if err != nil {
				return err
			}

			return j.runUpdate(context.TODO(), *cmdArgs)
		},
	}

	updateCmd.Flags().StringVar(&cmdArgs.subnetId, "subnet-id", "", "Public subnet ID to create a jumphost in")
	updateCmd.MarkFlagRequired("subnet-id")
	updateCmd.Flags().StringVar(&cmdArgs.setIp, "set-ip", "", "Update AWS Security Group to allow specified IP")
	updateCmd.Flags().BoolVarP(&cmdArgs.setSelfIp, "set-self-ip", "", false, "Update AWS Security Group to allow your auto-discovered egress IP")
	updateCmd.MarkFlagsOneRequired("set-ip", "set-self-ip")
	updateCmd.MarkFlagsMutuallyExclusive("set-ip", "set-self-ip")

	return updateCmd
}

func (j *jumphostConfig) runUpdate(ctx context.Context, a cmdArgs) error {

	// Lookup VPC Subnet ID
	vpcId, err := j.findVpcId(ctx)
	if err != nil {
		return err
	}

	// Lookup SG for VPC Subnet ID
	sgId, err := j.getSecurityGroup(ctx, vpcId)
	if err != nil {
		return err
	}

	if len(sgId.SecurityGroups) == 0 {
		log.Fatalf("unable to find security group matching name %s", []string{awsResourceName})
	}

	// Add IP to Security Group Rules when either --set-self-ip or --set-ip are provided
	// (Currently this is the only feature of the "update" command)
	if a.setIp != "" || a.setSelfIp {
		j.updateIpList(ctx, a, *sgId.SecurityGroups[0].GroupId)
	}

	return nil
}

// updateIpList will either take in a user provided IP Address, or discover your current Egress IP Address
// and will update the Security Group to allow the new IP Address
func (j *jumphostConfig) updateIpList(ctx context.Context, a cmdArgs, sgId string) {

	// Pass CLI args to logic that figures out what IP to set
	ip, err := findIP(a)
	if err != nil {
		log.Fatalf(err.Error())
	}

	// Update SG with new IP
	if err := j.allowJumphostSshFromIp(ctx, sgId, ip); err != nil {
		log.Fatal("failed to allow SSH to jumphost:", err)
	}
}

func findIP(a cmdArgs) (string, error) {
	var ip string

	// Figure out what IP to use (self or provided)
	if (a.setIp != "") && (a.setSelfIp) {
		return "", fmt.Errorf("you provided more than one way of setting an IP")
	}

	if a.setIp != "" {
		err := validateIP(a.setIp)
		if err != nil {
			return "", fmt.Errorf("provided IP %s is not an valid IP Address", a.setIp)
		}
		return a.setIp, nil
	}

	if a.setSelfIp {
		ip, err := determinePublicIp()
		if err != nil {
			return "", fmt.Errorf("skipping modifying security group rule - failed to determine public ip: %s", err)
		}
		return ip, nil
	}

	return ip, nil
}
