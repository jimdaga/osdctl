package jumphost

import (
	"context"
	"log"

	"github.com/spf13/cobra"
)

func newCmdUpdateJumphost() *cobra.Command {
	var (
		clusterId string
		subnetId  string
		setIp     string
		setSelfIp bool
	)

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
			j, err := initJumphostConfig(context.TODO(), clusterId, subnetId)
			if err != nil {
				return err
			}

			return j.runUpdate(context.TODO(), setIp, setSelfIp)
		},
	}

	updateCmd.Flags().StringVar(&subnetId, "subnet-id", "", "Public subnet ID to create a jumphost in")
	updateCmd.MarkFlagRequired("subnet-id")
	updateCmd.Flags().StringVar(&setIp, "set-ip", "", "Update AWS Security Group to allow specified IP")
	updateCmd.Flags().BoolVarP(&setSelfIp, "set-self-ip", "", false, "Update AWS Security Group to allow your auto-discovered egress IP")
	updateCmd.MarkFlagsMutuallyExclusive("set-ip", "set-self-ip")

	return updateCmd
}

func (j *jumphostConfig) runUpdate(ctx context.Context, setIp string, setSelfIp bool) error {

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
	if setIp != "" || setSelfIp {
		j.updateIpList(ctx, *sgId.SecurityGroups[0].GroupId, setIp, setSelfIp)
	}

	return nil
}

// updateIpList will either take in a user provided IP Address, or discover your current Egress IP Address
// and will update the Security Group to allow the new IP Address
func (j *jumphostConfig) updateIpList(ctx context.Context, sgId string, setIp string, setSelfIp bool) {

	var ip string

	// Figure out what IP to use (self or provided)
	if setIp != "" {
		err := validateIP(setIp)
		if err != nil {
			log.Fatalf("provided IP %s is not an valid IP Address", setIp)
		}

		log.Printf("updating AWS Security Group to allow specified IP: %s\n", setIp)
		ip = setIp
	}

	if setSelfIp {
		ip, err := determinePublicIp()
		if err != nil {
			log.Printf("skipping modifying security group rule - failed to determine public ip: %s", err)
		}
		log.Printf("updating AWS Security Group to allow your local egress IP: %s\n", ip)
	}

	// Update SG with new IP
	if err := j.allowJumphostSshFromIp(ctx, sgId, ip); err != nil {
		log.Fatal("failed to allow SSH to jumphost:", err)
	}
}
