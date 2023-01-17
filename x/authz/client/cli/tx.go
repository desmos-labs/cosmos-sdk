package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/version"
	authclient "github.com/cosmos/cosmos-sdk/x/auth/client"
	"github.com/cosmos/cosmos-sdk/x/authz"
	bank "github.com/cosmos/cosmos-sdk/x/bank/types"
	staking "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// Flag names and values
const (
	FlagSpendLimit        = "spend-limit"
	FlagMsgType           = "msg-type"
	FlagExpiration        = "expiration"
	FlagAllowedValidators = "allowed-validators"
	FlagDenyValidators    = "deny-validators"
	delegate              = "delegate"
	redelegate            = "redelegate"
	unbond                = "unbond"
)

// GetTxCmd returns the transaction commands for this module
func GetTxCmd() *cobra.Command {
	AuthorizationTxCmd := &cobra.Command{
		Use:                        authz.ModuleName,
		Short:                      "Authorization transactions subcommands",
		Long:                       "Authorize and revoke access to execute transactions on behalf of your address",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	AuthorizationTxCmd.AddCommand(
		NewCmdGrantAuthorization(),
		NewCmdRevokeAuthorization(),
		NewCmdExecAuthorization(),
	)

	return AuthorizationTxCmd
}

func NewCmdGrantAuthorization() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant <grantee> <authorization_type=\"send\"|\"generic\"|\"delegate\"|\"unbond\"|\"redelegate\"> --from <granter>",
		Short: "Grant authorization to an address",
		Long: strings.TrimSpace(
			fmt.Sprintf(`grant authorization to an address to execute a transaction on your behalf:

Examples:
 $ %s tx %s grant cosmos1skjw.. send %s --spend-limit=1000stake --from=cosmos1skl..
 $ %s tx %s grant cosmos1skjw.. generic --msg-type=/cosmos.gov.v1beta1.MsgVote --from=cosmos1sk..
	`, version.AppName, authz.ModuleName, bank.SendAuthorization{}.MsgTypeURL(), version.AppName, authz.ModuleName),
		),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			grantee, err := sdk.AccAddressFromBech32(args[0])
			if err != nil {
				return err
			}

			exp, err := cmd.Flags().GetInt64(FlagExpiration)
			if err != nil {
				return err
			}

			authorization, err := GetAuthorizationFromFlags(args[1], cmd.Flags())
			if err != nil {
				return err
			}

			msg, err := authz.NewMsgGrant(clientCtx.GetFromAddress(), grantee, authorization, time.Unix(exp, 0))
			if err != nil {
				return err
			}

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().String(FlagMsgType, "", "The Msg method name for which we are creating a GenericAuthorization")
	cmd.Flags().String(FlagSpendLimit, "", "SpendLimit for Send Authorization, an array of Coins allowed spend")
	cmd.Flags().StringSlice(FlagAllowedValidators, []string{}, "Allowed validators addresses separated by ,")
	cmd.Flags().StringSlice(FlagDenyValidators, []string{}, "Deny validators addresses separated by ,")
	cmd.Flags().Int64(FlagExpiration, time.Now().AddDate(1, 0, 0).Unix(), "The Unix timestamp. Default is one year.")
	return cmd
}

// GetAuthorizationFromFlags returns an authorization from the given command flags
func GetAuthorizationFromFlags(typ string, flags *pflag.FlagSet) (authz.Authorization, error) {
	var authorization authz.Authorization
	switch typ {
	case "send":
		sendAuthz, err := getSendAuthorizationFromFlags(flags)
		if err != nil {
			return nil, err
		}
		authorization = sendAuthz

	case "generic":
		genericAuthz, err := getGenericAuthorizationFromFlags(flags)
		if err != nil {
			return nil, err
		}
		authorization = genericAuthz

	case delegate, unbond, redelegate:
		stakeAuthz, err := getStakeAuthorizationFromFlags(typ, flags)
		if err != nil {
			return nil, err
		}
		authorization = stakeAuthz

	default:
		return nil, fmt.Errorf("invalid authorization type, %s", typ)
	}
	return authorization, nil
}

// getSendAuthorizationFromFlags returns a send authorization from the given command flags
func getSendAuthorizationFromFlags(flags *pflag.FlagSet) (*bank.SendAuthorization, error) {
	limit, err := flags.GetString(FlagSpendLimit)
	if err != nil {
		return nil, err
	}

	spendLimit, err := sdk.ParseCoinsNormalized(limit)
	if err != nil {
		return nil, err
	}

	if !spendLimit.IsAllPositive() {
		return nil, fmt.Errorf("spend-limit should be greater than zero")
	}

	return bank.NewSendAuthorization(spendLimit), nil
}

// getGenericAuthorizationFromFlags returns a generic authorization from the given command flags
func getGenericAuthorizationFromFlags(flags *pflag.FlagSet) (*authz.GenericAuthorization, error) {
	msgType, err := flags.GetString(FlagMsgType)
	if err != nil {
		return nil, err
	}
	return authz.NewGenericAuthorization(msgType), nil
}

// getStakeAuthorizationFromFlags returns a stake authorization from the given command flags
func getStakeAuthorizationFromFlags(stakingType string, flags *pflag.FlagSet) (*staking.StakeAuthorization, error) {
	limit, err := flags.GetString(FlagSpendLimit)
	if err != nil {
		return nil, err
	}

	var delegateLimit *sdk.Coin
	if limit != "" {
		spendLimit, err := sdk.ParseCoinNormalized(limit)
		if err != nil {
			return nil, err
		}

		if !spendLimit.IsPositive() {
			return nil, fmt.Errorf("spend-limit should be greater than zero")
		}
		delegateLimit = &spendLimit
	}

	allowed, err := getValidatorAddressesFromFlags(flags, FlagAllowedValidators)
	if err != nil {
		return nil, err
	}

	denied, err := getValidatorAddressesFromFlags(flags, FlagDenyValidators)
	if err != nil {
		return nil, err
	}

	var authorizationType staking.AuthorizationType
	switch stakingType {
	case delegate:
		authorizationType = staking.AuthorizationType_AUTHORIZATION_TYPE_DELEGATE
	case unbond:
		authorizationType = staking.AuthorizationType_AUTHORIZATION_TYPE_UNDELEGATE
	default:
		authorizationType = staking.AuthorizationType_AUTHORIZATION_TYPE_REDELEGATE
	}

	return staking.NewStakeAuthorization(allowed, denied, authorizationType, delegateLimit)
}

// getValidatorAddressesFromFlags returns validator addresses with type (allowed or deny) from flags
func getValidatorAddressesFromFlags(flags *pflag.FlagSet, typ string) ([]sdk.ValAddress, error) {
	validators, err := flags.GetStringSlice(typ)
	if err != nil {
		return nil, err
	}

	validatorAddrs := make([]sdk.ValAddress, len(validators))
	for i, validator := range validators {
		addr, err := sdk.ValAddressFromBech32(validator)
		if err != nil {
			return nil, err
		}
		validatorAddrs[i] = addr
	}
	return validatorAddrs, nil
}

func NewCmdRevokeAuthorization() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke [grantee] [msg_type] --from=[granter]",
		Short: "revoke authorization",
		Long: strings.TrimSpace(
			fmt.Sprintf(`revoke authorization from a granter to a grantee:
Example:
 $ %s tx %s revoke cosmos1skj.. %s --from=cosmos1skj..
			`, version.AppName, authz.ModuleName, bank.SendAuthorization{}.MsgTypeURL()),
		),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			grantee, err := sdk.AccAddressFromBech32(args[0])
			if err != nil {
				return err
			}

			granter := clientCtx.GetFromAddress()
			msgAuthorized := args[1]
			msg := authz.NewMsgRevoke(granter, grantee, msgAuthorized)

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), &msg)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func NewCmdExecAuthorization() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec [msg_tx_json_file] --from [grantee]",
		Short: "execute tx on behalf of granter account",
		Long: strings.TrimSpace(
			fmt.Sprintf(`execute tx on behalf of granter account:
Example:
 $ %s tx %s exec tx.json --from grantee
 $ %s tx bank send <granter> <recipient> --from <granter> --chain-id <chain-id> --generate-only > tx.json && %s tx %s exec tx.json --from grantee
			`, version.AppName, authz.ModuleName, version.AppName, version.AppName, authz.ModuleName),
		),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			grantee := clientCtx.GetFromAddress()

			if offline, _ := cmd.Flags().GetBool(flags.FlagOffline); offline {
				return errors.New("cannot broadcast tx during offline mode")
			}

			theTx, err := authclient.ReadTxFromFile(clientCtx, args[0])
			if err != nil {
				return err
			}
			msg := authz.NewMsgExec(grantee, theTx.GetMsgs())

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), &msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}
