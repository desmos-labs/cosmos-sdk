package server

import (
	"fmt"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Deprecated: GenerateCoinKey generates a new key mnemonic along with its addrress.
// Please use testutils.GenerateCoinKey instead.
func GenerateCoinKey(algo keyring.SignatureAlgo) (sdk.AccAddress, string, error) {
	// generate a private key, with recovery phrase
	info, secret, err := keyring.NewInMemory().NewMnemonic("name", keyring.English, sdk.FullFundraiserPath, keyring.DefaultBIP39Passphrase, algo)
	if err != nil {
		return sdk.AccAddress([]byte{}), "", err
	}
	return sdk.AccAddress(info.GetPubKey().Address()), secret, nil
}

// GenerateSaveCoinKey returns the address of a public key, along with the secret
// phrase to recover the private key.
func GenerateSaveCoinKey(keybase keyring.Keyring, keyName string, overwrite bool, algo keyring.SignatureAlgo) (sdk.AccAddress, string, error) {
	return GenerateSaveCoinKeyFromPath(keybase, keyName, overwrite, algo, sdk.FullFundraiserPath)
}

// GenerateSaveCoinKeyFromPath returns the address of a public key, along with the secret
// phrase to recover the private key.
func GenerateSaveCoinKeyFromPath(keybase keyring.Keyring, keyName string, overwrite bool, algo keyring.SignatureAlgo, path string) (sdk.AccAddress, string, error) {
	exists := false
	_, err := keybase.Key(keyName)
	if err == nil {
		exists = true
	}

	// ensure no overwrite
	if !overwrite && exists {
		return sdk.AccAddress{}, "", fmt.Errorf("key already exists, overwrite is disabled")
	}

	// remove the old key by name if it exists
	if exists {
		if err := keybase.Delete(keyName); err != nil {
			return sdk.AccAddress{}, "", fmt.Errorf("failed to overwrite key")
		}
	}

	info, secret, err := keybase.NewMnemonic(keyName, keyring.English, path, keyring.DefaultBIP39Passphrase, algo)
	if err != nil {
		return sdk.AccAddress{}, "", err
	}

	return sdk.AccAddress(info.GetPubKey().Address()), secret, nil
}
