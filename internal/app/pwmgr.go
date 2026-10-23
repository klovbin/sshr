package app

import "sshr.dev/internal/pwmgr"

// 1Password and Bitwarden live in package pwmgr, these names keep the
// front ends working as before

// OPAccount is a 1Password account the op CLI knows
type OPAccount = pwmgr.OPAccount

// The errors of the password managers, the same values as in pwmgr
var (
	ErrNoOP             = pwmgr.ErrNoOP
	ErrOPIntegrationOff = pwmgr.ErrOPIntegrationOff
	ErrOPPrivacy        = pwmgr.ErrOPPrivacy
	ErrNoBW             = pwmgr.ErrNoBW
)

// ListOPAccounts lists the 1Password accounts the op CLI knows
func ListOPAccounts() ([]OPAccount, error) { return pwmgr.ListOPAccounts() }

// AuthorizeOPAccount asks 1Password to let op use account
func AuthorizeOPAccount(account string) error { return pwmgr.AuthorizeOPAccount(account) }

// OpenOPPrivacySettings opens the privacy settings of the system for op
func OpenOPPrivacySettings() error { return pwmgr.OpenOPPrivacySettings() }

// OpenOnePasswordCLIIntegration opens the developer settings of 1Password
func OpenOnePasswordCLIIntegration() error { return pwmgr.OpenOnePasswordCLIIntegration() }

// OpenOnePasswordCLIInstall opens the install page of the op CLI
func OpenOnePasswordCLIInstall() error { return pwmgr.OpenOnePasswordCLIInstall() }

// OpenURL opens url with the program of the system
func OpenURL(url string) error { return pwmgr.OpenURL(url) }

func opRead(ref string) ([]byte, error)        { return pwmgr.OPRead(ref) }
func opReadKey(ref string) ([]byte, error)     { return pwmgr.OPReadKey(ref) }
func opKeyPub(ref string) (string, error)      { return pwmgr.OPKeyPub(ref) }
func bwPassword(ref string) ([]byte, error)    { return pwmgr.BWPassword(ref) }
func bwKey(ref string) ([]byte, string, error) { return pwmgr.BWKey(ref) }
func bwKeyPub(ref string) (string, error)      { return pwmgr.BWKeyPub(ref) }
