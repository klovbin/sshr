package app

import (
	"errors"

	"sshr.dev/internal/pwmgr"
)

// opStorePassword creates a 1Password item for a password typed with
// PasswordOnePassword and keeps only its reference, the password itself is
// not written to the host file
func (s *Store) opStorePassword(h *Host) error {
	if h.PasswordMode != PasswordOnePassword || h.Password == "" {
		return nil
	}
	if h.PasswordRef != "" {
		return errors.New("the host is linked to a 1Password item, change the password there and leave it empty here")
	}
	vault := ""
	if s.OPVault != nil {
		vault = *s.OPVault
	} else if st, err := LoadSettings(); err == nil {
		vault = st.OPVault
	}
	ref, err := pwmgr.OPCreateLogin(h.Name, h.User, h.Password, vault)
	if err != nil {
		return err
	}
	h.PasswordRef, h.Password = ref, ""
	return nil
}
