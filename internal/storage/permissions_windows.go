//go:build windows

package storage

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// hardenPermissions restricts the database file's DACL so that only the current user
// (owner) and SYSTEM have access, removing inherited/group/everyone access. This is a
// defense-in-depth control (see docs/THREAT_MODEL.md); the primary protection remains
// the at-rest encryption of secret values.
func hardenPermissions(path string) error {
	// Ensure the file exists before adjusting its security descriptor.
	if _, err := os.Stat(path); err != nil {
		return nil // nothing to harden yet
	}

	owner, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("storage: current user sid: %w", err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("storage: system sid: %w", err)
	}

	access := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(owner),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(systemSID),
			},
		},
	}

	dacl, err := windows.ACLFromEntries(access, nil)
	if err != nil {
		return fmt.Errorf("storage: build dacl: %w", err)
	}

	// PROTECTED_DACL_SECURITY_INFORMATION strips inherited ACEs.
	secInfo := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		secInfo,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("storage: set security info: %w", err)
	}
	return nil
}

func currentUserSID() (*windows.SID, error) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}
