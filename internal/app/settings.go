package app

import "sshr.dev/internal/settings"

// Settings are the choices kept in ~/.sshr/settings.json, see package
// settings
type Settings = settings.Settings

// OPLinkedAccount is a 1Password account linked in the settings
type OPLinkedAccount = settings.OPLinkedAccount

// LoadSettings reads settings.json, see settings.Load
func LoadSettings() (Settings, error) { return settings.Load() }

// SaveSettings writes the fields the holder changed, see settings.Save
func SaveSettings(s Settings) error { return settings.Save(s) }

func settingsPath() (string, error) { return settings.Path() }
