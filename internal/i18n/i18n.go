// Package i18n is key→string catalogs with English fallback.
package i18n

import "fmt"

type Language struct {
	Code string
	Name string
}

func Languages() []Language {
	return []Language{
		{Code: "ru", Name: "Русский"},
		{Code: "en", Name: "English"},
	}
}

// Locale looks up UI strings, a missing key falls back to English, then to the key itself
type Locale struct {
	code     string
	messages map[string]string
	fallback map[string]string
}

// New picks a catalog, an unknown code gets Russian
func New(code string) Locale {
	if _, ok := catalogs[code]; !ok {
		code = "ru"
	}
	return Locale{
		code:     code,
		messages: catalogs[code],
		fallback: catalogs["en"],
	}
}

func (l Locale) Code() string {
	return l.code
}

// T returns a translated string, optional args go to fmt.Sprintf
func (l Locale) T(key string, args ...any) string {
	s, ok := l.messages[key]
	if !ok || s == "" {
		s = l.fallback[key]
	}
	if s == "" {
		return key
	}
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

var catalogs = map[string]map[string]string{
	"ru": ru,
	"en": en,
}
