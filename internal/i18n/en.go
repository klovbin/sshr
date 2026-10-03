package i18n

// English UI strings (also used as i18n fallback).
var en = map[string]string{
	"app.title": "sshr",

	"status.ready": "ready",
	"status.empty": "no hosts yet",
	"status.count": "hosts: %d",
	"status.added":   "added: %s",
	"status.deleted": "deleted: %s",

	"list.empty": "List empty — tap Add",

	"btn.add":      "Add host",
	"btn.save":     "Save",
	"btn.cancel":   "Cancel",
	"btn.delete":   "Delete",
	"btn.settings": "Settings",
	"btn.back":     "Back",
	"nav.hosts":    "Servers",

	"modal.delete.title": "Delete server?",
	"modal.delete.body":  "“%s” will be removed from the list. This cannot be undone.",
	"modal.add.title":    "Add server",

	"field.name": "Name",
	"field.host": "Host / IP",
	"field.user": "User",
	"field.port": "Port",

	"settings.title":    "Settings",
	"settings.language": "Interface language",

	"sidebar.hosts.title": "Servers",
	"sidebar.hosts.hint":  "List and filters go here",
	"sidebar.about":       "About",

	"err.host_empty":    "host is required",
	"err.user_required": "user is required",
	"err.port_invalid":  "invalid port",
	"err.not_found":     "not found",
}
