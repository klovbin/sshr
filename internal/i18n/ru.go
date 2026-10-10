package i18n

// Russian UI strings (keys shared with en.go).
var ru = map[string]string{
	"app.title": "sshr",

	"status.ready": "готово",
	"status.empty": "хостов пока нет",
	"status.count": "хостов: %d",
	"status.added":   "добавлен: %s",
	"status.deleted": "удалён: %s",

	"list.empty": "Список пуст — жми «Добавить»",

	"btn.add":      "Добавить",
	"btn.save":     "Сохранить",
	"btn.cancel":   "Отмена",
	"btn.delete":   "Удалить",
	"btn.settings": "Настройки",
	"btn.back":     "Назад",
	"nav.hosts":    "Серверы",

	"modal.delete.title": "Удалить сервер?",
	"modal.delete.body":  "«%s» будет удалён из списка. Это нельзя отменить.",
	"modal.add.title":    "Добавить сервер",

	"field.name": "Имя",
	"field.host": "Хост / IP",
	"field.user": "Пользователь",
	"field.port": "Порт",

	"settings.title":    "Настройки",
	"settings.language": "Язык интерфейса",
	"settings.connection": "Подключение",
	"settings.mosh":       "Подключаться через mosh",
	"settings.mosh.hint":  "Сеанс не рвётся при смене сети и сне ноутбука, набранное видно сразу даже на медленной связи. Нужен mosh на этом компьютере, а на сервере — mosh-server и открытые UDP-порты 60000–61000. Нет проброса портов, нет прокрутки без tmux, не показываются картинки в терминале, не работает на Windows. Если mosh не поднялся, sshr подключится обычным ssh.",

	"sidebar.hosts.title": "Серверы",
	"sidebar.hosts.hint":  "Список и фильтры — сюда",
	"sidebar.about":       "About",

	"err.host_empty":    "host пустой",
	"err.user_required": "user обязателен",
	"err.port_invalid":  "порт кривой",
	"err.not_found":     "не найден",
}
