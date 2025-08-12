# -------- Settings --------
APP_NAME       := sniffer                   # базовое имя бинарника
ENTRYPOINT     := ./cmd/sniffer             # путь к main пакету
DIST           := dist

# Версия из файла VERSION
VERSION        := $(shell cat VERSION 2>/dev/null)

# По умолчанию поднимаем patch; можно: make release BUMP=minor|major
BUMP           ?= patch

# Встраиваем версию в бинарник (если в main есть: var version = "dev")
LDFLAGS        := -s -w -X 'main.version=$(VERSION)'

# Для воспроизводимых билдов лучше выключить CGO
CGO_ENABLED    := 0

# -------- Targets --------
.PHONY: all build clean release bump tag push check-git

all: build

build: clean mkdist \
	build-darwin-amd64 \
	build-darwin-arm64 \
	build-windows-amd64
	@echo "✅ Билды готовы в $(DIST)/"

mkdist:
	@mkdir -p $(DIST)

clean:
	@rm -rf $(DIST)

# ---- Platform builds ----
build-darwin-amd64:
	@echo "→ darwin/amd64 v$(VERSION)"
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) \
		go build -trimpath -ldflags "$(LDFLAGS)" \
		-o "$(DIST)/$(APP_NAME)_v$(VERSION)_darwin_amd64" $(ENTRYPOINT)

build-darwin-arm64:
	@echo "→ darwin/arm64 v$(VERSION)"
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=$(CGO_ENABLED) \
		go build -trimpath -ldflags "$(LDFLAGS)" \
		-o "$(DIST)/$(APP_NAME)_v$(VERSION)_darwin_arm64" $(ENTRYPOINT)

build-windows-amd64:
	@echo "→ windows/amd64 v$(VERSION)"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) \
		go build -trimpath -ldflags "$(LDFLAGS)" \
		-o "$(DIST)/$(APP_NAME)_v$(VERSION)_windows_amd64.exe" $(ENTRYPOINT)

# ---- Release flow ----
release: check-git
	@echo "Текущая версия: v$(VERSION)"
	@NEW_VERSION=$$( \
		awk -F. -v b=$(BUMP) '{
			M=$$1; m=$$2; p=$$3;
			if (b=="major") { M=M+1; m=0; p=0 }
			else if (b=="minor") { m=m+1; p=0 }
			else { p=p+1 }
			printf "%d.%d.%d", M,m,p
		}' VERSION \
	); \
	echo $$NEW_VERSION > VERSION; \
	git add VERSION; \
	git commit -m "chore: bump version to v$$NEW_VERSION"; \
	git tag -a v$$NEW_VERSION -m "v$$NEW_VERSION"; \
	git push && git push --tags; \
	$(MAKE) build VERSION=$$NEW_VERSION LDFLAGS="-s -w -X 'main.version=$$NEW_VERSION'"; \
	git add $(DIST)/*; \
	git commit -m "build: release binaries for v$$NEW_VERSION" || true; \
	git push; \
	echo "📦 Релиз собран и закоммичен: v$$NEW_VERSION"

# Только поднять версию локально (без тега/пуша)
bump:
	@NEW_VERSION=$$( \
		awk -F. -v b=$(BUMP) '{
			M=$$1; m=$$2; p=$$3;
			if (b=="major") { M=M+1; m=0; p=0 }
			else if (b=="minor") { m=m+1; p=0 }
			else { p=p+1 }
			printf "%d.%d.%d", M,m,p
		}' VERSION \
	); \
	echo $$NEW_VERSION > VERSION; \
	echo "v$$NEW_VERSION"

# Поставить тег на текущую версию и запушить (без изменения VERSION)
tag: check-git
	@test -n "$(VERSION)" || (echo "Файл VERSION пустой"; exit 1)
	git tag -a v$(VERSION) -m "v$(VERSION)"
	git push --tags
	@echo "🔖 Tagged v$(VERSION)"

push:
	git push && git push --tags

check-git:
	@# рабочее дерево должно быть чистым
	@git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Не в git-репозитории"; exit 1; }
	@git diff --quiet && git diff --cached --quiet || { \
		echo "Есть незафиксированные изменения. Закоммить их или stash перед release."; exit 1; }
