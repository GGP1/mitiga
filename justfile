# Mitiga Build System
# Per §12 Development Workflow

# Default recipe
default: build

# Variables
binary := "mitiga"
module := "github.com/GGP1/mitiga"
main := "./cmd/mitiga"
version := `git describe --tags --always --dirty 2>/dev/null || echo "dev"`
commit := `git rev-parse --short HEAD 2>/dev/null || echo "unknown"`
build_time := `date -u +"%Y-%m-%dT%H:%M:%SZ"`
ldflags := "-s -w -X main.version=" + version + " -X main.commit=" + commit + " -X main.buildTime=" + build_time

# Build the binary (static, stripped, reproducible per §3.6)
build:
    CGO_ENABLED=0 go build -trimpath -ldflags '{{ldflags}}' -o {{binary}} {{main}}
    @echo "Built {{binary}} ({{version}})"
    sha256sum {{binary}} | tee {{binary}}.sha256
    @echo "Checksum recorded in {{binary}}.sha256"

# Run all tests with race detector per §3.5
test:
    go test -race -count=1 ./...

# Run tests with verbose output
test-verbose:
    go test -race -count=1 -v ./...

# Run fuzz tests (10 seconds per target by default)
fuzz duration="10s":
    @echo "Running fuzz tests for {{duration}}..."
    find . -name '*_test.go' -exec grep -l 'func Fuzz' {} \; | while read f; do \
        dir=$(dirname "$f"); \
        grep -o 'func Fuzz[A-Za-z0-9_]*' "$f" | while read fn; do \
            echo "Fuzzing $fn in $dir"; \
            go test -fuzz="^${fn#func }$" -fuzztime={{duration}} "$dir" || true; \
        done \
    done

# Format all Go files per §12
fmt:
    gofmt -w .
    goimports -w .

# Lint with golangci-lint per §12
lint:
    golangci-lint run ./...

# Run go vet per §12
vet:
    go vet ./...

# Check for known vulnerabilities per §12
vulncheck:
    govulncheck ./...

# Run all checks (format, vet, lint, test)
check: fmt vet lint test

# Tidy go modules
tidy:
    go mod tidy

# Clean build artifacts
clean:
    rm -f {{binary}} {{binary}}.sha256

# Sync skills catalog from .github/skills/ into internal/skills/catalog/ for go:embed
sync-skills:
    @echo "Syncing skills catalog..."
    rm -rf internal/skills/catalog
    mkdir -p internal/skills/catalog
    for d in .github/skills/*/; do \
        name=$(basename "$d"); \
        if [ -f "$d/SKILL.md" ]; then \
            mkdir -p "internal/skills/catalog/$name"; \
            cp "$d/SKILL.md" "internal/skills/catalog/$name/SKILL.md"; \
        fi; \
    done
    @echo "Synced $$(ls internal/skills/catalog | wc -l) skills"

# Verify skills catalog is in sync (for CI)
check-skills:
    @just sync-skills > /dev/null 2>&1
    @git diff --exit-code internal/skills/catalog/ || (echo "Skills catalog out of sync — run 'just sync-skills'" && exit 1)

# Show the current version
version:
    @echo "{{version}} ({{commit}})"

# Run the agent with default config
run: build
    ./{{binary}} -config config/mitiga.toml

# Run the agent with debug logging
run-debug: build
    ./{{binary}} -config config/mitiga.toml -log-level debug
