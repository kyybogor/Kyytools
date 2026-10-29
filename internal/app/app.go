package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kyybogor/Kyytools/internal/cli"
	"github.com/kyybogor/Kyytools/internal/config"
	"github.com/kyybogor/Kyytools/internal/models"
	"github.com/kyybogor/Kyytools/internal/safety"
	"github.com/kyybogor/Kyytools/internal/scanner"
	"github.com/kyybogor/Kyytools/internal/storage"
	"github.com/kyybogor/Kyytools/internal/target"
)

// App is the root coordinator of KyyTools Security Scanner.
type App struct {
	Config  *models.AppConfig
	Storage *storage.Storage
	Engine  *scanner.Engine
}

// Run boots up the application lifecycle.
func Run(args []string) error {
	// 1. Setup graceful cancellation context on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 2. Load Configuration
	cfg, err := config.LoadConfig("configs/config.yaml")
	if err != nil {
		return fmt.Errorf("kesalahan inisialisasi konfigurasi: %w", err)
	}

	// 3. Initialize SQLite Storage
	store, err := storage.NewStorage(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("kesalahan inisialisasi database SQLite: %w", err)
	}
	defer store.Close()

	// 4. Initialize Safety Guardrails & Target Parser
	scopeVal := safety.NewScopeValidator(cfg.Scope)
	parser := target.NewParser(scopeVal)

	// 5. Initialize Scanner Engine
	engine := scanner.NewEngine(cfg, store, scopeVal)

	// 6. Bundle services and invoke CLI router
	services := &cli.AppServices{
		Config:  cfg,
		Storage: store,
		Parser:  parser,
		Engine:  engine,
	}

	cli.StartCLI(ctx, services, args)
	return nil
}
