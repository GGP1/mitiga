package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// LoadFromFile reads a TOML configuration file and decodes it into cfg.
// Fields not present in the file retain their current values (typically defaults).
func LoadFromFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read file %q: %w", path, err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("config: parse TOML %q: %w", path, err)
	}

	return nil
}

// Load builds a complete Config by applying the layered configuration model:
//
//  1. Start with hardcoded safe defaults
//  2. Overlay TOML configuration file (if it exists)
//  3. Overlay environment variables
//  4. Validate the final result
//
// CLI flags are applied by the caller after Load returns.
func Load(configPath string) (Config, error) {
	cfg := Default()

	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			if err := LoadFromFile(configPath, &cfg); err != nil {
				return Config{}, fmt.Errorf("config: load file: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return Config{}, fmt.Errorf("config: stat %q: %w", configPath, err)
		}
		// If the file doesn't exist, proceed with defaults only.
	}

	cfg.ApplyEnvironment()

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
