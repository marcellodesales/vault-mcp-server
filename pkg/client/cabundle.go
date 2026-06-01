// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

// VIASATIOCACertURL is the env var pointing at the Viasat private CA bundle to
// fetch when the local bundle file (VIASAT_IO_CACERT_FILE) is missing.
const VIASATIOCACertURL = "VIASAT_IO_CACERT_URL"

// CABootstrapStatus describes the state of the Viasat private CA bundle on disk.
type CABootstrapStatus struct {
	Enabled       bool
	File          string
	URL           string
	Exists        bool
	SizeBytes     int64
	UpdatedAt     string // file mtime (RFC3339), set when the file exists on disk
	LastFetchedAt string // set only when the file was fetched in this process run
}

// EnsurePrivateCARoot guarantees the Viasat private CA bundle is available on
// disk at VIASAT_IO_CACERT_FILE so TLS to vault.seceng-iam.viasat.io is trusted.
//
// If the file already exists it is reused as-is (no network call). Only when the
// file is missing is VIASAT_IO_CACERT_URL fetched. This keeps container restarts
// cheap and lets operators prime the bundle by mounting a host directory at
// /viasat/certs (e.g. via docker-compose `volumes:`). When neither the file nor
// URL is configured this is a no-op.
func EnsurePrivateCARoot(ctx context.Context, logger *log.Logger) (CABootstrapStatus, error) {
	file := getEnv(VIASATIOCACertFile, "")
	url := getEnv(VIASATIOCACertURL, "")

	status := CABootstrapStatus{
		Enabled: file != "" && url != "",
		File:    file,
		URL:     url,
	}
	statPopulate(&status)

	if !status.Enabled {
		if logger != nil {
			logger.Info("private ca root bootstrap disabled (VIASAT_IO_CACERT_FILE or VIASAT_IO_CACERT_URL not set)")
		}
		return status, nil
	}

	// Bundle already on disk — reuse without a network call.
	if status.Exists {
		if logger != nil {
			logger.WithFields(log.Fields{
				"path":       status.File,
				"size_bytes": status.SizeBytes,
				"updated_at": status.UpdatedAt,
				"refetched":  false,
			}).Info("private ca root ready")
		}
		return status, nil
	}

	// Bundle missing — fetch from the configured URL.
	if logger != nil {
		logger.WithFields(log.Fields{
			"path": status.File,
			"url":  status.URL,
		}).Info("private ca root missing, fetching from url")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return status, fmt.Errorf("build viasat ca request: %w", err)
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return status, fmt.Errorf("fetch viasat ca bundle: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return status, fmt.Errorf("fetch viasat ca bundle: unexpected status %s", resp.Status)
	}

	pemBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return status, fmt.Errorf("read viasat ca bundle: %w", err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		return status, fmt.Errorf("viasat ca bundle at %s did not contain PEM certificates", url)
	}

	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return status, fmt.Errorf("create viasat ca directory: %w", err)
	}

	// Write atomically via a temp file + rename.
	tmp, err := os.CreateTemp(filepath.Dir(file), "viasat-io-cacert-*.pem")
	if err != nil {
		return status, fmt.Errorf("create temp viasat ca file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(pemBytes); err != nil {
		return status, fmt.Errorf("write viasat ca bundle: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		return status, fmt.Errorf("chmod viasat ca bundle: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return status, fmt.Errorf("close viasat ca bundle: %w", err)
	}
	if err := os.Rename(tmpPath, file); err != nil {
		return status, fmt.Errorf("install viasat ca bundle: %w", err)
	}
	cleanup = false

	status.LastFetchedAt = time.Now().UTC().Format(time.RFC3339)
	statPopulate(&status)

	if logger != nil {
		logger.WithFields(log.Fields{
			"path":       status.File,
			"size_bytes": status.SizeBytes,
			"updated_at": status.UpdatedAt,
			"refetched":  true,
		}).Info("private ca root fetched")
	}

	return status, nil
}

func statPopulate(status *CABootstrapStatus) {
	if status.File == "" {
		return
	}
	if info, err := os.Stat(status.File); err == nil {
		status.Exists = true
		status.SizeBytes = info.Size()
		status.UpdatedAt = info.ModTime().UTC().Format(time.RFC3339)
	}
}
