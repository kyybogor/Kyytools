package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kyytools/kyytools/internal/models"
	"github.com/kyytools/kyytools/internal/storage"
)

func TestStorage_CRUD(t *testing.T) {
	tempDB := filepath.Join(t.TempDir(), "test_kyytools.db")
	defer os.Remove(tempDB)

	store, err := storage.NewStorage(tempDB)
	if err != nil {
		t.Fatalf("gagal membuat storage pengujian: %v", err)
	}
	defer store.Close()

	// 1. Target Save
	target := &models.Target{
		RawInput:     "example.com",
		Type:         models.TargetTypeDomain,
		Host:         "example.com",
		Port:         443,
		Scheme:       "https",
		ResolvedIPs:  []string{"93.184.216.34"},
		CanonicalURL: "https://example.com",
		CreatedAt:    time.Now(),
	}

	targetID, err := store.SaveTarget(target)
	if err != nil || targetID == 0 {
		t.Fatalf("gagal menyimpan target: %v", err)
	}

	// 2. Scan Create & Update
	scan := &models.Scan{
		TargetID:    targetID,
		TargetHost:  target.Host,
		TargetType:  string(target.Type),
		ProfileName: "quick",
		Status:      models.ScanStatusRunning,
		StartTime:   time.Now(),
		CreatedAt:   time.Now(),
	}

	scanID, err := store.CreateScan(scan)
	if err != nil || scanID == 0 {
		t.Fatalf("gagal membuat sesi scan: %v", err)
	}

	// 3. Save Finding
	finding := &models.Finding{
		ScanID:             scanID,
		ModuleName:         "test_module",
		Title:              "Test Vulnerability",
		Description:        "Deskripsi pengujian",
		Severity:           models.SeverityMedium,
		Confidence:         models.ConfidenceCertain,
		Host:               target.Host,
		Port:               443,
		VerificationStatus: "VERIFIED",
		CreatedAt:          time.Now(),
	}

	findingID, err := store.SaveFinding(finding)
	if err != nil || findingID == 0 {
		t.Fatalf("gagal menyimpan temuan: %v", err)
	}

	// 4. Update Scan Status & Counts
	err = store.UpdateScanCounts(scanID, 0, 0, 1, 0, 0, 1)
	if err != nil {
		t.Fatalf("gagal update scan counts: %v", err)
	}

	err = store.UpdateScanStatus(scanID, models.ScanStatusCompleted, 1500, 4.5, "")
	if err != nil {
		t.Fatalf("gagal update scan status: %v", err)
	}

	// 5. Query Scan & Findings
	retrievedScan, err := store.GetScanByID(scanID)
	if err != nil {
		t.Fatalf("gagal mengambil scan by ID: %v", err)
	}

	if retrievedScan.Status != models.ScanStatusCompleted || retrievedScan.FindingsCount != 1 {
		t.Errorf("data scan tidak sesuai: status=%s, findings=%d", retrievedScan.Status, retrievedScan.FindingsCount)
	}

	findingsList, err := store.GetFindingsByScanID(scanID)
	if err != nil || len(findingsList) != 1 {
		t.Fatalf("gagal mengambil temuan scan: %v, count=%d", err, len(findingsList))
	}

	if findingsList[0].Title != "Test Vulnerability" {
		t.Errorf("judul temuan tidak sesuai: %s", findingsList[0].Title)
	}

	// 6. List Scans
	list, err := store.ListScans(10)
	if err != nil || len(list) != 1 {
		t.Fatalf("gagal list scans: %v, count=%d", err, len(list))
	}
}
