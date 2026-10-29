package tests

import (
	"testing"

	"github.com/kyytools/kyytools/internal/models"
	"github.com/kyytools/kyytools/internal/risk"
)

func TestRiskScore_Calculations(t *testing.T) {
	// 1. Empty findings -> score 0.0, SECURE
	score, level := risk.CalculateScore([]models.Finding{})
	if score != 0.0 || level != risk.RiskLevelSecure {
		t.Errorf("diharapkan score 0.0 dan SECURE untuk temuan kosong, didapat %.1f dan %s", score, level)
	}

	// 2. Critical finding -> level CRITICAL
	findingsCrit := []models.Finding{
		{
			Severity:   models.SeverityCritical,
			Confidence: models.ConfidenceCertain,
		},
	}
	scoreCrit, levelCrit := risk.CalculateScore(findingsCrit)
	if levelCrit != risk.RiskLevelCritical {
		t.Errorf("diharapkan level CRITICAL untuk temuan critical, didapat %s", levelCrit)
	}
	if scoreCrit < 2.0 {
		t.Errorf("skor risiko tidak wajar untuk temuan critical: %.1f", scoreCrit)
	}

	// 3. Info and Low findings -> level LOW
	findingsLow := []models.Finding{
		{Severity: models.SeverityLow, Confidence: models.ConfidenceFirm},
		{Severity: models.SeverityInfo, Confidence: models.ConfidenceCertain},
	}
	_, levelLow := risk.CalculateScore(findingsLow)
	if levelLow != risk.RiskLevelLow {
		t.Errorf("diharapkan level LOW, didapat %s", levelLow)
	}
}
