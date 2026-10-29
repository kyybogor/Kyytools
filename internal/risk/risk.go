package risk

import (
	"strings"

	"github.com/kyytools/kyytools/internal/models"
)

// Severity weights for aggregate risk scoring.
const (
	WeightCritical = 10.0
	WeightHigh     = 7.5
	WeightMedium   = 4.5
	WeightLow      = 2.0
	WeightInfo     = 0.5
)

// Confidence multipliers.
const (
	MultiplierCertain   = 1.0
	MultiplierFirm      = 0.8
	MultiplierTentative = 0.5
)

// RiskLevel represents an overall evaluation label.
type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "CRITICAL"
	RiskLevelHigh     RiskLevel = "HIGH"
	RiskLevelMedium   RiskLevel = "MEDIUM"
	RiskLevelLow      RiskLevel = "LOW"
	RiskLevelSecure   RiskLevel = "SECURE"
)

// CalculateScore computes an overall risk score (0.0 to 10.0) based on findings, severities, and confidence.
func CalculateScore(findings []models.Finding) (score float64, level RiskLevel) {
	if len(findings) == 0 {
		return 0.0, RiskLevelSecure
	}

	var rawScore float64
	hasCritical := false
	hasHigh := false

	for _, f := range findings {
		var baseWeight float64
		switch f.Severity {
		case models.SeverityCritical:
			baseWeight = WeightCritical
			hasCritical = true
		case models.SeverityHigh:
			baseWeight = WeightHigh
			hasHigh = true
		case models.SeverityMedium:
			baseWeight = WeightMedium
		case models.SeverityLow:
			baseWeight = WeightLow
		case models.SeverityInfo:
			baseWeight = WeightInfo
		default:
			baseWeight = 0.0
		}

		var mult float64
		switch f.Confidence {
		case models.ConfidenceCertain:
			mult = MultiplierCertain
		case models.ConfidenceFirm:
			mult = MultiplierFirm
		case models.ConfidenceTentative:
			mult = MultiplierTentative
		default:
			mult = MultiplierFirm
		}

		rawScore += baseWeight * mult
	}

	// Normalize score: 0 to 10.0 scale with logarithmic dampening for high finding volume
	if rawScore > 50.0 {
		score = 9.0 + (rawScore-50.0)/(rawScore+100.0)
	} else {
		score = rawScore / 5.0
	}

	if score > 10.0 {
		score = 10.0
	}

	// Determine overall risk level
	if hasCritical || score >= 8.5 {
		level = RiskLevelCritical
	} else if hasHigh || score >= 6.0 {
		level = RiskLevelHigh
	} else if score >= 3.5 {
		level = RiskLevelMedium
	} else if score > 0.0 {
		level = RiskLevelLow
	} else {
		level = RiskLevelSecure
	}

	// Round to 1 decimal place
	score = float64(int(score*10+0.5)) / 10

	return score, level
}

// NormalizeSeverity safely maps string values to typed Severity.
func NormalizeSeverity(val string) models.Severity {
	switch strings.ToUpper(strings.TrimSpace(val)) {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH":
		return models.SeverityHigh
	case "MEDIUM":
		return models.SeverityMedium
	case "LOW":
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

// NormalizeConfidence safely maps string values to typed Confidence.
func NormalizeConfidence(val string) models.Confidence {
	switch strings.ToUpper(strings.TrimSpace(val)) {
	case "CERTAIN":
		return models.ConfidenceCertain
	case "TENTATIVE":
		return models.ConfidenceTentative
	default:
		return models.ConfidenceFirm
	}
}
