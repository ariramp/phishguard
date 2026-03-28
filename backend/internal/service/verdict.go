package service

type PredictionSignals struct {
	URLScore              float64
	TextScore             float64
	TrustedDomain         bool
	HasIPHost             bool
	HasPunycode           bool
	HasAtSymbol           bool
	HasShortener          bool
	SuspiciousKeywordCount int
	BrandSimilarity       float64
}

func DetermineVerdict(score float32, risk int16, features map[string]any) string {
	signals := extractPredictionSignals(score, features)

	dangerousURL := signals.HasIPHost ||
		signals.HasPunycode ||
		signals.HasAtSymbol ||
		signals.HasShortener

	strongURLEvidence := signals.URLScore >= 0.9 ||
		(signals.URLScore >= 0.78 && (dangerousURL || signals.BrandSimilarity >= 0.92)) ||
		(signals.URLScore >= 0.72 && signals.SuspiciousKeywordCount >= 2)

	trustedAndClean := signals.TrustedDomain &&
		!dangerousURL &&
		signals.SuspiciousKeywordCount == 0 &&
		signals.BrandSimilarity < 0.9

	if strongURLEvidence {
		return "phishing"
	}

	if trustedAndClean && signals.URLScore < 0.7 {
		return "safe"
	}

	if signals.URLScore >= 0.58 || risk >= 2 || score >= 0.62 || signals.TextScore >= 0.9 {
		return "suspicious"
	}

	return "safe"
}

func extractPredictionSignals(score float32, features map[string]any) PredictionSignals {
	signals := PredictionSignals{
		URLScore: float64(score),
	}

	if components, ok := nestedMap(features, "components"); ok {
		if value, ok := asFloat(components["url_score"]); ok {
			signals.URLScore = value
		}
		if value, ok := asFloat(components["text_score"]); ok {
			signals.TextScore = value
		}
	}

	if urlFeatures, ok := nestedMap(features, "url_features"); ok {
		signals.TrustedDomain = asBoolish(urlFeatures["trusted_domain"])
		signals.HasIPHost = asBoolish(urlFeatures["has_ip_host"])
		signals.HasPunycode = asBoolish(urlFeatures["has_punycode"])
		signals.HasAtSymbol = asBoolish(urlFeatures["has_at_symbol"])
		signals.HasShortener = asBoolish(urlFeatures["has_shortener"])
		if value, ok := asInt(urlFeatures["suspicious_keyword_count"]); ok {
			signals.SuspiciousKeywordCount = value
		}
		if value, ok := asFloat(urlFeatures["brand_similarity"]); ok {
			signals.BrandSimilarity = value
		}
	}

	return signals
}

func nestedMap(input map[string]any, key string) (map[string]any, bool) {
	value, ok := input[key]
	if !ok {
		return nil, false
	}
	typed, ok := value.(map[string]any)
	return typed, ok
}

func asFloat(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	default:
		return 0, false
	}
}

func asInt(value any) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case float32:
		return int(v), true
	default:
		return 0, false
	}
}

func asBoolish(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case int:
		return v != 0
	case int16:
		return v != 0
	case int32:
		return v != 0
	case int64:
		return v != 0
	case float64:
		return v != 0
	case float32:
		return v != 0
	default:
		return false
	}
}
