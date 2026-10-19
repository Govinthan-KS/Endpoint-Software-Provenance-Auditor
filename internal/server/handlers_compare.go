package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/example/appaudit/internal/application"
	"github.com/example/appaudit/internal/provenance"
)

// CompareEngineResult holds individual engine output in comparison benchmark mode.
type CompareEngineResult struct {
	Mode               string         `json:"mode"`
	DisplayName        string         `json:"display_name"`
	Classification     string         `json:"classification"`
	RawClassification  string         `json:"raw_classification"`
	Confidence         string         `json:"confidence"`
	VerificationSource string         `json:"verification_source"`
	Summary            string         `json:"summary"`
	LatencyMs          float64        `json:"latency_ms"`
	Privacy            string         `json:"privacy"`
	IsFastest          bool           `json:"is_fastest"`
	AIError            string         `json:"ai_error,omitempty"`
	StageNumber        int            `json:"stage_number"`
	StageName          string         `json:"stage_name"`
	AIBypassed         bool           `json:"ai_bypassed"`
	ExitLayer          string         `json:"exit_layer"`
	TokenEconomics     TokenEconomics `json:"token_economics"`
	SearchGrounded     bool           `json:"search_grounded"`
	DegradationWarning string         `json:"degradation_warning,omitempty"`
	SearchWarning      string         `json:"search_warning,omitempty"`
	ReadError          string         `json:"read_error,omitempty"`
}

// CompareResponse represents the side-by-side engine benchmark outcome.
type CompareResponse struct {
	Name                 string                `json:"name"`
	SHA256               string                `json:"sha256"`
	SizeBytes            int64                 `json:"size_bytes"`
	Agreement            bool                  `json:"agreement"`
	ConsensusVerdict     string                `json:"consensus_verdict"`
	DiscrepancyDetected  bool                  `json:"discrepancy_detected"`
	EfficiencyWinner     string                `json:"efficiency_winner"`
	Takeaway             string                `json:"takeaway"`
	TokenSavingsTakeaway string                `json:"token_savings_takeaway,omitempty"`
	ProviderErrors       []string              `json:"provider_errors,omitempty"`
	ScanWarnings         []string              `json:"scan_warnings,omitempty"`
	Engines              []CompareEngineResult `json:"engines"`
}

// CompareEngineScanSummary encapsulates the outcome of an engine across a multi-application scan.
type CompareEngineScanSummary struct {
	Mode                 string               `json:"mode"`
	DisplayName          string               `json:"display_name"`
	LatencyMs            float64              `json:"latency_ms"`
	ThirdPartyCount      int                  `json:"third_party_count"`
	InHouseCount         int                  `json:"in_house_count"`
	UnverifiedCount      int                  `json:"unverified_count"`
	StaticEarlyExitCount int                  `json:"static_early_exit_count"`
	AIEngagedCount       int                  `json:"ai_engaged_count"`
	Economics            ScanEconomicsSummary `json:"economics"`
	IsFastest            bool                 `json:"is_fastest"`
}

// MultiAppCompareItem encapsulates cross-engine consensus for a single software package.
type MultiAppCompareItem struct {
	Name              string                       `json:"name"`
	Path              string                       `json:"path"`
	SHA256            string                       `json:"sha256"`
	Agreement         bool                         `json:"agreement"`
	ConsensusVerdict  string                       `json:"consensus_verdict"`
	RawClassification string                       `json:"raw_classification,omitempty"`
	Discrepancy       bool                         `json:"discrepancy"`
	EngineVerdicts    map[string]ScannedAppSummary `json:"engine_verdicts"`
}

// MultiAppCompareResponse represents the multi-engine comparison benchmark across discovered applications.
type MultiAppCompareResponse struct {
	ScanType             string                     `json:"scan_type"`
	Target               string                     `json:"target"`
	TotalScanned         int                        `json:"total_scanned"`
	Modes                []string                   `json:"modes"`
	DurationMs           float64                    `json:"duration_ms"`
	EfficiencyWinner     string                     `json:"efficiency_winner"`
	ConsensusRate        float64                    `json:"consensus_rate,omitempty"`
	AgreementCount       int                        `json:"agreement_count"`
	DiscrepancyCount     int                        `json:"discrepancy_count"`
	StaticEarlyExitCount int                        `json:"static_early_exit_count"`
	Takeaway             string                     `json:"takeaway"`
	TokenSavingsTakeaway string                     `json:"token_savings_takeaway"`
	ProviderErrors       []string                   `json:"provider_errors,omitempty"`
	ScanWarnings         []string                   `json:"scan_warnings,omitempty"`
	DegradedCIRCL        bool                       `json:"degraded_circl,omitempty"`
	CIRCLSkippedCount    int                        `json:"circl_skipped_count,omitempty"`
	EngineSummaries      []CompareEngineScanSummary `json:"engine_summaries"`
	Applications         []MultiAppCompareItem      `json:"applications"`
}

// handleAuditCompare runs a head-to-head evaluation of a single uploaded binary across multiple engines.
func (s *Server) handleAuditCompare(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := r.RemoteAddr

	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed. Use POST."})
		s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusMethodNotAllowed, time.Since(start), "Invalid method")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
	if err := r.ParseMultipartForm(32 * 1024 * 1024); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Failed to parse upload for comparison"})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Missing 'file' field for engine comparison"})
		return
	}
	defer file.Close()

	modes := parseComparisonModes(r)
	if len(modes) < 2 {
		modes = []string{"none", "gemini"}
	}

	if err := s.validateEngineKeys("", modes); err != nil {
		s.logError("Comparison rejected: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"code":   "API_KEY_REQUIRED",
		})
		s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusBadRequest, time.Since(start), "API key required")
		return
	}

	s.logDetail("Starting head-to-head comparison on %q across %d engines: %s",
		header.Filename, len(modes), strings.Join(modes, ", "))

	tempFile, err := os.CreateTemp("", "appaudit-compare-*.exe")
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Internal error saving comparison binary"})
		return
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	defer tempFile.Close()

	if _, err := io.Copy(tempFile, file); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Failed to stream binary for comparison"})
		return
	}
	_ = tempFile.Close()

	var results []CompareEngineResult
	minLatency := 99999999.0
	fastestIdx := -1
	primarySHA256 := ""
	firstVerdict := ""
	allAgree := true
	hasErrors := false

	for _, m := range modes {
		privacy := "Local Offline (0 egress bytes)"
		if m == "gemini" || m == "deepseek" {
			privacy = "Cloud API Roundtrip"
		}

		eng, engErr := s.buildEngineForMode(r.Context(), m)
		if engErr != nil {
			hasErrors = true
			results = append(results, CompareEngineResult{
				Mode:               m,
				DisplayName:        getModeDisplayName(m),
				Classification:     "Connection Failed",
				RawClassification:  "ERROR",
				Confidence:         "0%",
				VerificationSource: "Service Offline",
				Summary:            fmt.Sprintf("Failed to initialize engine %s: %v. Please verify the service is running.", getModeDisplayName(m), engErr),
				LatencyMs:          0.0,
				Privacy:            privacy,
				AIError:            engErr.Error(),
			})
			continue
		}
		mStart := time.Now()
		app, mErr := eng.InspectSingleBinary(tempPath, header.Filename)
		mLat := float64(time.Since(mStart).Microseconds()) / 1000.0

		if mErr != nil {
			hasErrors = true
			results = append(results, CompareEngineResult{
				Mode:               m,
				DisplayName:        getModeDisplayName(m),
				Classification:     "Analysis Error",
				RawClassification:  "ERROR",
				Confidence:         "0%",
				VerificationSource: "Engine Error",
				Summary:            fmt.Sprintf("Error during %s analysis: %v", getModeDisplayName(m), mErr),
				LatencyMs:          mLat,
				Privacy:            privacy,
				AIError:            mErr.Error(),
			})
			continue
		}

		if primarySHA256 == "" {
			primarySHA256 = app.PrimarySHA256()
		}

		rawClass := string(app.Classification)
		if app.Classification == provenance.ClassificationCompany {
			rawClass = "IN_HOUSE"
		}
		if firstVerdict == "" {
			firstVerdict = rawClass
		} else if rawClass != firstVerdict {
			allAgree = false
		}

		if mLat < minLatency {
			minLatency = mLat
			fastestIdx = len(results)
		}

		tier := determineTriageTier(app)
		sourceLabel := FormatVerificationSource(tier, app.Reasons, app.SearchGrounded)
		classLabel := FormatClassification(app.Classification)
		confLabel := FormatConfidence(app.Confidence)
		summary := FormatSummaryOfFindings(app)

		stageNum, stageName, aiBypassed, exitLayer, _ := determineStageInfo(tier, app)
		tokenEcon := computeTokenEconomics(app, m, aiBypassed)

		results = append(results, CompareEngineResult{
			Mode:               m,
			DisplayName:        getModeDisplayName(m),
			Classification:     classLabel,
			RawClassification:  rawClass,
			Confidence:         confLabel,
			VerificationSource: sourceLabel,
			Summary:            summary,
			LatencyMs:          math.Round(mLat*10) / 10,
			Privacy:            privacy,
			AIError:            app.AIError,
			StageNumber:        stageNum,
			StageName:          stageName,
			AIBypassed:         aiBypassed,
			ExitLayer:          exitLayer,
			TokenEconomics:     tokenEcon,
			SearchGrounded:     app.SearchGrounded,
			DegradationWarning: app.DegradationWarning,
			ReadError:          app.ReadError,
		})
	}

	if hasErrors {
		allAgree = false
	}

	efficiencyWinner := "None"
	if fastestIdx >= 0 && fastestIdx < len(results) {
		results[fastestIdx].IsFastest = true
		efficiencyWinner = results[fastestIdx].DisplayName
	}

	consensusVerdict := FormatClassification(provenance.Classification(firstVerdict))
	if hasErrors {
		consensusVerdict = "Incomplete (Engine Failure)"
	} else if !allAgree {
		consensusVerdict = "Discrepancy Detected"
	}

	takeaway := generateComparisonTakeaway(results, allAgree, fastestIdx)
	tokenTakeaway := generateTokenSavingsTakeaway(results)

	var compProvErrors []string
	var compScanWarnings []string
	for _, res := range results {
		if res.AIError != "" {
			compProvErrors = append(compProvErrors, fmt.Sprintf("%s: %s", res.DisplayName, NormalizeProviderError(res.AIError)))
		}
		if !res.SearchGrounded && (res.Mode == "gemini" || res.Mode == "ollama" || res.Mode == "deepseek") && res.RawClassification != "ERROR" && res.RawClassification != "UNKNOWN" {
			if res.DegradationWarning != "" {
				compScanWarnings = append(compScanWarnings, fmt.Sprintf("%s: %s", res.DisplayName, res.DegradationWarning))
			} else {
				compScanWarnings = append(compScanWarnings, fmt.Sprintf("%s: Evaluated from model memory without live web search grounding.", res.DisplayName))
			}
		}
		if res.ReadError != "" {
			compScanWarnings = append(compScanWarnings, "File inspection halted: "+res.ReadError)
		}
	}

	compareResp := CompareResponse{
		Name:                 header.Filename,
		SHA256:               primarySHA256,
		SizeBytes:            header.Size,
		Agreement:            allAgree,
		ConsensusVerdict:     consensusVerdict,
		DiscrepancyDetected:  !allAgree,
		EfficiencyWinner:     efficiencyWinner,
		Takeaway:             takeaway,
		TokenSavingsTakeaway: tokenTakeaway,
		ProviderErrors:       compProvErrors,
		ScanWarnings:         compScanWarnings,
		Engines:              results,
	}

	s.logSuccess("Comparison complete for %q: Agreement=%v | Winner=%s in %.1fms total",
		header.Filename, allAgree, efficiencyWinner, float64(time.Since(start).Microseconds())/1000.0)
	s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusOK, time.Since(start),
		fmt.Sprintf("Compare (%d modes) -> Agreement: %v", len(modes), allAgree))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(compareResp)
}

func (s *Server) runMultiAppCompare(ctx context.Context, scanType, target string, modes []string, rawInputs []application.RawInput, start time.Time) MultiAppCompareResponse {
	var engineSummaries []CompareEngineScanSummary
	engineVerdicts := make(map[string]map[string]ScannedAppSummary)

	minLatency := 999999999.0
	fastestIdx := 0

	triageStart := time.Now()
	baseEng, baseErr := s.buildEngineForMode(ctx, "none")
	var baseApps []application.Application
	if baseErr != nil {
		s.logWarn("Base deterministic engine init failed: %v", baseErr)
		baseApps = make([]application.Application, len(rawInputs))
		for rIdx, rIn := range rawInputs {
			baseApps[rIdx] = application.Application{
				Name:             rIn.Name,
				Classification:   provenance.ClassificationUnknown,
				Confidence:       provenance.ConfidenceNone,
				ResolutionSource: "triage_error",
				AIError:          baseErr.Error(),
				Reasons:          []string{fmt.Sprintf("Base triage failed to initialize: %v", baseErr)},
			}
		}
	} else {
		baseApps = baseEng.ProcessRaw(ctx, rawInputs)
	}
	baseTriageDuration := time.Since(triageStart)

	var unresolvedIndices []int
	for i := range baseApps {
		if baseApps[i].Classification == "" || baseApps[i].Classification == provenance.ClassificationUnknown {
			unresolvedIndices = append(unresolvedIndices, i)
		}
	}

	canonicalAppOrder := cloneApplications(baseApps)

	for idx, m := range modes {
		mStart := time.Now()
		apps := cloneApplications(baseApps)

		if m != "none" && len(unresolvedIndices) > 0 {
			eng, engErr := s.buildEngineForMode(ctx, m)
			if engErr != nil {
				s.logWarn("Multi-engine compare init failed for %s: %v", m, engErr)
				for _, uIdx := range unresolvedIndices {
					apps[uIdx].ResolutionSource = m + "_error"
					apps[uIdx].AIError = engErr.Error()
					apps[uIdx].Reasons = append(apps[uIdx].Reasons, fmt.Sprintf("Engine %s failed to initialize: %v", m, engErr))
				}
			} else {
				candidatePtrs := make([]*application.Application, len(unresolvedIndices))
				for k, uIdx := range unresolvedIndices {
					candidatePtrs[k] = &apps[uIdx]
				}
				eng.ClassifyBatch(ctx, candidatePtrs)
			}
		}

		mDuration := time.Since(mStart)
		if m == "none" {
			mDuration += baseTriageDuration
		}
		mLat := float64(mDuration.Microseconds()) / 1000.0

		sort.Slice(apps, func(i, j int) bool {
			if apps[i].Classification != apps[j].Classification {
				return apps[i].Classification < apps[j].Classification
			}
			return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name)
		})

		if mLat < minLatency {
			minLatency = mLat
			fastestIdx = idx
		}

		tpCount := 0
		ihCount := 0
		unkCount := 0
		staticEarlyExits := 0
		aiEngaged := 0
		totalPrompt := 0
		totalCompletion := 0
		totalConsumed := 0
		totalSaved := 0

		appMap := make(map[string]ScannedAppSummary)

		for _, a := range apps {
			tier := determineTriageTier(&a)
			sourceLabel := FormatVerificationSource(tier, a.Reasons, a.SearchGrounded)
			classLabel := FormatClassification(a.Classification)
			confLabel := FormatConfidence(a.Confidence)
			summary := FormatSummaryOfFindings(&a)

			rawClass := string(a.Classification)
			switch a.Classification {
			case provenance.ClassificationCompany:
				rawClass = "IN_HOUSE"
				ihCount++
			case provenance.ClassificationThirdParty:
				tpCount++
			default:
				unkCount++
			}

			p := a.PrimaryBinaryPath
			if p == "" && len(a.Binaries) > 0 {
				p = a.Binaries[0].Path
			}

			stageNum, stageName, aiBypassed, exitLayer, _ := determineStageInfo(tier, &a)
			tokenEcon := computeTokenEconomics(&a, m, aiBypassed)

			if aiBypassed {
				staticEarlyExits++
				totalSaved += tokenEcon.TokensSaved
			} else {
				aiEngaged++
				totalPrompt += tokenEcon.PromptTokens
				totalCompletion += tokenEcon.CompletionTokens
				totalConsumed += tokenEcon.TotalTokens
			}

			summaryObj := ScannedAppSummary{
				Name:               a.Name,
				Path:               MaskPII(p),
				SHA256:             a.PrimarySHA256(),
				Classification:     classLabel,
				RawClassification:  rawClass,
				Confidence:         confLabel,
				VerificationSource: sourceLabel,
				Summary:            summary,
				StageNumber:        stageNum,
				StageName:          stageName,
				AIBypassed:         aiBypassed,
				ExitLayer:          exitLayer,
				TokenEconomics:     tokenEcon,
				SearchGrounded:     a.SearchGrounded,
				DegradationWarning: a.DegradationWarning,
				ReadError:          a.ReadError,
				AIError:            a.AIError,
				Reasons:            maskReasons(a.Reasons),
			}

			key := p
			if key == "" {
				key = a.Name + ":" + a.PrimarySHA256()
			}
			appMap[key] = summaryObj
		}

		engineVerdicts[m] = appMap

		savingsPct := 100.0
		if len(apps) > 0 {
			savingsPct = math.Round((float64(staticEarlyExits)/float64(len(apps)))*1000) / 10
		}

		var costUSD float64
		var costFormatted string
		switch m {
		case "ollama":
			costFormatted = "$0.0000 (Local Compute)"
		case "deepseek":
			costUSD = (float64(totalPrompt)*0.00000014 + float64(totalCompletion)*0.00000028)
			costFormatted = fmt.Sprintf("$%.4f", costUSD)
		default:
			costUSD = (float64(totalPrompt)*0.000000075 + float64(totalCompletion)*0.00000030)
			costFormatted = fmt.Sprintf("$%.4f", costUSD)
		}

		engineSummaries = append(engineSummaries, CompareEngineScanSummary{
			Mode:                 m,
			DisplayName:          getModeDisplayName(m),
			LatencyMs:            math.Round(mLat*10) / 10,
			ThirdPartyCount:      tpCount,
			InHouseCount:         ihCount,
			UnverifiedCount:      unkCount,
			StaticEarlyExitCount: staticEarlyExits,
			AIEngagedCount:       aiEngaged,
			Economics: ScanEconomicsSummary{
				TotalPromptTokens:     totalPrompt,
				TotalCompletionTokens: totalCompletion,
				TotalTokensConsumed:   totalConsumed,
				TotalTokensSaved:      totalSaved,
				StaticEarlyExitCount:  staticEarlyExits,
				AIEngagedCount:        aiEngaged,
				EstimatedCostUSD:      costUSD,
				FormattedCost:         costFormatted,
				SavingsPercentage:     savingsPct,
			},
		})
	}

	if len(engineSummaries) > 0 && fastestIdx < len(engineSummaries) {
		engineSummaries[fastestIdx].IsFastest = true
	}

	efficiencyWinner := getModeDisplayName(modes[fastestIdx])

	var comparedApps []MultiAppCompareItem
	discrepancyCount := 0

	for _, a := range canonicalAppOrder {
		p := a.PrimaryBinaryPath
		if p == "" && len(a.Binaries) > 0 {
			p = a.Binaries[0].Path
		}
		key := p
		if key == "" {
			key = a.Name + ":" + a.PrimarySHA256()
		}

		verdicts := make(map[string]ScannedAppSummary)
		firstClass := ""
		appAgree := true

		for _, m := range modes {
			if sObj, ok := engineVerdicts[m][key]; ok {
				verdicts[m] = sObj
				if firstClass == "" {
					firstClass = sObj.RawClassification
				} else if sObj.RawClassification != firstClass {
					appAgree = false
				}
			}
		}

		consensusVerdict := "Discrepancy"
		rawConsensus := "DISCREPANCY"
		if appAgree && firstClass != "" {
			consensusVerdict = FormatClassification(provenance.Classification(firstClass))
			rawConsensus = firstClass
		} else {
			discrepancyCount++
		}

		comparedApps = append(comparedApps, MultiAppCompareItem{
			Name:              a.Name,
			Path:              MaskPII(p),
			SHA256:            a.PrimarySHA256(),
			Agreement:         appAgree,
			ConsensusVerdict:  consensusVerdict,
			RawClassification: rawConsensus,
			Discrepancy:       !appAgree,
			EngineVerdicts:    verdicts,
		})
	}

	totalScanned := len(comparedApps)
	agreementCount := totalScanned - discrepancyCount
	consensusRate := 100.0
	if totalScanned > 0 {
		consensusRate = math.Round((float64(agreementCount)/float64(totalScanned))*1000) / 10
	}

	staticEarlyExitCount := totalScanned - len(unresolvedIndices)
	var providerErrors []string
	provErrSet := make(map[string]bool)
	var scanWarnings []string
	scanWarningSet := make(map[string]bool)
	ungroundedCount := 0

	for engKey, ea := range engineVerdicts {
		isLocalEng := strings.EqualFold(engKey, "ollama") || strings.Contains(strings.ToLower(engKey), "ollama")
		for _, sObj := range ea {
			if sObj.AIError != "" {
				normErr := NormalizeProviderError(sObj.AIError)
				if !provErrSet[normErr] {
					provErrSet[normErr] = true
					providerErrors = append(providerErrors, normErr)
				}
			} else if strings.Contains(sObj.Summary, "AI evaluation could not complete") {
				normErr := NormalizeProviderError(sObj.Summary)
				if !provErrSet[normErr] {
					provErrSet[normErr] = true
					providerErrors = append(providerErrors, normErr)
				}
			}
			isLocalApp := isLocalEng || strings.Contains(strings.ToLower(sObj.VerificationSource), "local") || strings.Contains(strings.ToLower(sObj.VerificationSource), "ollama")
			if isLocalApp && !sObj.SearchGrounded && sObj.RawClassification != "UNKNOWN" && sObj.RawClassification != "ERROR" && sObj.ExitLayer != "Static Cryptographic Layer (Early Exit)" {
				ungroundedCount++
			}
			if sObj.ReadError != "" && !scanWarningSet[sObj.ReadError] {
				scanWarningSet[sObj.ReadError] = true
				scanWarnings = append(scanWarnings, fmt.Sprintf("File inspection halted on %s: %s", sObj.Name, sObj.ReadError))
			}
		}
	}

	if ungroundedCount > 0 {
		scanWarnings = append(scanWarnings, fmt.Sprintf("%d local AI application verdict(s) generated without live web search grounding (model memory only).", ungroundedCount))
	}

	degradedCIRCL := false
	circlSkipped := 0
	if baseEng != nil && baseEng.DecisionEngine() != nil && baseEng.DecisionEngine().HashLookupClient != nil {
		hl := baseEng.DecisionEngine().HashLookupClient
		if hl.IsDegraded() {
			degradedCIRCL = true
			circlSkipped = hl.SkippedCount()
			scanWarnings = append(scanWarnings, fmt.Sprintf("Tier 3 Hashlookup throttled (429) — %d files bypassed registry check", circlSkipped))
		}
	}

	takeaway := fmt.Sprintf("Benchmark evaluated %d software applications across %d engines. %s achieved fastest throughput (%.1f ms). Discrepancies detected: %d (%d agreed).",
		totalScanned, len(modes), efficiencyWinner, minLatency, discrepancyCount, agreementCount)

	tokenTakeaway := "Static layer zero-cost early exits eliminated cloud LLM roundtrips and preserved bandwidth for verified enterprise software."

	return MultiAppCompareResponse{
		ScanType:             scanType,
		Target:               MaskPII(target),
		TotalScanned:         totalScanned,
		Modes:                modes,
		DurationMs:           math.Round((float64(time.Since(start).Microseconds())/1000.0)*10) / 10,
		EfficiencyWinner:     efficiencyWinner,
		ConsensusRate:        consensusRate,
		AgreementCount:       agreementCount,
		DiscrepancyCount:     discrepancyCount,
		StaticEarlyExitCount: staticEarlyExitCount,
		Takeaway:             takeaway,
		TokenSavingsTakeaway: tokenTakeaway,
		ProviderErrors:       providerErrors,
		ScanWarnings:         scanWarnings,
		DegradedCIRCL:        degradedCIRCL,
		CIRCLSkippedCount:    circlSkipped,
		EngineSummaries:      engineSummaries,
		Applications:         comparedApps,
	}
}

func cloneApplication(a application.Application) application.Application {
	cp := a
	if a.Binaries != nil {
		cp.Binaries = make([]application.ApplicationBinary, len(a.Binaries))
		copy(cp.Binaries, a.Binaries)
	}
	if a.IdentityEvidence != nil {
		cp.IdentityEvidence = make([]provenance.Evidence, len(a.IdentityEvidence))
		copy(cp.IdentityEvidence, a.IdentityEvidence)
	}
	if a.OwnershipEvidence != nil {
		cp.OwnershipEvidence = make([]provenance.Evidence, len(a.OwnershipEvidence))
		copy(cp.OwnershipEvidence, a.OwnershipEvidence)
	}
	if a.Reasons != nil {
		cp.Reasons = make([]string, len(a.Reasons))
		copy(cp.Reasons, a.Reasons)
	}
	if a.Sources != nil {
		cp.Sources = make([]string, len(a.Sources))
		copy(cp.Sources, a.Sources)
	}
	return cp
}

func cloneApplications(apps []application.Application) []application.Application {
	res := make([]application.Application, len(apps))
	for i, a := range apps {
		res[i] = cloneApplication(a)
	}
	return res
}

func parseComparisonModes(r *http.Request) []string {
	var modes []string

	rawModes := r.FormValue("modes")
	if rawModes != "" {
		var list []string
		if err := json.Unmarshal([]byte(rawModes), &list); err == nil && len(list) > 0 {
			modes = list
		} else {
			for _, part := range strings.Split(rawModes, ",") {
				if t := strings.TrimSpace(part); t != "" {
					modes = append(modes, t)
				}
			}
		}
	}

	if len(modes) == 0 && r.MultipartForm != nil {
		if list, ok := r.MultipartForm.Value["modes"]; ok {
			for _, item := range list {
				if t := strings.TrimSpace(item); t != "" {
					modes = append(modes, t)
				}
			}
		}
	}

	var cleaned []string
	for _, m := range modes {
		nm := strings.ToLower(strings.TrimSpace(m))
		if nm != "" {
			cleaned = append(cleaned, nm)
		}
	}

	return cleaned
}

func getModeDisplayName(m string) string {
	switch strings.ToLower(m) {
	case "none":
		return "Deterministic Only"
	case "ollama":
		return "Ollama (Local AI)"
	case "gemini":
		return "Gemini (Cloud Grounded)"
	case "deepseek":
		return "DeepSeek (Cloud Reasoning)"
	default:
		return m
	}
}

func generateComparisonTakeaway(results []CompareEngineResult, allAgree bool, fastestIdx int) string {
	if len(results) == 0 {
		return "Comparison complete."
	}

	hasErrors := false
	for _, r := range results {
		if r.AIError != "" || r.RawClassification == "ERROR" {
			hasErrors = true
			break
		}
	}
	if hasErrors {
		return "Comparison could not reach full consensus because one or more engines encountered an error or were offline. Review individual engine cards below for details."
	}

	if fastestIdx < 0 || fastestIdx >= len(results) {
		return "Comparison complete."
	}

	fastest := results[fastestIdx]

	if allAgree {
		if fastest.Mode == "none" && len(results) > 1 {
			slowestLat := results[0].LatencyMs
			for _, r := range results {
				if r.LatencyMs > slowestLat {
					slowestLat = r.LatencyMs
				}
			}
			ratio := 1.0
			if fastest.LatencyMs > 0 {
				ratio = math.Round((slowestLat/fastest.LatencyMs)*10) / 10
			}
			return fmt.Sprintf("Deterministic engine reached an identical verdict %.1fx faster with zero external network roundtrips.", ratio)
		}
		return "All engines reached unanimous consensus on software provenance classification."
	}

	for _, r := range results {
		if (r.Mode == "gemini" || r.Mode == "deepseek" || r.Mode == "ollama") && r.RawClassification == "THIRD_PARTY" {
			return "Cloud-grounded reasoning surfaced verified external provenance evidence that local heuristics were unable to resolve."
		}
	}

	return "Discrepancy detected between engine outputs. Review individual evidence summaries below."
}

func generateTokenSavingsTakeaway(results []CompareEngineResult) string {
	hasZero := false
	hasNonZero := false
	maxTokens := 0
	zeroEngine := ""

	for _, r := range results {
		if r.TokenEconomics.TotalTokens == 0 {
			hasZero = true
			if zeroEngine == "" {
				zeroEngine = r.DisplayName
			}
		} else {
			hasNonZero = true
			if r.TokenEconomics.TotalTokens > maxTokens {
				maxTokens = r.TokenEconomics.TotalTokens
			}
		}
	}

	if hasZero && hasNonZero {
		return fmt.Sprintf("Token Efficiency: %s resolved at upper static layers with 0 tokens consumed ($0.00 cost), saving ~%s tokens compared to AI reasoning.",
			zeroEngine, formatNumber(maxTokens))
	}
	if hasZero && !hasNonZero {
		return "Zero Token Consumption: All evaluated engines resolved via deterministic static layers with 0 API tokens spent."
	}
	return "All evaluated engines engaged AI models with measured token consumption."
}
