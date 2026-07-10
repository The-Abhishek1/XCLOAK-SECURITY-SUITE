package services

import (
	"fmt"
	"io"
	"time"

	"github.com/jung-kurt/gofpdf"
	"xcloak-platform/models"
)

// GenerateExecutivePDF writes an executive security report PDF to w.
func GenerateExecutivePDF(w io.Writer, m models.ExecutiveMetrics, reportName string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.SetMargins(20, 20, 20)
	pdf.AddPage()

	accent := [3]int{16, 185, 129} // emerald

	// ── Header bar ──────────────────────────────────────────────────────────
	pdf.SetFillColor(10, 10, 20)
	pdf.Rect(0, 0, 210, 28, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetXY(20, 8)
	pdf.Cell(120, 10, "XCLOAK")
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetXY(20, 18)
	pdf.Cell(120, 6, tr(reportName+" — Executive Security Report"))
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetXY(140, 18)
	pdf.CellFormat(50, 6, time.Now().Format("2006-01-02 15:04 UTC"), "", 0, "R", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
	pdf.SetXY(20, 34)

	// ── KPI tiles ───────────────────────────────────────────────────────────
	type kpi struct {
		label string
		value string
		warn  bool
	}
	kpis := []kpi{
		{"Open Cases", fmt.Sprintf("%d", m.OpenCases), m.OpenCases > 0},
		{"Critical Cases", fmt.Sprintf("%d", m.CriticalCases), m.CriticalCases > 0},
		{"MTTR", fmt.Sprintf("%.1fh", m.MTTRHours), m.MTTRHours > 24},
		{"MTTD", fmt.Sprintf("%.1fh", m.MTTDHours), false},
		{"SLA Compliance", fmt.Sprintf("%.0f%%", m.SLAComplianceRate), m.SLAComplianceRate < 90},
		{"Assets", fmt.Sprintf("%d", m.TotalAssets), false},
		{"Online Agents", fmt.Sprintf("%d", m.OnlineAgents), false},
		{"30d Alerts", fmt.Sprintf("%d", m.TotalAlerts), m.TotalAlerts > 1000},
	}
	tileW := 42.5
	tileH := 20.0
	for i, k := range kpis {
		x := 20.0 + float64(i%4)*tileW
		y := 36.0 + float64(i/4)*25
		if k.warn {
			pdf.SetFillColor(127, 29, 29)
			pdf.SetTextColor(255, 200, 200)
		} else {
			pdf.SetFillColor(20, 24, 36)
			pdf.SetTextColor(200, 210, 230)
		}
		pdf.RoundedRect(x, y, tileW-2, tileH, 2, "1234", "F")
		pdf.SetFont("Helvetica", "B", 14)
		pdf.SetXY(x, y+3)
		pdf.CellFormat(tileW-2, 8, k.value, "", 0, "C", false, 0, "")
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetXY(x, y+11)
		pdf.CellFormat(tileW-2, 5, k.label, "", 0, "C", false, 0, "")
	}
	pdf.SetTextColor(0, 0, 0)

	// ── Alert Volume Sparkline ───────────────────────────────────────────────
	sectionY := 92.0
	drawSectionHeader(pdf, tr, "Alert Volume — Last 30 Days", accent, sectionY)
	if len(m.AlertVolume) > 0 {
		drawBarChart(pdf, m.AlertVolume, 20, sectionY+8, 170, 30)
	} else {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetXY(20, sectionY+12)
		pdf.Cell(170, 6, "No alert data in the last 30 days.")
	}

	// ── Cases by Severity ────────────────────────────────────────────────────
	sectionY = 140.0
	drawSectionHeader(pdf, tr, "Cases by Severity", accent, sectionY)
	drawHorizBars(pdf, m.CasesBySeverity, 20, sectionY+8, 80, severityColor)

	// ── Cases by Phase ───────────────────────────────────────────────────────
	drawSectionHeader(pdf, tr, "IR Phase Distribution", accent, sectionY)
	drawHorizBars(pdf, m.CasesByPhase, 110, sectionY+8, 80, phaseColor)

	// ── Top MITRE Tactics ────────────────────────────────────────────────────
	sectionY = 200.0
	drawSectionHeader(pdf, tr, "Top MITRE ATT&CK Tactics", accent, sectionY)
	drawHorizBars(pdf, m.TopMITRETactics, 20, sectionY+8, 170, func(string) [3]int { return accent })

	// ── Footer ───────────────────────────────────────────────────────────────
	pdf.SetFillColor(10, 10, 20)
	pdf.Rect(0, 282, 210, 15, "F")
	pdf.SetTextColor(120, 130, 150)
	pdf.SetFont("Helvetica", "", 7)
	pdf.SetXY(20, 285)
	pdf.Cell(170, 5, tr("XCLOAK Security Suite — Confidential — Generated "+time.Now().Format(time.RFC1123)))

	return pdf.Output(w)
}

func drawSectionHeader(pdf *gofpdf.Fpdf, tr func(string) string, title string, color [3]int, y float64) {
	pdf.SetFillColor(color[0], color[1], color[2])
	pdf.Rect(20, y, 4, 5, "F")
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(30, 30, 50)
	pdf.SetXY(26, y)
	pdf.Cell(160, 5, tr(title))
}

func drawBarChart(pdf *gofpdf.Fpdf, data []models.DailyCount, x, y, w, h float64) {
	if len(data) == 0 {
		return
	}
	max := 1
	for _, d := range data {
		if d.Count > max {
			max = d.Count
		}
	}
	barW := w / float64(len(data))
	pdf.SetFillColor(16, 185, 129)
	for i, d := range data {
		bh := (float64(d.Count) / float64(max)) * h
		if bh < 1 {
			bh = 1
		}
		bx := x + float64(i)*barW
		pdf.Rect(bx+0.5, y+h-bh, barW-1, bh, "F")
	}
}

func drawHorizBars(pdf *gofpdf.Fpdf, data []models.LabelCount, x, y, w float64, colorFn func(string) [3]int) {
	if len(data) == 0 {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetXY(x, y+4)
		pdf.Cell(w, 5, "No data.")
		return
	}
	max := 1
	for _, d := range data {
		if d.Count > max {
			max = d.Count
		}
	}
	barH := 5.0
	gap := 2.0
	for i, d := range data {
		ry := y + float64(i)*(barH+gap)
		bw := (float64(d.Count) / float64(max)) * (w - 30)
		c := colorFn(d.Label)
		pdf.SetFillColor(c[0], c[1], c[2])
		pdf.Rect(x+30, ry, bw, barH, "F")
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(50, 50, 70)
		pdf.SetXY(x, ry)
		pdf.CellFormat(28, barH, d.Label, "", 0, "R", false, 0, "")
		pdf.SetXY(x+32+bw, ry)
		pdf.Cell(10, barH, fmt.Sprintf("%d", d.Count))
		if i >= 6 {
			break
		}
	}
	pdf.SetTextColor(0, 0, 0)
}

func execSeverityColor(s string) [3]int {
	switch s {
	case "critical":
		return [3]int{239, 68, 68}
	case "high":
		return [3]int{249, 115, 22}
	case "medium":
		return [3]int{234, 179, 8}
	default:
		return [3]int{34, 197, 94}
	}
}

func phaseColor(p string) [3]int {
	switch p {
	case "identification":
		return [3]int{59, 130, 246}
	case "containment":
		return [3]int{168, 85, 247}
	case "eradication":
		return [3]int{236, 72, 153}
	case "recovery":
		return [3]int{16, 185, 129}
	case "closed":
		return [3]int{100, 116, 139}
	default:
		return [3]int{99, 102, 241}
	}
}
