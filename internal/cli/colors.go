package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/kyybogor/Kyytools/internal/models"
)

var DisableColor = false

func init() {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		DisableColor = true
	}
}

func colorize(code, text string) string {
	if DisableColor {
		return text
	}
	return fmt.Sprintf("\033[%sm%s\033[0m", code, text)
}

func Red(t string) string     { return colorize("31", t) }
func Green(t string) string   { return colorize("32", t) }
func Yellow(t string) string  { return colorize("33", t) }
func Blue(t string) string    { return colorize("34", t) }
func Magenta(t string) string { return colorize("35", t) }
func Cyan(t string) string    { return colorize("36", t) }
func Gray(t string) string    { return colorize("90", t) }
func Bold(t string) string    { return colorize("1", t) }

func SeverityBadge(s models.Severity) string {
	if DisableColor {
		return fmt.Sprintf("[%s]", s)
	}
	switch s {
	case models.SeverityCritical:
		return "\033[1;97;41m CRITICAL \033[0m"
	case models.SeverityHigh:
		return "\033[1;97;48;5;202m  HIGH   \033[0m"
	case models.SeverityMedium:
		return "\033[1;97;48;5;214m MEDIUM  \033[0m"
	case models.SeverityLow:
		return "\033[1;97;42m   LOW   \033[0m"
	case models.SeverityInfo:
		return "\033[1;97;44m  INFO   \033[0m"
	default:
		return fmt.Sprintf("[%s]", s)
	}
}

// PrintBanner outputs the standardized KyyTools banner.
func PrintBanner() {
	banner := `
==================================================
       KyyTools Security Scanner
       Go-Based Security Assessment Tool
==================================================`
	fmt.Println(Bold(Cyan(banner)))
}

// RenderTable prints a simple bordered ASCII table.
func RenderTable(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}

	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Print top border
	printBorder(colWidths, "┌", "┬", "┐")

	// Print header
	fmt.Print("│")
	for i, h := range headers {
		fmt.Printf(" %-*s │", colWidths[i], Bold(h))
	}
	fmt.Println()

	// Print header separator
	printBorder(colWidths, "├", "┼", "┤")

	// Print rows
	for _, row := range rows {
		fmt.Print("│")
		for i := 0; i < len(headers); i++ {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			fmt.Printf(" %-*s │", colWidths[i], cell)
		}
		fmt.Println()
	}

	// Print bottom border
	printBorder(colWidths, "└", "┴", "┘")
}

func printBorder(widths []int, left, mid, right string) {
	fmt.Print(left)
	for i, w := range widths {
		fmt.Print(strings.Repeat("─", w+2))
		if i < len(widths)-1 {
			fmt.Print(mid)
		}
	}
	fmt.Println(right)
}
