package banner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/FreeNetLabs/bugscanx-go/internal/config"
)

const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Red     = "\033[91m"
	Green   = "\033[92m"
	Yellow  = "\033[93m"
	Blue    = "\033[94m"
	Magenta = "\033[95m"
	Cyan    = "\033[96m"
	White   = "\033[97m"
	Gray    = "\033[90m"
	Orange  = "\033[33m"
)

var stdinReader = bufio.NewReader(os.Stdin)

func Colorize(text, color string) string {
	return color + text + Reset
}

func ClearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	_ = cmd.Run()
}

func PrintBanner() {
	ClearScreen()
	fmt.Printf(`
    %s╔╗ %s╦ ╦╔═╗╔═╗╔═╗╔═╗╔╗╔═╗ ╦%s   %s[GO EDITION v%s]%s
    %s╠╩╗%s║ ║║ ╦╚═╗║  ╠═╣║║║╔╩╦╝%s   %sZero-False-Negative Engine%s
    %s╚═╝%s╚═╝╚═╝╚═╝╚═╝╩ ╩╝╚╝╩ ╚═%s   %sAll HTTP + QUERY + WebDAV Methods%s
    %s  Dᴇᴠᴇʟᴏᴘᴇʀ: FreeNetLabs (Go High-Speed Core)%s
`,
		Bold+Red, Cyan, Reset, Bold+Green, config.Version, Reset,
		Bold+Red, Cyan, Reset, Yellow, Reset,
		Bold+Red, Cyan, Reset, Gray, Reset,
		Bold+Magenta, Reset,
	)
	fmt.Println()
}

func PrintSectionTitle(title string) {
	ClearScreen()
	border := strings.Repeat("═", len(title)+6)
	fmt.Printf("\n  %s╔%s╗%s\n", Bold+Magenta, border, Reset)
	fmt.Printf("  %s║   %s%s   %s║%s\n", Bold+Magenta, Bold+Cyan, title, Bold+Magenta, Reset)
	fmt.Printf("  %s╚%s╝%s\n\n", Bold+Magenta, border, Reset)
}

func ReadLine() string {
	line, err := stdinReader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return ""
	}
	return strings.TrimSpace(line)
}

func PromptText(label, defaultVal string, required bool) string {
	for {
		if defaultVal != "" {
			fmt.Printf(" %s?%s %s%s%s [%s%s%s]: ", Cyan, Reset, Bold+White, label, Reset, Green, defaultVal, Reset)
		} else {
			fmt.Printf(" %s?%s %s%s%s: ", Cyan, Reset, Bold+White, label, Reset)
		}
		val := ReadLine()
		if val == "" {
			val = defaultVal
		}
		if required && val == "" {
			fmt.Printf("   %s[!] Input is required.%s\n", Red, Reset)
			continue
		}
		return val
	}
}

func PromptInt(label string, defaultVal int, minVal int) int {
	for {
		raw := PromptText(label, strconv.Itoa(defaultVal), true)
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || n < minVal {
			fmt.Printf("   %s[!] Please enter a valid number >= %d.%s\n", Red, minVal, Reset)
			continue
		}
		return n
	}
}

func PromptConfirm(label string, defaultYes bool) bool {
	hint := "Y/n"
	if !defaultYes {
		hint = "y/N"
	}
	fmt.Printf(" %s?%s %s%s%s (%s): ", Cyan, Reset, Bold+White, label, Reset, hint)
	val := strings.ToLower(ReadLine())
	if val == "" {
		return defaultYes
	}
	return val == "y" || val == "yes"
}

func PromptChoice(label string, choices []string, defaultIdx int) string {
	fmt.Printf("\n %s%s:%s\n", Bold+Cyan, label, Reset)
	for i, c := range choices {
		marker := " "
		if i == defaultIdx {
			marker = Green + "▸" + Reset
		}
		fmt.Printf("  %s %s[%d]%s %s\n", marker, Cyan, i+1, Reset, c)
	}
	for {
		defStr := ""
		if defaultIdx >= 0 && defaultIdx < len(choices) {
			defStr = strconv.Itoa(defaultIdx + 1)
		}
		raw := PromptText("Select option", defStr, true)
		idx, err := strconv.Atoi(raw)
		if err == nil && idx >= 1 && idx <= len(choices) {
			return choices[idx-1]
		}
		// Allow matching by name
		for _, c := range choices {
			if strings.EqualFold(c, raw) {
				return c
			}
		}
		fmt.Printf("   %s[!] Choose a number between 1 and %d.%s\n", Red, len(choices), Reset)
	}
}

// PromptMethods lets the user choose HTTP method presets (including newer QUERY, PRI, WebDAV) or custom verbs.
func PromptMethods() []string {
	presets := []string{
		"Core + Modern Bypass [17 methods: GET, HEAD, POST, OPTIONS, QUERY, PATCH, PUT, DELETE, TRACE, CONNECT, PROPFIND, REPORT, SEARCH, PURGE, MKCOL, ACL, PRI]",
		"All Extended HTTP Methods [35 methods: All RFC 9110 + QUERY + PRI + All WebDAV/DeltaV]",
		"Standard HTTP Methods [9 methods: GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE, PATCH, CONNECT]",
		"Essential Fast Methods [5 methods: GET, HEAD, POST, OPTIONS, QUERY]",
		"Single Method: GET only",
		"Custom Method List (enter comma-separated methods)",
	}
	choice := PromptChoice("Select HTTP Methods to Test", presets, 0)
	switch {
	case strings.HasPrefix(choice, "Core + Modern"):
		return append([]string{}, config.ModernAndBypassMethods...)
	case strings.HasPrefix(choice, "All Extended"):
		return append([]string{}, config.AllExtendedMethods...)
	case strings.HasPrefix(choice, "Standard HTTP"):
		return append([]string{}, config.StandardMethods...)
	case strings.HasPrefix(choice, "Essential Fast"):
		return []string{"GET", "HEAD", "POST", "OPTIONS", "QUERY"}
	case strings.HasPrefix(choice, "Single Method"):
		return []string{"GET"}
	default:
		raw := PromptText("Enter methods (comma-separated)", "GET,HEAD,POST,OPTIONS,QUERY,PATCH,PROPFIND,TRACE,CONNECT", true)
		var out []string
		seen := make(map[string]bool)
		for _, part := range strings.Split(raw, ",") {
			m := strings.ToUpper(strings.TrimSpace(part))
			if m != "" && !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
		if len(out) == 0 {
			return []string{"GET"}
		}
		return out
	}
}
