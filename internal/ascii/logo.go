package ascii

import (
	"fmt"
	"strings"
	"github.com/helviojunior/randmap/internal/version"
)

// Logo returns the randmap ascii logo
func Logo() string {
	txt := `
{R}[:: {O}RandMap {R}::]{GR} -// randomized ip & port feed for scans{W}
     > inject chaos into your targets{GR} // v`

	v := fmt.Sprintf("%s-%s", version.Version, version.GitHash)
	txt += v + "{W}"
	txt = strings.Replace(txt, "{GR}", "\033[0m\033[1;90m", -1)
	txt = strings.Replace(txt, "{R}", "\033[1;31m", -1)
	txt = strings.Replace(txt, "{O}", "\033[33m", -1)
	txt = strings.Replace(txt, "{W}", "\033[0m", -1)
	return fmt.Sprintln(txt)
}

// LogoHelp returns the logo, with help
func LogoHelp(s string) string {
	return Logo() + "\n\n" + s
}
