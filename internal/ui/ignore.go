package ui

import (
	"fmt"
	"strings"

	"github.com/smagew/whatsrisky/internal/exclude"
)

// ignoreText lists what we always skip. The panel can only say how many there
// are; a number you cannot check is a number you have to trust, and this project
// does not ask for that anywhere else.
//
// The list is read from exclude.Defaults, never retyped here: a copy in the
// interface would drift from the one that does the skipping.
func ignoreText(width int) string {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s%d folders and files that whatsrisky never looks at%s\n",
		titleTag, len(exclude.Defaults), resetTag))
	out.WriteString(dimTag +
		"A name skips that folder. A name with * skips any file that matches it." +
		resetTag + "\n\n")

	columns := maxInt(1, (width-2)/24)
	rows := (len(exclude.Defaults) + columns - 1) / columns
	for row := 0; row < rows; row++ {
		var line strings.Builder
		for column := 0; column < columns; column++ {
			index := column*rows + row
			if index >= len(exclude.Defaults) {
				continue
			}
			line.WriteString(fmt.Sprintf("%-24s", exclude.Defaults[index]))
		}
		out.WriteString(inkTag + strings.TrimRight(line.String(), " ") + resetTag + "\n")
	}

	out.WriteString("\n" + dimTag +
		"To scan one of these anyway, point whatsrisky straight at it: whatsrisky ./dist" +
		resetTag + "\n")
	return out.String()
}
