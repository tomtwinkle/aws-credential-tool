package errguide

import (
	"errors"
	"fmt"
	"strings"
)

const marker = "\n\nHow to fix:\n"

// New creates an actionable user-facing error without exposing implementation
// details. The first line remains the original problem statement so existing
// callers can continue matching the cause text.
func New(message string, steps ...string) error {
	return errors.New(message + formatSteps(steps...))
}

// Wrap preserves the original error for errors.Is/errors.As callers and adds
// concise recovery steps. Avoid adding a second guide when a lower layer has
// already provided one.
func Wrap(err error, steps ...string) error {
	if err == nil || len(steps) == 0 || strings.Contains(err.Error(), marker) {
		return err
	}
	return fmt.Errorf("%w%s", err, formatSteps(steps...))
}

func formatSteps(steps ...string) string {
	if len(steps) == 0 {
		return ""
	}

	var builder strings.Builder
	builder.WriteString(marker)
	stepNumber := 0
	for _, step := range steps {
		if strings.TrimSpace(step) == "" {
			continue
		}
		stepNumber++
		fmt.Fprintf(&builder, "%d. %s\n", stepNumber, step)
	}
	if stepNumber == 0 {
		return ""
	}
	return builder.String()
}
