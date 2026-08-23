package unpack

import "fmt"

// Hard limits for archive extraction (non-negotiable).
const (
	MaxDecompressedSize int64 = 8 << 30 // 8 GiB
	MaxEntryCount       int   = 500_000
	MaxDepth            int   = 16
)

// LimitError reports a limit breach with the offending archive entry named.
type LimitError struct {
	Entry  string
	Reason string
}

func (e *LimitError) Error() string {
	if e.Entry == "" {
		return fmt.Sprintf("unpack: %s", e.Reason)
	}
	return fmt.Sprintf("unpack: entry %q: %s", e.Entry, e.Reason)
}
