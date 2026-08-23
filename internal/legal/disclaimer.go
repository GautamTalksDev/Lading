// Package legal holds liability and licensing text shared by CLI output and VEX emitters.
package legal

// DisclaimerShort is embedded in CLI --help and every emitted VEX document metadata.
// Keep in sync with DISCLAIMER.md.
const DisclaimerShort = "LADING produces evidence, not conclusions; the manufacturer remains solely responsible for statements in their technical file."

// DisclaimerFull is the canonical liability text (DISCLAIMER.md body).
const DisclaimerFull = `LADING produces evidence, not legal advice.

The manufacturer remains solely responsible for statements in their technical file.

LADING makes no warranty of completeness.

Use of LADING does not create an attorney-client relationship, does not certify
regulatory compliance, and does not shift liability for Vulnerability Exploitability
Exchange (VEX) or other product security statements away from the party that
publishes them.

LADING never submits reports to regulators or notified bodies on your behalf.
Draft export files only; you transmit them if and when you choose.`
