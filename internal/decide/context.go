package decide

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/manifest"
	"github.com/gautamtalksdev/lading/internal/purl"
)

type evalContext struct {
	findingCVE          string
	findingPURL         purl.PURL
	matchPURL           purl.PURL
	identityRefusal     ReasonCode
	manifestVersion     string
	manifestComponent   *manifest.Component
	purlQuality         purl.MatchQuality
	entry               *manifest.Entry
	definitiveSymbols   []string
	componentIdentified bool
	componentInvIDs     []string
	inventories         []*inventory.Inventory
	inputsUsed          InputsUsed
}

func buildContext(in Input) (evalContext, error) {
	if in.Manifest == nil {
		return evalContext{}, fmt.Errorf("decide: nil Manifest")
	}
	findingPURL, err := purl.Canonicalize(strings.TrimSpace(in.Finding.ComponentPURL))
	if err != nil {
		return evalContext{}, fmt.Errorf("decide: finding PURL: %w", err)
	}

	idRes := resolveIdentity(findingPURL, in.IdentityAliases)
	matchPURL := idRes.matchPURL
	cve := strings.ToUpper(strings.TrimSpace(in.Finding.CVE))
	if cve == "" {
		return evalContext{}, fmt.Errorf("decide: empty CVE")
	}

	comp, quality := bestManifestMatch(in.Manifest, matchPURL)
	quality = applyIdentityMappedQuality(quality, idRes.identityMapped)
	ctx := evalContext{
		findingCVE:        cve,
		findingPURL:       findingPURL,
		matchPURL:         matchPURL,
		identityRefusal:   idRes.refusal,
		manifestVersion:   in.Manifest.Version(),
		purlQuality:       quality,
		inventories:       in.Inventories,
	}
	if comp != nil {
		c := *comp
		ctx.manifestComponent = &c
	}
	if ctx.manifestComponent != nil {
		ctx.entry = entryForCVE(in.Manifest, cve, ctx.manifestComponent.Name)
		if ctx.entry != nil {
			ctx.definitiveSymbols = definitiveSymbols(*ctx.entry)
		}
	}

	invIDs := inventoryIDs(in.Inventories)
	ctx.componentInvIDs, ctx.componentIdentified = componentInventories(
		in.Manifest, ctx.manifestComponent, in.Inventories)

	observed := observableSymbols(in.Inventories)
	present := intersectPresent(ctx.definitiveSymbols, observed)

	ctx.inputsUsed = InputsUsed{
		CVE:                      cve,
		ComponentPURL:            in.Finding.ComponentPURL,
		PURLMatchQuality:         quality.String(),
		Inventories:              invIDs,
		DefinitiveSymbolsChecked: append([]string(nil), ctx.definitiveSymbols...),
		SymbolsObserved:          present,
		ComponentInventories:     append([]string(nil), ctx.componentInvIDs...),
	}
	if ctx.manifestComponent != nil {
		ctx.inputsUsed.ManifestComponent = ctx.manifestComponent.Name
	}
	return ctx, nil
}

func bestManifestMatch(m *manifest.Manifest, finding purl.PURL) (*manifest.Component, purl.MatchQuality) {
	best := purl.None
	var winner *manifest.Component
	for i := range m.Components() {
		c := m.Components()[i]
		for _, raw := range c.PURLs {
			canon, err := purl.Canonicalize(raw)
			if err != nil {
				continue
			}
			q := purl.Equivalent(finding, canon)
			if q > best {
				best = q
				cc := c
				winner = &cc
			}
		}
	}
	if best < purl.NameVersionOnly {
		return nil, best
	}
	return winner, best
}

func entryForCVE(m *manifest.Manifest, cve, componentName string) *manifest.Entry {
	entries, ok := m.LookupCVE(cve)
	if !ok {
		return nil
	}
	for i := range entries {
		if entries[i].ComponentName == componentName {
			e := entries[i]
			return &e
		}
	}
	return nil
}

func definitiveSymbols(e manifest.Entry) []string {
	var out []string
	for _, vs := range e.VulnerableSymbols {
		if vs.Confidence == manifest.ConfidenceDefinitive {
			out = append(out, vs.Name)
		}
	}
	sort.Strings(out)
	return out
}

func inventoryIDs(invs []*inventory.Inventory) []string {
	out := make([]string, 0, len(invs))
	for _, inv := range invs {
		if inv == nil {
			out = append(out, "")
			continue
		}
		id := inv.Path
		if id == "" {
			id = inv.SHA256
		}
		out = append(out, id)
	}
	return out
}

func componentInventories(
	m *manifest.Manifest,
	comp *manifest.Component,
	invs []*inventory.Inventory,
) ([]string, bool) {
	if comp == nil || m == nil {
		return nil, false
	}
	var ids []string
	for _, inv := range invs {
		if inv == nil {
			continue
		}
		hits := m.IdentifyComponent(inv)
		for _, hit := range hits {
			if hit.Component.Name == comp.Name {
				id := inv.Path
				if id == "" {
					id = inv.SHA256
				}
				ids = append(ids, id)
				break
			}
		}
	}
	sort.Strings(ids)
	return ids, len(ids) > 0
}

func usableSymbolTable(inv *inventory.Inventory) bool {
	if inv == nil || inv.Format == inventory.FormatUnknown {
		return false
	}
	if inv.Stripped && inv.StaticLinked {
		return false
	}
	if len(inv.DynSyms) > 0 {
		return true
	}
	return !inv.Stripped && len(inv.SymTab) > 0
}

func observableSymbols(invs []*inventory.Inventory) map[string]struct{} {
	set := map[string]struct{}{}
	add := func(s inventory.Symbol) {
		if s.Normalized != "" {
			set[s.Normalized] = struct{}{}
		}
		if s.Raw != "" {
			set[s.Raw] = struct{}{}
		}
	}
	for _, inv := range invs {
		if inv == nil {
			continue
		}
		for _, s := range inv.DynSyms {
			add(s)
		}
		for _, s := range inv.SymTab {
			add(s)
		}
	}
	return set
}

func intersectPresent(definitive []string, observed map[string]struct{}) []string {
	var out []string
	for _, name := range definitive {
		if _, ok := observed[name]; ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (ctx evalContext) anyUsableSymbolTable() bool {
	for _, inv := range ctx.inventories {
		if usableSymbolTable(inv) {
			return true
		}
	}
	return false
}

func (ctx evalContext) anyDefinitivePresent() bool {
	if len(ctx.definitiveSymbols) == 0 {
		return false
	}
	observed := observableSymbols(ctx.inventories)
	for _, s := range ctx.definitiveSymbols {
		if _, ok := observed[s]; ok {
			return true
		}
	}
	return false
}

func (ctx evalContext) inventoryByID(id string) *inventory.Inventory {
	for _, inv := range ctx.inventories {
		if inv == nil {
			continue
		}
		invID := inv.Path
		if invID == "" {
			invID = inv.SHA256
		}
		if invID == id {
			return inv
		}
	}
	return nil
}

func checkD03(ctx evalContext) (ReasonCode, bool) {
	if ctx.identityRefusal != "" {
		return ctx.identityRefusal, true
	}
	if ctx.purlQuality <= purl.NameOnly {
		return ReasonPURLMatchInsufficient, true
	}
	if ctx.manifestComponent == nil {
		return ReasonPURLMatchInsufficient, true
	}
	if ctx.entry == nil {
		return ReasonManifestNoEntry, true
	}
	if len(ctx.definitiveSymbols) == 0 {
		return ReasonManifestProbableOnly, true
	}
	if !ctx.anyUsableSymbolTable() {
		return ReasonSymbolTableUnusable, true
	}

	for _, id := range ctx.componentInvIDs {
		inv := ctx.inventoryByID(id)
		if inv == nil {
			continue
		}
		if inv.Stripped && inv.StaticLinked {
			return ReasonStrippedStaticBinary, true
		}
		if inv.Stripped && !inv.StaticLinked && len(inv.DynSyms) == 0 {
			return ReasonStrippedInsufficientDynsym, true
		}
	}

	if !ctx.componentIdentified &&
		ctx.purlQuality == purl.NameVersionOnly &&
		ctx.entry != nil {
		return ReasonIdentityUnverified, true
	}

	return "", false
}
