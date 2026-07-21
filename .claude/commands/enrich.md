# /enrich

Enrich IOCs extracted from the threat-watch-data.json dataset using public APIs.

## Usage

```
/enrich                          # extract and enrich IOCs from the current dataset
/enrich 1.2.3.4                  # enrich a specific IP
/enrich evil.example.com         # enrich a specific domain
/enrich CVE-2024-12345           # look up a specific CVE
/enrich 1.2.3.4 evil.example.com CVE-2024-99999   # enrich multiple IOCs
```

## Steps

1. **Parse IOCs from `$ARGUMENTS`** — split on whitespace. Classify each token as:
   - IP: matches `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`
   - CVE: matches `CVE-\d{4}-\d+` (case-insensitive)
   - Domain: anything else that looks like a hostname

2. **If no IOCs were provided**, use the `ioc-enricher` agent to extract them from the dataset automatically.

3. **If IOCs were provided**, pass them directly to the `ioc-enricher` agent with the instruction to skip the auto-extraction step and enrich only the given list.

4. **After enrichment completes**, print:
   - Path to the enrichment report (`/tmp/ioc-enrichment-<date>.md`)
   - A summary table of what was found (country/ASN for IPs, age for domains, CVSS for CVEs)

## Notes

- Enrichment uses only public, no-auth APIs (ipapi.co, crt.sh, rdap.org, NVD).
- NVD requests are rate-limited — enriching more than ~5 CVEs will take 30+ seconds.
- Results are informational only. Confirm any suspicious finding through a threat intel platform before treating it as a confirmed indicator.
