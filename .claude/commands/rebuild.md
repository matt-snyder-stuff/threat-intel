# /rebuild

Rebuild the Threat Watch dashboard and JSON dataset from a chosen source.

## Usage

```
/rebuild                         # uses default source from $DEFAULT_SOURCE or opencti
/rebuild opencti                 # fetch from OpenCTI
/rebuild slack                   # fetch from Slack channel
/rebuild rss                     # fetch from RSS feeds
/rebuild splunk                  # fetch from Splunk REST API
/rebuild stix                    # fetch from TAXII server or local/remote STIX bundle
```

## Steps

1. **Parse the source** from `$ARGUMENTS` (first word). Default to `opencti` if not provided.

2. **Validate the source** is one of: `opencti`, `slack`, `rss`, `splunk`, `stix`. If not, print:
   ```
   Unknown source: <value>. Choose one of: opencti, slack, rss, splunk, stix
   ```
   and STOP.

3. **Check required env vars** for the chosen source:

   | Source | Required vars |
   |--------|--------------|
   | `opencti` | `OPENCTI_URL`, `OPENCTI_TOKEN` |
   | `slack` | `SLACK_TOKEN`, `SLACK_CHANNEL_ID` |
   | `rss` | none — `RSS_FEEDS` is optional (defaults to `sources/feeds.py`) |
   | `splunk` | `SPLUNK_URL` (plus `SPLUNK_TOKEN` or `SPLUNK_USERNAME`+`SPLUNK_PASSWORD`) |
   | `stix` | at least one of `TAXII_URL`, `STIX_FILE`, or `STIX_URL` |

   If any required vars are missing, print a clear error showing which are missing and STOP.
   For `rss`, never error on a missing `RSS_FEEDS` — the default feed list will be used.
   For `stix`, check that at least one of `TAXII_URL`, `STIX_FILE`, or `STIX_URL` is set; if none are set, print guidance and STOP.

4. **Run the pipeline:**
   ```bash
   cd <repo-root>
   python3 run.py --source <source> --build
   ```

5. **Report the output:**
   - Print the number of reports processed, cloud count, AI count, publishers.
   - Print the paths of the generated files (HTML and JSON).
   - If the build fails, print the error output and STOP.

6. **Optionally** — if `THREAT_WATCH_URL` is set (i.e. the JSON is served from somewhere), print a reminder:
   ```
   Dashboard JSON is served at $THREAT_WATCH_URL
   Copy threat-watch-data.json there to publish the updated dataset.
   ```
