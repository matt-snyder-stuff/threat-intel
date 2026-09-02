# Prebuilt conference preview

`threat-watch.html` and `threat-watch-data.json` are generated from the bundled
synthetic fixture. Download the HTML file and open it locally to explore the
dashboard without installing or running anything.

Regenerate both artifacts from the repository root:

```bash
python3 quickstart.py --output-dir demo/prebuilt
```

The generated pickle and publication sidecar are intermediate files and should
not be committed.
