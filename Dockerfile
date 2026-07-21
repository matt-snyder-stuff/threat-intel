FROM python:3.11-slim

WORKDIR /app

COPY sources/ sources/
COPY generator/ generator/
COPY agent/ agent/
COPY .claude/ .claude/
COPY run.py .
COPY CLAUDE.md .

# All pipeline I/O lives under /data so a single volume mount covers inputs + outputs.
ENV PKL_IN=/data/tw-30d-processed.pkl \
    RAW_IN=/data/tw-30d.json \
    PUB_IN=/data/tw-30d-published.json \
    PKL_OUT=/data/tw-30d-processed.pkl \
    RAW_OUT=/data/tw-30d.json \
    PUB_SIDECAR=/data/tw-30d-published.json \
    HTML_OUT=/data/threat-watch.html \
    JSON_OUT=/data/threat-watch-data.json

VOLUME ["/data"]

# Default: fetch from RSS and build. Override SOURCE and pass --build via CMD or
# docker run ... python3 run.py --source opencti --build
ENTRYPOINT ["python3", "run.py"]
CMD ["--source", "rss", "--build"]
