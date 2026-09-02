FROM python:3.11-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84

WORKDIR /app

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /data \
    && chown app:app /data

COPY sources/ sources/
COPY generator/ generator/
COPY guardrails/ guardrails/
COPY operations/ operations/
COPY agent/ agent/
COPY .claude/ .claude/
COPY run.py .
COPY CLAUDE.md .

# All pipeline I/O lives under /data so a single volume mount covers inputs + outputs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PKL_IN=/data/tw-30d-processed.pkl \
    RAW_IN=/data/tw-30d.json \
    PUB_IN=/data/tw-30d-published.json \
    PKL_OUT=/data/tw-30d-processed.pkl \
    RAW_OUT=/data/tw-30d.json \
    PUB_SIDECAR=/data/tw-30d-published.json \
    HTML_OUT=/data/threat-watch.html \
    JSON_OUT=/data/threat-watch-data.json \
    REVIEW_STATE_IN=/data/review-state.json \
    PUBLISH_MAX_TLP=TLP:AMBER

VOLUME ["/data"]

USER app

# Default: fetch from RSS and build. Override SOURCE and pass --build via CMD or
# docker run ... python3 run.py --source opencti --build
ENTRYPOINT ["python3", "run.py"]
CMD ["--source", "rss", "--build"]
