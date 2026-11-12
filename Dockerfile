# Minimal container image for coverguard.
# The tool has zero runtime dependencies; the image just packages Python + the
# wheel, and runs as a non-root user (least privilege).
#
# Supply chain: the base tag is watched by Dependabot (.github/dependabot.yml),
# which pins it to an immutable digest and proposes updates. To pin by hand:
#   docker buildx imagetools inspect python:3.12-slim   # copy the sha256
#   FROM python:3.12-slim@sha256:<digest> AS build

FROM python:3.15-slim AS build
WORKDIR /src
COPY . .
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.15-slim
LABEL org.opencontainers.image.title="coverguard" \
      org.opencontainers.image.description="CVE-aware coverage for Claude Cowork tool calls" \
      org.opencontainers.image.source="https://github.com/0xkhalsa07/coverguard" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN useradd --create-home --uid 10001 coverguard
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
USER coverguard
WORKDIR /work
ENTRYPOINT ["coverguard"]
CMD ["--help"]
