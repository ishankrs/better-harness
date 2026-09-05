FROM node:22-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Bump OPENCODE_VERSION on a schedule (check `npm view opencode-ai version`).
# --no-audit/--no-fund skips throwaway metadata; cache clean keeps it out of
# the layer. The version assertion fails the build closed if the registry
# serves anything other than the pinned release (hijack tripwire).
ARG OPENCODE_VERSION=1.18.29
RUN npm i -g --no-audit --no-fund "opencode-ai@${OPENCODE_VERSION}" \
    && npm cache clean --force \
    && rm -rf /tmp/* \
    && opencode --version | grep -q "${OPENCODE_VERSION}"

RUN useradd -ms /bin/bash agent

COPY gen_config.py export_trajectory.py scrub_stream.py entrypoint.sh /opt/
RUN chmod 644 /opt/gen_config.py /opt/export_trajectory.py /opt/scrub_stream.py && chmod 755 /opt/entrypoint.sh \
    && mkdir -p /logs/agent /workspace /task \
    && chown -R agent:agent /logs /workspace /task

USER agent
WORKDIR /workspace
ENV SHELL=/bin/bash
ENTRYPOINT ["bash", "/opt/entrypoint.sh"]
