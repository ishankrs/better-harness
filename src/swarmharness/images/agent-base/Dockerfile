FROM node:22-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

ARG OPENCODE_VERSION=1.18.4
RUN npm i -g "opencode-ai@${OPENCODE_VERSION}" && opencode --version

RUN useradd -ms /bin/bash agent

COPY gen_config.py export_trajectory.py entrypoint.sh /opt/
RUN chmod 644 /opt/gen_config.py /opt/export_trajectory.py && chmod 755 /opt/entrypoint.sh \
    && mkdir -p /logs/agent /workspace /task \
    && chown -R agent:agent /logs /workspace /task

USER agent
WORKDIR /workspace
ENV SHELL=/bin/bash
ENTRYPOINT ["bash", "/opt/entrypoint.sh"]
