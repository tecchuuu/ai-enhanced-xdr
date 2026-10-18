# Our group's Wazuh agent, as a container — see the wazuh.agent service in
# ../docker-compose.yml for why it isn't the VM's own (host) agent.
# Pinned to the manager's version: an agent must not be newer than its manager.
FROM ubuntu:24.04

ARG WAZUH_VERSION=4.14.1-1
ENV DEBIAN_FRONTEND=noninteractive

# Wazuh's documented apt install; iptables for the firewall-drop active response
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg iptables iproute2 procps \
 && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
 && chmod 644 /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends "wazuh-agent=${WAZUH_VERSION}" \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
