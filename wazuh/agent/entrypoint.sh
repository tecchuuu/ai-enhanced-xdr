#!/bin/bash
# Configure our containerized Wazuh agent, start it, and stay in the foreground.
# Settings come from the wazuh.agent service in ../docker-compose.yml.
set -euo pipefail

MANAGER_ADDRESS="${MANAGER_ADDRESS:-127.0.0.1}"
MANAGER_PORT="${MANAGER_PORT:-1514}"
ENROLL_PORT="${ENROLL_PORT:-1515}"
AGENT_NAME="${AGENT_NAME:-luckyfive-agent}"

# The whole config is ours, rewritten on every start:
#  - report to OUR manager and enroll there under a name that can't collide
#    with the VM's host agent (which belongs to the other group's Wazuh);
#  - run what this agent is for — Active Response (the console's Block IP).
#    File integrity, rootcheck, SCA and inventory would describe this
#    container's filesystem, not the VM's, so they're off. No <localfile>
#    either: SSH events already reach the manager through its mount of the
#    host's auth.log, and reading it here too would double every event.
cat > /var/ossec/etc/ossec.conf <<EOF
<ossec_config>
  <client>
    <server>
      <address>${MANAGER_ADDRESS}</address>
      <port>${MANAGER_PORT}</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>${MANAGER_ADDRESS}</manager_address>
      <port>${ENROLL_PORT}</port>
      <agent_name>${AGENT_NAME}</agent_name>
    </enrollment>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <rootcheck><disabled>yes</disabled></rootcheck>
  <syscheck><disabled>yes</disabled></syscheck>
  <sca><enabled>no</enabled></sca>
  <wodle name="syscollector"><disabled>yes</disabled></wodle>

  <active-response>
    <disabled>no</disabled>
  </active-response>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
EOF
chown root:wazuh /var/ossec/etc/ossec.conf
chmod 640 /var/ossec/etc/ossec.conf

# The manager container can come up after this one: wait until it listens.
echo "waiting for the manager at ${MANAGER_ADDRESS}:${MANAGER_PORT} ..."
for _ in $(seq 1 60); do
  if (echo > "/dev/tcp/${MANAGER_ADDRESS}/${MANAGER_PORT}") 2>/dev/null; then break; fi
  sleep 5
done

# The first start enrolls (port ${ENROLL_PORT}) and stores the key in
# /var/ossec/etc/client.keys — a volume, so later starts reuse it.
/var/ossec/bin/wazuh-control start

trap '/var/ossec/bin/wazuh-control stop; exit 0' TERM INT
tail -F /var/ossec/logs/ossec.log &
wait $!
