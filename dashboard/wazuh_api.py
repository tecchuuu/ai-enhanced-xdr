"""
Thin client for the Wazuh manager API (agents, active response).

Auth is JWT: POST /security/user/authenticate with basic auth returns a token
that expires after ~15 minutes; we cache it and re-authenticate on 401.
"""

import os
import time

import httpx

WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.environ.get("WAZUH_API_PASS", "")

_token = None
_token_time = 0
TOKEN_TTL = 800  # refresh before the ~900s server-side expiry


def _authenticate():
    global _token, _token_time
    res = httpx.post(
        f"{WAZUH_API_URL}/security/user/authenticate?raw=true",
        auth=(WAZUH_API_USER, WAZUH_API_PASS),
        verify=False,
        timeout=10,
    )
    res.raise_for_status()
    _token = res.text
    _token_time = time.time()
    return _token


def _request(method, path, **kwargs):
    global _token
    if not _token or time.time() - _token_time > TOKEN_TTL:
        _authenticate()
    headers = {"Authorization": f"Bearer {_token}"}
    res = httpx.request(method, f"{WAZUH_API_URL}{path}", headers=headers,
                        verify=False, timeout=15, **kwargs)
    if res.status_code == 401:          # token expired early — one retry
        _authenticate()
        headers = {"Authorization": f"Bearer {_token}"}
        res = httpx.request(method, f"{WAZUH_API_URL}{path}", headers=headers,
                            verify=False, timeout=15, **kwargs)
    res.raise_for_status()
    return res.json()


def get_agents():
    """Agent inventory with status, for the Agents page."""
    data = _request(
        "GET",
        "/agents?select=id,name,ip,status,os.name,os.version,version,lastKeepAlive&limit=500",
    )["data"]
    return data["affected_items"]


def block_ip(agent_id: str, srcip: str):
    """Trigger the firewall-drop active response on one agent.

    The agent-side AR script adds an iptables DROP for srcip — the same
    mechanism a Wazuh rule-triggered response uses, just initiated manually.
    """
    body = {
        "command": "!firewall-drop",
        "arguments": [],
        "alert": {"data": {"srcip": srcip}},
    }
    return _request("PUT", f"/active-response?agents_list={agent_id}", json=body)


def unblock_ip(agent_id: str, srcip: str):
    """Attempt to remove a firewall-drop previously added for srcip.

    Wazuh's manager API has no documented 'undo' for active response; this sends
    the firewall-drop command tagged as a delete, which the agent AR wrapper
    honours when it supports the add/delete protocol. Callers treat failure as
    non-fatal and fall back to recording intent + agent-side teardown.
    """
    body = {
        "command": "!firewall-drop",
        "arguments": ["delete"],
        "alert": {"data": {"srcip": srcip}},
    }
    return _request("PUT", f"/active-response?agents_list={agent_id}", json=body)
