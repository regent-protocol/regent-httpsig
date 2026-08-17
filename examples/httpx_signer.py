"""Sign your agent's outbound requests (Web Bot Auth).

1. Generate a key and well-known files:
       regent-httpsig keygen --agent https://myagent.example --out ./well-known/
2. Serve ./well-known/ at https://myagent.example/.well-known/
3. Sign every request:
"""

import os

import httpx

from regent_httpsig import EgressSigner

signer = EgressSigner(
    seed=os.environ["AGENT_KEY_SEED"],
    signature_agent="https://myagent.example",
)

url = "https://get4agent.com/v1/agents/register"
body = {"name": "Example Agent", "intent": "buy market data"}
headers = signer.sign("POST", url, {"content-type": "application/json"})

resp = httpx.post(url, json=body, headers=headers)
print(resp.status_code, resp.text[:200])
