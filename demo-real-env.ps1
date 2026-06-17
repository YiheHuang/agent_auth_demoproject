$env:DEMO_USE_LOCAL_REGISTRY = "0"
$env:DEMO_REGISTRY_CLIENT_ID = "huangyihe"
$env:DEMO_REGISTRY_API_KEY = "9_BwTK2z60WAsjE2rvRDNi6B069Nc1-cA7M7A7myJTI"

# Remote registry currently uses HTTP.
$env:DEMO_REGISTRY_URL = "http://192.144.228.237/.well-known/agent.json"
$env:DEMO_REGISTRY_PUBLISH_URL = "http://192.144.228.237/registry/agents/publish"

# Required real Vault configuration.
# The token file should be written by Vault Agent or another trusted bootstrap process.
$env:DEMO_VAULT_ADDR = "http://127.0.0.1:8200"
$env:DEMO_VAULT_TOKEN_FILE = "C:\Users\Yihe Huang\FDU\agent_auth\agent_auth_demoproject\runtime\vault-token.txt"
$env:DEMO_VAULT_TRANSIT_MOUNT = "transit"

# Required Transit key names for the four demo agents.
$env:DEMO_INTAKE_KMS_KEY_ID = "intake-agent"
$env:DEMO_TRIAGE_KMS_KEY_ID = "triage-agent"
$env:DEMO_RESOLVER_KMS_KEY_ID = "resolver-agent"
$env:DEMO_APPROVAL_KMS_KEY_ID = "approval-agent"
