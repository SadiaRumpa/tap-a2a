import json
import struct
import base64
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solana.rpc.api import Client

# Connect to local Solana validator
client = Client("http://127.0.0.1:8899")
PROGRAM_ID = Pubkey.from_string("6uKhjh29AdQxqtWwcNjo8efyPBzwookTPdzzEiozgyiS")

# =========================================================================
# 1. LOAD AGENT & SIMULATE SIGNED REQUEST
# =========================================================================
print("--- PHASE 1: AGENT SIGNING ---")
with open("agent_keypair.json", "r") as f:
    keypair_bytes = bytes(json.load(f))
agent = Keypair.from_bytes(keypair_bytes)
agent_pubkey = agent.pubkey()
print(f"Loaded Agent: {agent_pubkey}")

# Create payload
resource_id = "protected_database_1"
action = "read"
nonce = 98765
timestamp = 1700000000

payload_str = f"{agent_pubkey}|{nonce}|{timestamp}|{resource_id}|{action}"
payload_bytes = payload_str.encode('utf-8')

# Agent signs the payload
signature = agent.sign_message(payload_bytes)
print(f"✅ Agent signed payload. Sig: {str(signature)[:20]}...\n")

# =========================================================================
# 2. GATEWAY: VERIFY SIGNATURE
# =========================================================================
print("--- PHASE 2: GATEWAY SIGNATURE VERIFICATION ---")
def verify_signature(pubkey_bytes, message_bytes, signature_bytes):
    try:
        verify_key = VerifyKey(pubkey_bytes)
        verify_key.verify(message_bytes, signature_bytes)
        return True
    except BadSignatureError:
        return False

is_valid_sig = verify_signature(bytes(agent_pubkey), payload_bytes, bytes(signature))
print(f"✅ Signature valid? {is_valid_sig}\n")

if not is_valid_sig:
    print("❌ ACCESS DENIED: Invalid signature.")
    exit()

# =========================================================================
# 3. GATEWAY: CHECK BLOCKCHAIN STATE (MANUAL DESERIALIZATION)
# =========================================================================
print("--- PHASE 3: BLOCKCHAIN STATE VERIFICATION ---")

def get_pda(seeds):
    pda, bump = Pubkey.find_program_address(seeds, PROGRAM_ID)
    return pda

def get_account_data(pda):
    response = client.get_account_info(pda)
    if response.value is None:
        return None
    data = response.value.data
    # Safely handle base64 encoding returned by Solana RPC
    if isinstance(data, str):
        return base64.b64decode(data)
    elif isinstance(data, tuple):
        return base64.b64decode(data[0])
    return bytes(data)

# Check AgentRegistry
agent_seeds = [b"agent", bytes(agent_pubkey)]
agent_pda = get_pda(agent_seeds)

account_data = get_account_data(agent_pda)
if account_data is None:
    print(f"❌ ACCESS DENIED: Agent not registered.")
    exit()

# Deserialize AgentRegistry (Skip 8-byte Anchor discriminator)
data = account_data[8:]
unpacked = struct.unpack('<32s?qB', data)
is_active = unpacked[1]
print(f"✅ AgentRegistry found on-chain. Active: {is_active}")

if not is_active:
    print("❌ ACCESS DENIED: Agent is revoked/inactive.")
    exit()

# Check PolicyStore
policy_seeds = [b"policy", bytes(agent_pubkey), resource_id.encode('utf-8')]
policy_pda = get_pda(policy_seeds)

policy_data = get_account_data(policy_pda)
if policy_data is None:
    print(f"❌ ACCESS DENIED: No policy found for resource.")
    exit()

# Deserialize PolicyStore (Skip 8-byte discriminator)
policy_data = policy_data[8:]
offset = 32 # skip agent_pubkey

res_id_len = struct.unpack('<I', policy_data[offset:offset+4])[0]
offset += 4
res_id = policy_data[offset:offset+res_id_len].decode('utf-8')
offset += res_id_len

scope_len = struct.unpack('<I', policy_data[offset:offset+4])[0]
offset += 4
allowed_scope = policy_data[offset:offset+scope_len].decode('utf-8')

print(f"✅ PolicyStore found on-chain. Scope: '{allowed_scope}'\n")

# =========================================================================
# 4. GATEWAY: ENFORCE LEAST PRIVILEGE
# =========================================================================
print("--- PHASE 4: ACCESS DECISION ---")
if action in allowed_scope.split(','):
    print(f"🎉 ACCESS GRANTED: Agent authorized to '{action}' on '{resource_id}'.")
else:
    print(f"❌ ACCESS DENIED: Scope '{allowed_scope}' does not include '{action}'.")
