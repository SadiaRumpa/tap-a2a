import json
import struct
import base64
import time
from datetime import datetime
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solana.rpc.api import Client

client = Client("http://127.0.0.1:8899")
PROGRAM_ID = Pubkey.from_string("6uKhjh29AdQxqtWwcNjo8efyPBzwookTPdzzEiozgyiS")
MAX_TIMESTAMP_AGE = 300 # 5 minutes for replay protection

# Audit log file
AUDIT_LOG_FILE = "access_audit_log.json"

def load_agent(filename):
    try:
        with open(filename, "r") as f:
            return Keypair.from_bytes(bytes(json.load(f)))
    except FileNotFoundError:
        return None

def verify_signature(pubkey_bytes, message_bytes, signature_bytes):
    try:
        VerifyKey(pubkey_bytes).verify(message_bytes, signature_bytes)
        return True
    except BadSignatureError:
        return False

def get_pda(seeds):
    return Pubkey.find_program_address(seeds, PROGRAM_ID)[0]

def get_account_data(pda):
    response = client.get_account_info(pda)
    if response.value is None:
        return None
    data = response.value.data
    if isinstance(data, str):
        return base64.b64decode(data)
    elif isinstance(data, tuple):
        return base64.b64decode(data[0])
    return bytes(data)

def check_agent_status(agent_pubkey):
    agent_pda = get_pda([b"agent", bytes(agent_pubkey)])
    account_data = get_account_data(agent_pda)
    if account_data is None:
        return "NOT_REGISTERED"
    data = account_data[8:]
    is_active = struct.unpack('<32s?qB', data)[1]
    return "ACTIVE" if is_active else "REVOKED"

def check_policy(agent_pubkey, resource_id):
    policy_pda = get_pda([b"policy", bytes(agent_pubkey), resource_id.encode('utf-8')])
    policy_data = get_account_data(policy_pda)
    if policy_data is None:
        return None
    policy_data = policy_data[8:]
    offset = 32
    res_id_len = struct.unpack('<I', policy_data[offset:offset+4])[0]
    offset += 4 + res_id_len
    scope_len = struct.unpack('<I', policy_data[offset:offset+4])[0]
    offset += 4
    return policy_data[offset:offset+scope_len].decode('utf-8')

def log_access_decision(agent_pubkey, resource_id, action, decision, reason, timestamp):
    """Log access decision to local audit file"""
    audit_entry = {
        "timestamp": timestamp,
        "datetime": datetime.fromtimestamp(timestamp).isoformat(),
        "agent_pubkey": str(agent_pubkey),
        "resource_id": resource_id,
        "action": action,
        "decision": decision,
        "reason": reason
    }
    
    # Read existing log or create new
    try:
        with open(AUDIT_LOG_FILE, "r") as f:
            audit_log = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        audit_log = []
    
    # Append new entry
    audit_log.append(audit_entry)
    
    # Write back to file
    with open(AUDIT_LOG_FILE, "w") as f:
        json.dump(audit_log, f, indent=2)

def simulate_access(agent, resource_id, action, nonce, timestamp, custom_sig=None):
    payload_str = f"{agent.pubkey()}|{nonce}|{timestamp}|{resource_id}|{action}"
    payload_bytes = payload_str.encode('utf-8')
    
    signature = custom_sig if custom_sig else agent.sign_message(payload_bytes)
    
    # 1. Verify Signature
    if not verify_signature(bytes(agent.pubkey()), payload_bytes, bytes(signature)):
        decision = "DENIED"
        reason = "INVALID_SIGNATURE"
        log_access_decision(agent.pubkey(), resource_id, action, decision, reason, timestamp)
        return decision, reason
    
    # 2. Check Replay (Timestamp Freshness)
    if abs(time.time() - timestamp) > MAX_TIMESTAMP_AGE:
        decision = "DENIED"
        reason = f"REPLAY_ATTACK (Timestamp too old)"
        log_access_decision(agent.pubkey(), resource_id, action, decision, reason, timestamp)
        return decision, reason
    
    # 3. Check Agent Status
    status = check_agent_status(agent.pubkey())
    if status == "NOT_REGISTERED":
        decision = "DENIED"
        reason = "NOT_REGISTERED"
        log_access_decision(agent.pubkey(), resource_id, action, decision, reason, timestamp)
        return decision, reason
    if status == "REVOKED":
        decision = "DENIED"
        reason = "REVOKED"
        log_access_decision(agent.pubkey(), resource_id, action, decision, reason, timestamp)
        return decision, reason
    
    # 4. Check Policy
    allowed_scope = check_policy(agent.pubkey(), resource_id)
    if allowed_scope is None:
        decision = "DENIED"
        reason = "NO_POLICY"
        log_access_decision(agent.pubkey(), resource_id, action, decision, reason, timestamp)
        return decision, reason
    
    if action in allowed_scope.split(','):
        decision = "GRANTED"
        reason = f"Scope: {allowed_scope}"
        log_access_decision(agent.pubkey(), resource_id, action, decision, reason, timestamp)
        return decision, reason
    else:
        decision = "DENIED"
        reason = f"SCOPE_VIOLATION (has: {allowed_scope}, requested: {action})"
        log_access_decision(agent.pubkey(), resource_id, action, decision, reason, timestamp)
        return decision, reason

# =========================================================================
# SCENARIO TESTING
# =========================================================================
print("=" * 80)
print("TAP-A2A COMPREHENSIVE SCENARIO TESTING WITH AUDIT LOGGING")
print("=" * 80)

# Clear previous audit log
try:
    import os
    os.remove(AUDIT_LOG_FILE)
    print(f"🗑️  Cleared previous audit log: {AUDIT_LOG_FILE}\n")
except FileNotFoundError:
    pass

agent_a = load_agent("agent_a_keypair.json")
agent_b = load_agent("agent_b_keypair.json")
agent_c = load_agent("agent_c_keypair.json")
resource_id = "protected_database_1"

# Scenario 1: Agent A - Successful read access
print("\n[SCENARIO 1] Agent A (scope: read) requests 'read' access")
decision, reason = simulate_access(agent_a, resource_id, "read", 1001, int(time.time()))
print(f"  Result: {decision} - {reason}")

# Scenario 2: Agent A - Scope violation (tries to write)
print("\n[SCENARIO 2] Agent A (scope: read) attempts 'write' access")
decision, reason = simulate_access(agent_a, resource_id, "write", 1002, int(time.time()))
print(f"  Result: {decision} - {reason}")

# Scenario 3: Agent B - Successful write access (broader scope)
print("\n[SCENARIO 3] Agent B (scope: read,write) requests 'write' access")
decision, reason = simulate_access(agent_b, resource_id, "write", 1003, int(time.time()))
print(f"  Result: {decision} - {reason}")

# Scenario 4: Replay attack (reuse old timestamp)
print("\n[SCENARIO 4] REPLAY ATTACK - Reusing old timestamp (>5 mins ago)")
old_timestamp = int(time.time()) - 600 # 10 minutes ago
decision, reason = simulate_access(agent_a, resource_id, "read", 1004, old_timestamp)
print(f"  Result: {decision} - {reason}")

# Scenario 5: Invalid Signature (Agent B signs Agent A's payload)
print("\n[SCENARIO 5] INVALID SIGNATURE - Agent B signs Agent A's payload")
payload_str = f"{agent_a.pubkey()}|1005|{int(time.time())}|{resource_id}|read"
payload_bytes = payload_str.encode('utf-8')
fake_sig = agent_b.sign_message(payload_bytes) # Wrong signer!
decision, reason = simulate_access(agent_a, resource_id, "read", 1005, int(time.time()), custom_sig=fake_sig)
print(f"  Result: {decision} - {reason}")

# Scenario 6: Agent C - Revoked
print("\n[SCENARIO 6] Agent C (Revoked) requests 'read' access")
decision, reason = simulate_access(agent_c, resource_id, "read", 1006, int(time.time()))
print(f"  Result: {decision} - {reason}")

# Scenario 7: Agent D - Unregistered
print("\n[SCENARIO 7] Agent D (Unregistered) requests 'read' access")
agent_d = Keypair() # Generate a random, unregistered agent
decision, reason = simulate_access(agent_d, resource_id, "read", 1007, int(time.time()))
print(f"  Result: {decision} - {reason}")

print("\n" + "=" * 80)
print("SCENARIO TESTING COMPLETE")
print(f"✅ All access decisions logged to: {AUDIT_LOG_FILE}")
print("=" * 80)

# Display audit log summary
print(f"\n📊 AUDIT LOG SUMMARY:")
with open(AUDIT_LOG_FILE, "r") as f:
    audit_log = json.load(f)
    print(f"   Total decisions logged: {len(audit_log)}")
    granted = sum(1 for entry in audit_log if entry['decision'] == 'GRANTED')
    denied = sum(1 for entry in audit_log if entry['decision'] == 'DENIED')
    print(f"   Granted: {granted}")
    print(f"   Denied: {denied}")
