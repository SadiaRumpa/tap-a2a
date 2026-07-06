import json
import time
import struct
import base64
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solana.rpc.api import Client

client = Client("http://127.0.0.1:8899")
PROGRAM_ID = Pubkey.from_string("6uKhjh29AdQxqtWwcNjo8efyPBzwookTPdzzEiozgyiS")

def load_agent(filename):
    with open(filename, "r") as f:
        return Keypair.from_bytes(bytes(json.load(f)))

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

# Performance measurement
agent_a = load_agent("agent_a_keypair.json")
resource_id = "protected_database_1"
iterations = 100

print("=" * 80)
print("TAP-A2A PERFORMANCE MEASUREMENT")
print("=" * 80)
print(f"\nRunning {iterations} iterations...\n")

sig_verify_times = []
blockchain_query_times = []
total_decision_times = []

for i in range(iterations):
    # Create payload
    nonce = i
    timestamp = int(time.time())
    payload_str = f"{agent_a.pubkey()}|{nonce}|{timestamp}|{resource_id}|read"
    payload_bytes = payload_str.encode('utf-8')
    
    # Measure signature verification
    start = time.perf_counter()
    signature = agent_a.sign_message(payload_bytes)
    is_valid = verify_signature(bytes(agent_a.pubkey()), payload_bytes, bytes(signature))
    sig_time = (time.perf_counter() - start) * 1000  # ms
    sig_verify_times.append(sig_time)
    
    # Measure blockchain queries
    start = time.perf_counter()
    status = check_agent_status(agent_a.pubkey())
    scope = check_policy(agent_a.pubkey(), resource_id)
    query_time = (time.perf_counter() - start) * 1000  # ms
    blockchain_query_times.append(query_time)
    
    # Total decision time
    total_time = sig_time + query_time
    total_decision_times.append(total_time)

# Calculate statistics
def calc_stats(times):
    return {
        'min': min(times),
        'max': max(times),
        'avg': sum(times) / len(times),
        'p50': sorted(times)[len(times)//2],
        'p95': sorted(times)[int(len(times)*0.95)]
    }

sig_stats = calc_stats(sig_verify_times)
query_stats = calc_stats(blockchain_query_times)
total_stats = calc_stats(total_decision_times)

print("RESULTS:")
print("-" * 80)
print(f"Signature Verification (Ed25519):")
print(f"  Min: {sig_stats['min']:.2f} ms")
print(f"  Avg: {sig_stats['avg']:.2f} ms")
print(f"  P50: {sig_stats['p50']:.2f} ms")
print(f"  P95: {sig_stats['p95']:.2f} ms")
print(f"  Max: {sig_stats['max']:.2f} ms")

print(f"\nBlockchain Query (Agent + Policy):")
print(f"  Min: {query_stats['min']:.2f} ms")
print(f"  Avg: {query_stats['avg']:.2f} ms")
print(f"  P50: {query_stats['p50']:.2f} ms")
print(f"  P95: {query_stats['p95']:.2f} ms")
print(f"  Max: {query_stats['max']:.2f} ms")

print(f"\nTotal Gateway Decision Time:")
print(f"  Min: {total_stats['min']:.2f} ms")
print(f"  Avg: {total_stats['avg']:.2f} ms")
print(f"  P50: {total_stats['p50']:.2f} ms")
print(f"  P95: {total_stats['p95']:.2f} ms")
print(f"  Max: {total_stats['max']:.2f} ms")

print("\n" + "=" * 80)
print("✅ Performance measurement complete!")
print("=" * 80)

# Save results to JSON for dissertation
results = {
    'signature_verification_ms': sig_stats,
    'blockchain_query_ms': query_stats,
    'total_decision_ms': total_stats,
    'iterations': iterations
}

with open('performance_results.json', 'w') as f:
    json.dump(results, f, indent=2)

print(f"\n📊 Results saved to: performance_results.json")
