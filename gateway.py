import base64
import json
import sys

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solana.rpc.api import Client

from tap_a2a_common import (
    RPC_URL, load_program_id, agent_pda, policy_pda, config_pda,
    action_hash, current_epoch, access_nullifier,
    parse_agent_record, parse_policy_record,
)


def fetch_account_data(client: Client, pda: Pubkey):
    resp = client.get_account_info(pda)
    if resp.value is None:
        return None
    data = resp.value.data
    if isinstance(data, str):
        return base64.b64decode(data)
    if isinstance(data, tuple):
        return base64.b64decode(data[0])
    return bytes(data)


def verify_signature(pubkey_bytes: bytes, message: bytes, signature: bytes) -> bool:
    try:
        VerifyKey(pubkey_bytes).verify(message, signature)
        return True
    except BadSignatureError:
        return False


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python3 gateway.py <group_id_hex> <action_name>")
        return 2

    group_id = bytes.fromhex(sys.argv[1])
    action_name = sys.argv[2]
    action = action_hash(action_name)
    epoch = current_epoch()

    client = Client(RPC_URL)
    program_id = load_program_id()

    cfg = fetch_account_data(client, config_pda(program_id))
    if cfg is None:
        print("ABORT: protocol not initialised — run initialize first.")
        return 1

    print("--- PHASE 1: AGENT SIGNING ---")
    with open("agent_keypair.json") as f:
        agent = Keypair.from_bytes(bytes(json.load(f)))
    agent_pubkey = agent.pubkey()
    print(f"Agent:   {agent_pubkey}")
    print(f"Program: {program_id}")
    print(f"Action:  {action_name}")
    print(f"Epoch:   {epoch}")

    # The payload binds the request to the exact nullifier the program
    # will recompute, so the signature commits to a specific
    # (agent, group, action, epoch) rather than to free-form text.
    nullifier = access_nullifier(agent_pubkey, group_id, action, epoch)
    payload = bytes(agent_pubkey) + group_id + bytes(action) + bytes(nullifier) + epoch.to_bytes(8, "little")
    signature = agent.sign_message(payload)
    print("Payload signed (bound to this epoch's nullifier).\n")

    print("--- PHASE 2: SIGNATURE VERIFICATION ---")
    if not verify_signature(bytes(agent_pubkey), payload, bytes(signature)):
        print("ACCESS DENIED: invalid signature.")
        return 1
    print("Signature valid.\n")

    print("--- PHASE 3: ON-CHAIN STATE ---")
    raw_agent = fetch_account_data(client, agent_pda(program_id, agent_pubkey))
    if raw_agent is None:
        print("ACCESS DENIED: agent not registered.")
        return 1

    record = parse_agent_record(raw_agent[8:])  # strip Anchor discriminator
    print(f"AgentRecord found. Active: {record['is_active']}")
    if not record["is_active"]:
        print("ACCESS DENIED: agent revoked.")
        return 1
    if record["agent_group_id"] != group_id:
        print("ACCESS DENIED: agent belongs to a different group than supplied.")
        return 1

    raw_policy = fetch_account_data(client, policy_pda(program_id, group_id, action))
    if raw_policy is None:
        print(f"ACCESS DENIED: no policy exists for this group and {action_name}.")
        return 1

    policy = parse_policy_record(raw_policy[8:])
    print(f"PolicyRecord found. Allowed: {policy['is_allowed']}\n")

    print("--- PHASE 4: DECISION ---")
    if policy["is_allowed"]:
        print(f"ACCESS GRANTED: agent authorised for {action_name}.")
        print("NOTE: advisory only. The binding decision is the program's, "
              "taken when log_traceable_access executes.")
        return 0

    print("ACCESS DENIED: policy explicitly denies this action.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
