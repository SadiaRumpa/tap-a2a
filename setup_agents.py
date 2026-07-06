import json
from solders.keypair import Keypair

agents = {
    "agent_a": {"scope": "read"},
    "agent_b": {"scope": "read,write"},
    "agent_c": {"scope": "read"},  # Will be revoked later
    # Agent D is intentionally NOT registered
}

for agent_name, config in agents.items():
    agent = Keypair()
    pubkey = str(agent.pubkey())
    
    # Save keypair
    with open(f"{agent_name}_keypair.json", "w") as f:
        json.dump(list(bytes(agent)), f)
    
    print(f"✅ Generated {agent_name}: {pubkey} (scope: {config['scope']})")

print("\n✅ All agents generated. Now register them on-chain!")
