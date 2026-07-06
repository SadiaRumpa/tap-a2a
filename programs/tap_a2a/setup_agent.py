from solders.keypair import Keypair
import json

# Generate a brand new cryptographic identity for our Agent
agent = Keypair()
print(f"🔑 Generated Agent Public Key: {agent.pubkey()}")

# Save the 64-byte keypair (32 byte secret + 32 byte public) to a JSON file
with open("agent_keypair.json", "w") as f:
    json.dump(list(bytes(agent)), f)

print("✅ Saved agent_keypair.json. Now we will register this exact agent on-chain!")

