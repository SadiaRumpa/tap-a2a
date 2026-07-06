import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TapA2a } from "../target/types/tap_a2a";
import * as fs from "fs";
import * as path from "path";

describe("TAP-A2A Multi-Agent Tests", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.TapA2a as Program<TapA2a>;
  const provider = anchor.getProvider();

  const resourceId = "protected_database_1";

  async function loadAgent(filename: string) {
    const keypairPath = path.join(process.cwd(), filename);
    const secretKeyArray = JSON.parse(fs.readFileSync(keypairPath, "utf-8"));
    return anchor.web3.Keypair.fromSecretKey(Uint8Array.from(secretKeyArray));
  }

  async function registerAndSetPolicy(agentKeypair: anchor.web3.Keypair, scope: string) {
    const airdropSig = await provider.connection.requestAirdrop(
      agentKeypair.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(airdropSig);

    const [agentRegistryPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("agent"), agentKeypair.publicKey.toBuffer()],
      program.programId
    );

    await program.methods
      .registerAgent()
      .accounts({
        agent: agentKeypair.publicKey,
        agentRegistry: agentRegistryPda,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([agentKeypair])
      .rpc();

    const [policyStorePda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("policy"), agentKeypair.publicKey.toBuffer(), Buffer.from(resourceId)],
      program.programId
    );

    await program.methods
      .setPolicy(resourceId, scope)
      .accounts({
        authority: agentKeypair.publicKey,
        agent: agentKeypair.publicKey,
        policyStore: policyStorePda,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([agentKeypair])
      .rpc();

    console.log(`✅ Registered and set policy for ${agentKeypair.publicKey.toBase58()}: ${scope}`);
    return agentRegistryPda;
  }

  it("Registers Agents A, B, C and Revokes C!", async () => {
    const agentA = await loadAgent("agent_a_keypair.json");
    const agentB = await loadAgent("agent_b_keypair.json");
    const agentC = await loadAgent("agent_c_keypair.json");

    await registerAndSetPolicy(agentA, "read");
    await registerAndSetPolicy(agentB, "read,write");
    const agentCRegistryPda = await registerAndSetPolicy(agentC, "read");

    // REVOKE AGENT C
    const [revocationRegistryPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("revocation"), agentC.publicKey.toBuffer()],
      program.programId
    );

    await program.methods
      .revokeAgent("Suspicious activity detected")
      .accounts({
        authority: agentC.publicKey,
        agentRegistry: agentCRegistryPda,
        revocationRegistry: revocationRegistryPda,
        agent: agentC.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([agentC])
      .rpc();

    console.log(`✅ REVOKED Agent C: ${agentC.publicKey.toBase58()}`);
    console.log("\n✅ All scenarios set up on-chain!");
  });
});

