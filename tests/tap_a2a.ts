import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TapA2a } from "../target/types/tap_a2a";
import { assert } from "chai";
import { PublicKey, SystemProgram, Keypair } from "@solana/web3.js";
import { createHash } from "crypto";

// Must equal EPOCH_SECONDS in lib.rs.
const EPOCH_SECONDS = 3600;

describe("TAP-A2A Access Control Lifecycle", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.TapA2a as Program<TapA2a>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const admin = provider.wallet.publicKey;

  function generateBytes32(): number[] {
    return Array.from(crypto.getRandomValues(new Uint8Array(32)));
  }

  function actionHash(name: string): number[] {
    return Array.from(
      createHash("sha256").update(Buffer.concat([Buffer.from("tap-a2a-action"), Buffer.from(name)])).digest()
    );
  }

  function currentEpoch(): anchor.BN {
    return new anchor.BN(Math.floor(Date.now() / 1000 / EPOCH_SECONDS));
  }

  // Mirrors the on-chain derivation:
  //   sha256("tap-a2a-nullifier" || agent || group || action || epoch_le)
  function accessNullifier(
    agent: PublicKey, groupId: number[], action: number[], epoch: anchor.BN
  ): number[] {
    const epochLe = Buffer.alloc(8);
    epochLe.writeBigUInt64LE(BigInt(epoch.toString()));
    return Array.from(
      createHash("sha256")
        .update(Buffer.concat([
          Buffer.from("tap-a2a-nullifier"),
          agent.toBuffer(),
          Buffer.from(groupId),
          Buffer.from(action),
          epochLe,
        ]))
        .digest()
    );
  }

  const [configPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("config")], program.programId
  );
  const agentPda = (a: PublicKey) =>
    PublicKey.findProgramAddressSync([Buffer.from("agent"), a.toBuffer()], program.programId)[0];
  const policyPda = (g: number[], a: number[]) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("policy"), Buffer.from(g), Buffer.from(a)], program.programId)[0];
  const tracePda = (n: number[]) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("trace_log"), Buffer.from(n)], program.programId)[0];

  let agentA: Keypair, agentB: Keypair, rogue: Keypair;
  let groupId: number[], action: number[], epoch: anchor.BN;

  before(async () => {
    agentA = Keypair.generate();
    agentB = Keypair.generate();
    rogue = Keypair.generate();
    groupId = generateBytes32();
    action = actionHash("READ_DATABASE");
    epoch = currentEpoch();

    for (const kp of [agentA, agentB, rogue]) {
      await provider.connection.confirmTransaction(
        await provider.connection.requestAirdrop(kp.publicKey, 1_000_000_000),
        "confirmed"
      );
    }

    // Idempotent: the config may already exist from a previous run.
    try {
      await program.methods.initialize().accounts({
        admin, config: configPda, systemProgram: SystemProgram.programId,
      }).rpc();
    } catch (e: any) {
      if (!e.message.includes("already in use")) throw e;
    }
  });

  it("1. Fixes the admin authority in Config", async () => {
    const config = await program.account.config.fetch(configPda);
    assert.isTrue(config.admin.equals(admin), "Config admin should be the provider wallet");
  });

  it("2. Rejects a rogue key attempting to register an agent", async () => {
    try {
      await program.methods.registerAgent(groupId).accounts({
        admin: rogue.publicKey,
        config: configPda,
        newAgent: agentB.publicKey,
        agentRecord: agentPda(agentB.publicKey),
        systemProgram: SystemProgram.programId,
      }).signers([rogue]).rpc();
      assert.fail("A non-admin must not be able to register agents");
    } catch (err: any) {
      assert.include(err.message, "UnauthorizedAdmin");
    }
  });

  it("3. Registers Agent A and sets a policy", async () => {
    await program.methods.registerAgent(groupId).accounts({
      admin, config: configPda,
      newAgent: agentA.publicKey,
      agentRecord: agentPda(agentA.publicKey),
      systemProgram: SystemProgram.programId,
    }).rpc();

    // Agent B is registered too, so the impersonation test below fails
    // on the seeds constraint rather than on a missing account.
    await program.methods.registerAgent(groupId).accounts({
      admin, config: configPda,
      newAgent: agentB.publicKey,
      agentRecord: agentPda(agentB.publicKey),
      systemProgram: SystemProgram.programId,
    }).rpc();

    await program.methods.setPolicy(groupId, action, true).accounts({
      admin, config: configPda,
      policyRecord: policyPda(groupId, action),
      systemProgram: SystemProgram.programId,
    }).rpc();

    const record = await program.account.agentRecord.fetch(agentPda(agentA.publicKey));
    assert.isTrue(record.isActive);
    const policy = await program.account.policyRecord.fetch(policyPda(groupId, action));
    assert.isTrue(policy.isAllowed);
  });

  it("4. Rejects a FORGED nullifier", async () => {
    // The scenario that matters for traceability: an agent supplying
    // random bytes rather than the correct derivation. Before the
    // nullifier was verified on-chain this attack succeeded silently.
    const forged = generateBytes32();
    try {
      await program.methods.logTraceableAccess(action, forged, epoch).accounts({
        agent: agentA.publicKey,
        agentRecord: agentPda(agentA.publicKey),
        policyRecord: policyPda(groupId, action),
        traceLog: tracePda(forged),
        systemProgram: SystemProgram.programId,
      }).signers([agentA]).rpc();
      assert.fail("A forged nullifier must be rejected");
    } catch (err: any) {
      assert.include(err.message, "InvalidNullifier");
    }
  });

  it("5. Grants access with the correct nullifier, then blocks the replay", async () => {
    const nullifier = accessNullifier(agentA.publicKey, groupId, action, epoch);
    const accounts = {
      agent: agentA.publicKey,
      agentRecord: agentPda(agentA.publicKey),
      policyRecord: policyPda(groupId, action),
      traceLog: tracePda(nullifier),
      systemProgram: SystemProgram.programId,
    };

    await program.methods.logTraceableAccess(action, nullifier, epoch)
      .accounts(accounts).signers([agentA]).rpc();

    const log = await program.account.traceabilityLog.fetch(tracePda(nullifier));
    assert.isTrue(log.agentPubkey.equals(agentA.publicKey));

    try {
      await program.methods.logTraceableAccess(action, nullifier, epoch)
        .accounts(accounts).signers([agentA]).rpc();
      assert.fail("Reusing a nullifier in the same epoch must fail");
    } catch (err: any) {
      assert.include(err.message, "already in use");
    }
  });

  it("6. Honours a policy flipped from allow to deny", async () => {
    const other = actionHash("WRITE_REPORT");
    await program.methods.setPolicy(groupId, other, true).accounts({
      admin, config: configPda,
      policyRecord: policyPda(groupId, other),
      systemProgram: SystemProgram.programId,
    }).rpc();

    await program.methods.updatePolicy(false).accounts({
      admin, config: configPda, policyRecord: policyPda(groupId, other),
    }).rpc();

    const nullifier = accessNullifier(agentA.publicKey, groupId, other, epoch);
    try {
      await program.methods.logTraceableAccess(other, nullifier, epoch).accounts({
        agent: agentA.publicKey,
        agentRecord: agentPda(agentA.publicKey),
        policyRecord: policyPda(groupId, other),
        traceLog: tracePda(nullifier),
        systemProgram: SystemProgram.programId,
      }).signers([agentA]).rpc();
      assert.fail("A denied policy must block access");
    } catch (err: any) {
      assert.include(err.message, "PolicyDenied");
    }
  });

  it("7. Blocks a revoked agent", async () => {
    // A fresh action is essential: Anchor validates the `init` constraint
    // on trace_log BEFORE the handler body, so reusing an already-consumed
    // action would fail with "already in use" rather than AgentRevoked.
    const fresh = actionHash("ARCHIVE_LOGS");
    await program.methods.setPolicy(groupId, fresh, true).accounts({
      admin, config: configPda,
      policyRecord: policyPda(groupId, fresh),
      systemProgram: SystemProgram.programId,
    }).rpc();

    await program.methods.revokeAgent().accounts({
      admin, config: configPda,
      targetAgent: agentA.publicKey,
      agentRecord: agentPda(agentA.publicKey),
    }).rpc();

    const record = await program.account.agentRecord.fetch(agentPda(agentA.publicKey));
    assert.isFalse(record.isActive);

    const nullifier = accessNullifier(agentA.publicKey, groupId, fresh, epoch);
    try {
      await program.methods.logTraceableAccess(fresh, nullifier, epoch).accounts({
        agent: agentA.publicKey,
        agentRecord: agentPda(agentA.publicKey),
        policyRecord: policyPda(groupId, fresh),
        traceLog: tracePda(nullifier),
        systemProgram: SystemProgram.programId,
      }).signers([agentA]).rpc();
      assert.fail("A revoked agent must be denied");
    } catch (err: any) {
      assert.include(err.message, "AgentRevoked");
    }
  });
  it("8. Blocks impersonation: the record must belong to the signer", async () => {
    // Agent B signs a well-formed request but presents Agent A's
    // AgentRecord. lib.rs seeds agent_record on [b"agent", agent.key()],
    // binding the record to the signer, so Anchor rejects the mismatch
    // during ACCOUNT VALIDATION -- before any handler logic runs. That
    // ordering is why Agent A's revoked state at this point does not
    // affect what is being tested.
    //
    // Note this is not a "malformed signature" test: the Solana runtime
    // verifies signatures before the program is invoked, so a bad
    // signature never reaches TAP-A2A. Presenting a VALID signature over
    // someone else's identity is the attack the program must defeat.
    // This is the empirical counterpart of the impersonation_resistance
    // lemma in tap_a2a.spthy.
    const impersonated = actionHash("READ_CONFIDENTIAL");
    await program.methods.setPolicy(groupId, impersonated, true).accounts({
      admin, config: configPda,
      policyRecord: policyPda(groupId, impersonated),
      systemProgram: SystemProgram.programId,
    }).rpc();

    const nullifier = accessNullifier(agentB.publicKey, groupId, impersonated, epoch);
    try {
      await program.methods.logTraceableAccess(impersonated, nullifier, epoch).accounts({
        agent: agentB.publicKey,
        agentRecord: agentPda(agentA.publicKey),   // NOT agentB's record
        policyRecord: policyPda(groupId, impersonated),
        traceLog: tracePda(nullifier),
        systemProgram: SystemProgram.programId,
      }).signers([agentB]).rpc();
      assert.fail("Presenting another agent's record must be blocked");
    } catch (err: any) {
      assert.include(err.message, "ConstraintSeeds");
    }
  });
});
