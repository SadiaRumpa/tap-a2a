use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;

declare_id!("7Bai6A8ANjhLcGHPWQXExAbPRYZ9jUxtFEzQq3FgDiDK");

/// Length of one access epoch, in seconds.
///
/// The nullifier is bound to an epoch so that "one access per agent,
/// per action, per epoch" is enforced by the runtime rather than by
/// client good behaviour. Shorten this for a stricter policy; lengthen
/// it to reduce trace-log account churn. This is the single knob for
/// the security/performance trade-off discussed in the evaluation.
pub const EPOCH_SECONDS: i64 = 3600;

#[program]
pub mod tap_a2a {
    use super::*;

    /// Initialise the protocol and fix the administrative authority.
    ///
    /// MUST be called once immediately after deployment. Until this
    /// runs, no agent can be registered and no policy can be set.
    ///
    /// Previously there was no Config account at all, which meant
    /// `admin: Signer` in the instructions below was satisfied by ANY
    /// funded keypair -- so any party could self-register, author a
    /// permissive policy, or revoke another agent.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.bump = ctx.bumps.config;

        msg!("TAP-A2A: initialised with admin {}", config.admin);
        Ok(())
    }

    /// Transfer administrative authority to a new key.
    pub fn set_admin(ctx: Context<SetAdmin>, new_admin: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let previous = config.admin;
        config.admin = new_admin;

        msg!("TAP-A2A: admin transferred from {} to {}", previous, new_admin);
        Ok(())
    }

    /// Register a new AI agent into an agent group.
    ///
    /// Callable only by the configured admin.
    pub fn register_agent(
        ctx: Context<RegisterAgent>,
        agent_group_id: [u8; 32],
    ) -> Result<()> {
        let agent = &mut ctx.accounts.agent_record;

        agent.agent_pubkey = ctx.accounts.new_agent.key();
        agent.agent_group_id = agent_group_id;
        agent.is_active = true;
        agent.bump = ctx.bumps.agent_record;

        msg!("TAP-A2A: Agent {} registered successfully", agent.agent_pubkey);
        Ok(())
    }

    /// Create a least-privilege policy for an agent group and action.
    ///
    /// A policy is uniquely identified by [agent_group_id, action_hash].
    /// Callable only by the configured admin.
    pub fn set_policy(
        ctx: Context<SetPolicy>,
        agent_group_id: [u8; 32],
        action_hash: [u8; 32],
        is_allowed: bool,
    ) -> Result<()> {
        let policy = &mut ctx.accounts.policy_record;

        policy.agent_group_id = agent_group_id;
        policy.action_hash = action_hash;
        policy.is_allowed = is_allowed;
        policy.bump = ctx.bumps.policy_record;

        msg!("TAP-A2A: Policy created. Group/action allowed = {}", is_allowed);
        Ok(())
    }

    /// Flip an existing policy between allow and deny.
    ///
    /// `set_policy` uses `init`, so it can only ever create. Without
    /// this instruction a policy was immutable once written, meaning
    /// the "policy update and revocation" capability claimed in the
    /// system model had no implementation behind it.
    pub fn update_policy(ctx: Context<UpdatePolicy>, is_allowed: bool) -> Result<()> {
        let policy = &mut ctx.accounts.policy_record;
        policy.is_allowed = is_allowed;

        msg!("TAP-A2A: Policy updated. Allowed = {}", is_allowed);
        Ok(())
    }

    /// Revoke an agent. Callable only by the configured admin.
    pub fn revoke_agent(ctx: Context<RevokeAgent>) -> Result<()> {
        let agent = &mut ctx.accounts.agent_record;

        require!(agent.is_active, CustomError::AgentAlreadyRevoked);
        agent.is_active = false;

        msg!("TAP-A2A: Agent {} has been revoked", agent.agent_pubkey);
        Ok(())
    }

    /// Log a traceable access request.
    ///
    /// Access is granted only if:
    ///   1. The requesting agent is registered and signs the request.
    ///   2. The agent is active.
    ///   3. A policy exists for the agent's group and requested action.
    ///   4. The policy allows the action.
    ///   5. The supplied nullifier is the correct derivation for this
    ///      (agent, group, action, epoch).
    ///   6. That nullifier has not previously been used.
    ///
    /// Check 5 is the important addition. Previously the nullifier was
    /// an opaque caller-supplied value used only as a PDA seed, so an
    /// agent could submit fresh random bytes on every request and
    /// obtain unlimited unlinkable accesses. Replay protection only
    /// caught a caller who resubmitted a byte-identical nullifier --
    /// something no adversary would do. Deriving it on-chain from the
    /// signer's own public key makes the one-access-per-epoch rule
    /// enforceable rather than advisory.
    ///
    /// NOTE ON ANONYMITY: this nullifier is deterministic and derived
    /// from public inputs, so anyone can compute it and link an access
    /// to its agent. That is a deliberate trade -- the current design
    /// offers accountability, not anonymity. Do not describe it as a
    /// traceable ring signature. A genuine TRS would derive the key
    /// image from the agent's SECRET key and verify a ring-membership
    /// proof on-chain; see the dissertation's future-work section.
    pub fn log_traceable_access(
        ctx: Context<LogAccess>,
        action_hash: [u8; 32],
        nullifier: [u8; 32],
        epoch: u64,
    ) -> Result<()> {
        let agent = &ctx.accounts.agent_record;
        let policy = &ctx.accounts.policy_record;

        // --- Check 1: agent must be active -------------------------
        require!(agent.is_active, CustomError::AgentRevoked);

        // --- Check 2: policy must explicitly allow the action -------
        require!(policy.is_allowed, CustomError::PolicyDenied);

        // --- Check 3: epoch must be current (or the one just past) --
        //
        // A one-epoch grace window absorbs clock skew between the
        // client deriving the PDA and the validator processing the
        // transaction. Without the bound, an agent could pre-compute
        // nullifiers for arbitrary future epochs.
        let now = Clock::get()?.unix_timestamp;
        let current_epoch = (now / EPOCH_SECONDS) as u64;
        require!(
            epoch == current_epoch || epoch + 1 == current_epoch,
            CustomError::InvalidEpoch
        );

        // --- Check 4: nullifier must be correctly derived -----------
        let expected = hashv(&[
            b"tap-a2a-nullifier",
            ctx.accounts.agent.key().as_ref(),
            agent.agent_group_id.as_ref(),
            action_hash.as_ref(),
            &epoch.to_le_bytes(),
        ])
        .to_bytes();
        require!(nullifier == expected, CustomError::InvalidNullifier);

        // --- Check 5: uniqueness -----------------------------------
        //
        // trace_log is initialised at [b"trace_log", nullifier], so a
        // second access with the same nullifier fails at account
        // creation. Combined with check 4, this now genuinely bounds
        // an agent to one access per action per epoch.
        let log_entry = &mut ctx.accounts.trace_log;

        log_entry.agent_pubkey = agent.agent_pubkey;
        log_entry.agent_group_id = agent.agent_group_id;
        log_entry.action_hash = action_hash;
        log_entry.nullifier = nullifier;
        log_entry.epoch = epoch;
        log_entry.timestamp = now;
        log_entry.bump = ctx.bumps.trace_log;

        msg!("TAP-A2A: Access GRANTED and logged.");
        msg!("Agent: {} | Epoch: {}", log_entry.agent_pubkey, epoch);

        Ok(())
    }
}

// ============================================================================
// ACCOUNT CONTEXTS
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        init,
        payer = admin,
        space = 8 + Config::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetAdmin<'info> {
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump,
        has_one = admin @ CustomError::UnauthorizedAdmin
    )]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
#[instruction(agent_group_id: [u8; 32])]
pub struct RegisterAgent<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    /// Protocol configuration. `has_one = admin` is what actually
    /// restricts this instruction to the real authority.
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = admin @ CustomError::UnauthorizedAdmin
    )]
    pub config: Account<'info, Config>,

    /// Public key of the agent being registered. Does not sign.
    pub new_agent: SystemAccount<'info>,

    #[account(
        init,
        payer = admin,
        space = 8 + AgentRecord::INIT_SPACE,
        seeds = [b"agent", new_agent.key().as_ref()],
        bump
    )]
    pub agent_record: Account<'info, AgentRecord>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(agent_group_id: [u8; 32], action_hash: [u8; 32])]
pub struct SetPolicy<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = admin @ CustomError::UnauthorizedAdmin
    )]
    pub config: Account<'info, Config>,

    #[account(
        init,
        payer = admin,
        space = 8 + PolicyRecord::INIT_SPACE,
        seeds = [b"policy", agent_group_id.as_ref(), action_hash.as_ref()],
        bump
    )]
    pub policy_record: Account<'info, PolicyRecord>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdatePolicy<'info> {
    pub admin: Signer<'info>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = admin @ CustomError::UnauthorizedAdmin
    )]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [
            b"policy",
            policy_record.agent_group_id.as_ref(),
            policy_record.action_hash.as_ref()
        ],
        bump = policy_record.bump
    )]
    pub policy_record: Account<'info, PolicyRecord>,
}

#[derive(Accounts)]
pub struct RevokeAgent<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = admin @ CustomError::UnauthorizedAdmin
    )]
    pub config: Account<'info, Config>,

    /// CHECK: used only to derive the deterministic AgentRecord PDA.
    pub target_agent: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [b"agent", target_agent.key().as_ref()],
        bump = agent_record.bump
    )]
    pub agent_record: Account<'info, AgentRecord>,
}

#[derive(Accounts)]
#[instruction(action_hash: [u8; 32], nullifier: [u8; 32], epoch: u64)]
pub struct LogAccess<'info> {
    /// The AI agent requesting access. Pays for its own trace record.
    #[account(mut)]
    pub agent: Signer<'info>,

    /// The PDA seeds bind this record to the signing agent, so an
    /// agent cannot present another agent's registration.
    #[account(
        seeds = [b"agent", agent.key().as_ref()],
        bump = agent_record.bump
    )]
    pub agent_record: Account<'info, AgentRecord>,

    /// Seeding from `agent_record.agent_group_id` (rather than a
    /// caller-supplied group) is what prevents an agent presenting a
    /// permissive policy belonging to a different group.
    #[account(
        seeds = [
            b"policy",
            agent_record.agent_group_id.as_ref(),
            action_hash.as_ref()
        ],
        bump = policy_record.bump
    )]
    pub policy_record: Account<'info, PolicyRecord>,

    #[account(
        init,
        payer = agent,
        space = 8 + TraceabilityLog::INIT_SPACE,
        seeds = [b"trace_log", nullifier.as_ref()],
        bump
    )]
    pub trace_log: Account<'info, TraceabilityLog>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// DATA ACCOUNTS
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Config {
    /// The only key permitted to register, revoke, or author policy.
    pub admin: Pubkey,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct AgentRecord {
    pub agent_pubkey: Pubkey,
    pub agent_group_id: [u8; 32],
    pub is_active: bool,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct PolicyRecord {
    pub agent_group_id: [u8; 32],
    pub action_hash: [u8; 32],
    pub is_allowed: bool,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct TraceabilityLog {
    pub agent_pubkey: Pubkey,
    pub agent_group_id: [u8; 32],
    pub action_hash: [u8; 32],
    pub nullifier: [u8; 32],
    /// Epoch this access was consumed in.
    pub epoch: u64,
    pub timestamp: i64,
    pub bump: u8,
}

// ============================================================================
// CUSTOM ERRORS
// ============================================================================
//
// Anchor assigns codes from 6000 in DECLARATION ORDER. The two new
// variants are appended at the end so existing codes 6000-6004 keep
// their meaning and tap_a2a_common.ErrorCode stays valid.

#[error_code]
pub enum CustomError {
    #[msg("This agent has been revoked and cannot perform actions.")]
    AgentRevoked, // 6000

    #[msg("The policy explicitly denies this action for this agent group.")]
    PolicyDenied, // 6001

    #[msg("This agent is already revoked.")]
    AgentAlreadyRevoked, // 6002

    #[msg("The policy belongs to a different agent group.")]
    PolicyGroupMismatch, // 6003

    #[msg("The policy does not correspond to the requested action.")]
    PolicyActionMismatch, // 6004

    #[msg("The supplied nullifier is not the correct derivation for this agent, action and epoch.")]
    InvalidNullifier, // 6005

    #[msg("The supplied epoch is not the current access epoch.")]
    InvalidEpoch, // 6006

    #[msg("Signer is not the configured protocol administrator.")]
    UnauthorizedAdmin, // 6007
}
