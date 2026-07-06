use anchor_lang::prelude::*;

// This is the Program ID synced to your machine
declare_id!("6uKhjh29AdQxqtWwcNjo8efyPBzwookTPdzzEiozgyiS");

#[program]
pub mod tap_a2a {
    use super::*;

    // =========================================================================
    // INSTRUCTIONS
    // =========================================================================

    /// Registers a new agent in the system and emits an audit event.
    pub fn register_agent(ctx: Context<RegisterAgent>) -> Result<()> {
        let agent = &mut ctx.accounts.agent_registry;

        agent.agent_pubkey = ctx.accounts.agent.key();
        agent.is_active = true;
        agent.registered_at = Clock::get()?.unix_timestamp;
        agent.bump = ctx.bumps.agent_registry;

        // Emit Audit Event for Registration (Type 1)
        emit!(AuditEvent {
            agent_pubkey: ctx.accounts.agent.key(),
            event_type: 1, 
            resource_id: "".to_string(),
            timestamp: Clock::get()?.unix_timestamp,
            details: "Agent registered successfully".to_string(),
        });

        Ok(())
    }

    /// Sets the least-privilege access policy for an agent on a specific resource.
    pub fn set_policy(
        ctx: Context<SetPolicy>,
        resource_id: String,
        allowed_scope: String,
    ) -> Result<()> {
        let policy = &mut ctx.accounts.policy_store;

        policy.agent_pubkey = ctx.accounts.agent.key();
        policy.resource_id = resource_id.clone();
        policy.allowed_scope = allowed_scope;
        policy.bump = ctx.bumps.policy_store;

        // Emit Audit Event for Policy Update (Type 2)
        emit!(AuditEvent {
            agent_pubkey: ctx.accounts.agent.key(),
            event_type: 2, 
            resource_id: resource_id,
            timestamp: Clock::get()?.unix_timestamp,
            details: "Policy set successfully".to_string(),
        });

        Ok(())
    }

    /// Revokes an agent's access, marking them inactive and recording the reason.
    pub fn revoke_agent(ctx: Context<RevokeAgent>, reason: String) -> Result<()> {
        let agent_registry = &mut ctx.accounts.agent_registry;
        let revocation_registry = &mut ctx.accounts.revocation_registry;

        // 1. Mark the agent as inactive in their Registry
        agent_registry.is_active = false;

        // 2. Record the revocation details in the Revocation PDA
        revocation_registry.agent_pubkey = ctx.accounts.agent.key();
        revocation_registry.revoked_at = Clock::get()?.unix_timestamp;
        revocation_registry.reason = reason.clone();
        revocation_registry.bump = ctx.bumps.revocation_registry;

        // 3. Emit Audit Event for Revocation (Type 5)
        emit!(AuditEvent {
            agent_pubkey: ctx.accounts.agent.key(),
            event_type: 5, 
            resource_id: "".to_string(),
            timestamp: Clock::get()?.unix_timestamp,
            details: reason,
        });

        Ok(())
    }
}

// =====================================================
// ACCOUNTS (Contexts)
// =====================================================

#[derive(Accounts)]
pub struct RegisterAgent<'info> {
    #[account(
        init,
        payer = agent,
        space = 8 + AgentRegistry::INIT_SPACE,
        seeds = [b"agent", agent.key().as_ref()],
        bump
    )]
    pub agent_registry: Account<'info, AgentRegistry>,

    #[account(mut)]
    pub agent: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(resource_id: String)]
pub struct SetPolicy<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + PolicyStore::INIT_SPACE,
        seeds = [b"policy", agent.key().as_ref(), resource_id.as_bytes()],
        bump
    )]
    pub policy_store: Account<'info, PolicyStore>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: used only for PDA derivation
    pub agent: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeAgent<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    // Mutate the existing AgentRegistry to set is_active = false
    #[account(
        mut,
        seeds = [b"agent", agent.key().as_ref()],
        bump = agent_registry.bump
    )]
    pub agent_registry: Account<'info, AgentRegistry>,

    // Initialize a new RevocationRegistry PDA to record the reason
    #[account(
        init,
        payer = authority,
        space = 8 + RevocationRegistry::INIT_SPACE,
        seeds = [b"revocation", agent.key().as_ref()],
        bump
    )]
    pub revocation_registry: Account<'info, RevocationRegistry>,

    /// CHECK: used only for PDA derivation
    pub agent: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

// =====================================================
// STATE ACCOUNTS
// =====================================================

#[account]
#[derive(InitSpace)]
pub struct AgentRegistry {
    pub agent_pubkey: Pubkey,
    pub is_active: bool,
    pub registered_at: i64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct PolicyStore {
    pub agent_pubkey: Pubkey,
    #[max_len(64)]
    pub resource_id: String,
    #[max_len(64)]
    pub allowed_scope: String,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct RevocationRegistry {
    pub agent_pubkey: Pubkey,
    pub revoked_at: i64,
    #[max_len(256)]
    pub reason: String,
    pub bump: u8,
}

// =====================================================
// EVENTS (Off-Chain Audit Trail)
// =====================================================

#[event]
pub struct AuditEvent {
    pub agent_pubkey: Pubkey,
    pub event_type: u8, // 1: Register, 2: PolicyUpdate, 3: AccessAllow, 4: AccessDeny, 5: Revoke
    pub resource_id: String,
    pub timestamp: i64,
    pub details: String,
}

