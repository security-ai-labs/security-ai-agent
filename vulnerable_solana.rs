// ❌ CRITICAL: Multiple Solana security vulnerabilities

use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod vulnerable_solana {
    use super::*;

    // ❌ CRITICAL: Missing signer check
    pub fn withdraw_unsafe(ctx: Context<WithdrawUnsafe>, amount: u64) -> Result<()> {
        let account = &ctx.accounts.user;
        
        // ❌ No is_signer verification - signature forgery possible
        msg!("Withdrawing {} from {:?}", amount, account.key());
        
        // ❌ Missing owner validation
        **account.lamports.borrow_mut() -= amount;
        
        Ok(())
    }

    // ❌ HIGH: Unchecked account
    pub fn transfer_unchecked(ctx: Context<TransferUnchecked>, amount: u64) -> Result<()> {
        let from = &ctx.accounts.from;
        let to = &ctx.accounts.to;
        
        // ❌ No account validation - any account can be used
        **from.lamports.borrow_mut() -= amount;
        **to.lamports.borrow_mut() += amount;
        
        Ok(())
    }

    // ❌ HIGH: Arithmetic overflow without checks
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &ctx.accounts.vault;
        let user_balance = vault.balance as u64;
        
        // ❌ No checked_add - can overflow
        vault.balance = user_balance + amount;
        
        Ok(())
    }

    // ❌ CRITICAL: Missing owner check
    pub fn admin_transfer(ctx: Context<AdminTransfer>, amount: u64) -> Result<()> {
        let vault = &ctx.accounts.vault;
        let recipient = &ctx.accounts.recipient;
        
        // ❌ No verify that caller is owner
        **vault.lamports.borrow_mut() -= amount;
        **recipient.lamports.borrow_mut() += amount;
        
        Ok(())
    }

    // ❌ MEDIUM: Rent exemption violation
    pub fn drain_account(ctx: Context<DrainAccount>) -> Result<()> {
        let account = &ctx.accounts.target;
        
        // ❌ Doesn't check rent exemption
        let lamports = account.lamports();
        **account.lamports.borrow_mut() = 0;
        
        Ok(())
    }
}

// ❌ CRITICAL: Missing signer validation
#[derive(Accounts)]
pub struct WithdrawUnsafe<'info> {
    #[account(mut)]
    pub user: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

// ❌ HIGH: Unchecked accounts
#[derive(Accounts)]
pub struct TransferUnchecked<'info> {
    #[account(mut)]
    pub from: AccountInfo<'info>,
    #[account(mut)]
    pub to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

// ❌ CRITICAL: No owner check
#[derive(Accounts)]
pub struct AdminTransfer<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DrainAccount<'info> {
    #[account(mut)]
    pub target: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub balance: u64,
    pub owner: Pubkey,
}