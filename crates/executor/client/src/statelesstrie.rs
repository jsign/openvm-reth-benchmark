use bincode::config::standard;
use bumpalo::Bump;
use openvm_mpt::{EthereumState, EthereumStateBytes, Mpt};
use reth_stateless::{validation::StatelessValidationError, ExecutionWitness};
use reth_storage_errors::provider::ProviderError;
use reth_trie::{TrieAccount, EMPTY_ROOT_HASH};
use reth_trie_common::HashedPostState;
use revm::state::Bytecode;
use revm_primitives::{keccak256, map::B256Map, Address, B256, U256};

#[derive(Debug)]
pub struct StatelessSparseTrie {
    state: EthereumState,
}

impl reth_stateless::StatelessTrie for StatelessSparseTrie {
    /// Initialize the stateless trie using the `ExecutionWitness`
    fn new(
        witness: &ExecutionWitness,
        pre_state_root: B256,
    ) -> Result<(Self, B256Map<Bytecode>), StatelessValidationError>
    where
        Self: Sized,
    {
        let bump = Box::leak(Box::new(Bump::with_capacity(1 << 20)));
        let bincode_config = standard();
        let state_bytes: EthereumStateBytes =
            bincode::serde::decode_from_slice(witness.state[0].as_ref(), bincode_config).unwrap().0;
        let state = EthereumState::from_ethereum_state_bytes(
            bump,
            pre_state_root,
            Box::leak(Box::new(state_bytes)),
        )
        .unwrap();

        // Build bytecode map: code_hash -> Bytecode
        let bytecodes: B256Map<Bytecode> = witness
            .codes
            .iter()
            .map(|code| (keccak256(code), Bytecode::new_raw(code.clone())))
            .collect();

        Ok((Self { state }, bytecodes))
    }

    /// Returns the `TrieAccount` that corresponds to the `Address`
    ///
    /// This method will error if the `ExecutionWitness` is not able to guarantee
    /// that the account is missing from the Trie _and_ the witness was complete.
    fn account(&self, address: Address) -> Result<Option<TrieAccount>, ProviderError> {
        let hashed_address = keccak256(address);
        let account = self
            .state
            .state_trie
            .get_rlp::<TrieAccount>(hashed_address.as_slice())
            .expect("Failed to get account from trie");
        Ok(account)
    }

    /// Returns the storage slot value that corresponds to the given (address, slot) tuple.
    ///
    /// This method will error if the `ExecutionWitness` is not able to guarantee
    /// that the storage was missing from the Trie _and_ the witness was complete.
    fn storage(&self, address: Address, slot: U256) -> Result<U256, ProviderError> {
        let hashed_address = keccak256(address);

        let storage_trie = self
            .state
            .storage_tries
            .get(&hashed_address)
            .expect("Missing storage trie for account");

        let hashed_slot = keccak256(slot.to_be_bytes::<32>());
        Ok(storage_trie
            .get_rlp::<U256>(hashed_slot.as_slice())
            .expect("Failed to get storage from trie")
            .unwrap_or_default())
    }

    /// Computes the new state root from the `HashedPostState`.
    fn calculate_state_root(
        &mut self,
        state: HashedPostState,
    ) -> Result<B256, StatelessValidationError> {
        // Process storage updates first
        for (hashed_address, hashed_storage) in &state.storages {
            let storage_trie = self
                .state
                .storage_tries
                .entry(*hashed_address)
                .or_insert_with(|| Mpt::new(self.state.bump));

            // If storage was wiped, reset the trie
            if hashed_storage.wiped {
                *storage_trie = Mpt::new(self.state.bump);
            }

            // Apply storage changes (keys are already hashed)
            for (hashed_slot, value) in &hashed_storage.storage {
                if value.is_zero() {
                    storage_trie.delete(hashed_slot.as_slice()).map_err(|_| {
                        StatelessValidationError::StatelessStateRootCalculationFailed
                    })?;
                } else {
                    storage_trie.insert_rlp(hashed_slot.as_slice(), *value).map_err(|_| {
                        StatelessValidationError::StatelessStateRootCalculationFailed
                    })?;
                }
            }
        }

        // Process account updates
        for (hashed_address, account_opt) in &state.accounts {
            match account_opt {
                Some(account) => {
                    let storage_root = self
                        .state
                        .storage_tries
                        .get(hashed_address)
                        .map_or(EMPTY_ROOT_HASH, |t| t.hash());

                    let trie_account = TrieAccount {
                        nonce: account.nonce,
                        balance: account.balance,
                        storage_root,
                        code_hash: account.bytecode_hash.unwrap_or_default(),
                    };
                    self.state
                        .state_trie
                        .insert_rlp(hashed_address.as_slice(), trie_account)
                        .map_err(|_| {
                            StatelessValidationError::StatelessStateRootCalculationFailed
                        })?;
                }
                None => {
                    // Account destroyed
                    self.state.state_trie.delete(hashed_address.as_slice()).map_err(|_| {
                        StatelessValidationError::StatelessStateRootCalculationFailed
                    })?;
                    self.state.storage_tries.remove(hashed_address);
                }
            }
        }

        Ok(self.state.state_trie.hash())
    }
}
