// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Cumulus is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Cumulus is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

use crate::chain_spec::Extensions;
use cumulus_primitives_core::ParaId;
use parachains_common::AuraId;
use sc_service::ChainType;

use super::get_collator_keys_from_seed;

/// Specialized `ChainSpec` for the shell parachain runtime.
pub type ShellChainSpec =
	sc_service::GenericChainSpec<shell_runtime::RuntimeGenesisConfig, Extensions>;

pub fn get_shell_chain_spec() -> ShellChainSpec {
	#[allow(deprecated)]
	ShellChainSpec::from_genesis(
		"Shell Local Testnet",
		"shell_local_testnet",
		ChainType::Local,
		move || {
			shell_testnet_genesis(1000.into(), vec![get_collator_keys_from_seed::<AuraId>("Alice")])
		},
		Vec::new(),
		None,
		None,
		None,
		None,
		Extensions { relay_chain: "westend".into(), para_id: 1000 },
		shell_runtime::WASM_BINARY.expect("WASM binary was not build, please build it!"),
	)
}

fn shell_testnet_genesis(
	parachain_id: ParaId,
	collators: Vec<AuraId>,
) -> shell_runtime::RuntimeGenesisConfig {
	shell_runtime::RuntimeGenesisConfig {
		system: shell_runtime::SystemConfig::default(),
		parachain_info: shell_runtime::ParachainInfoConfig { parachain_id, ..Default::default() },
		parachain_system: Default::default(),
		aura: shell_runtime::AuraConfig { authorities: collators },
		aura_ext: Default::default(),
	}
}
