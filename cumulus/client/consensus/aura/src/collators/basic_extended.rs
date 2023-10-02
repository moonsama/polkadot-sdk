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

//! This provides the option to run a basic relay-chain driven Aura implementation.
//!
//! This collator only builds on top of the most recently included block, limiting the
//! block time to a maximum of two times the relay-chain block time, and requiring the
//! block to be built and distributed to validators between two relay-chain blocks.
//!
//! For more information about AuRa, the Substrate crate should be checked.

use codec::{Codec, Decode};
use cumulus_client_collator::service::ServiceInterface as CollatorServiceInterface;
use cumulus_client_consensus_common::ParachainBlockImportMarker;
use cumulus_client_consensus_proposer::ProposerInterface;
use cumulus_primitives_core::{relay_chain::BlockId as RBlockId, CollectCollationInfo};
use cumulus_relay_chain_interface::RelayChainInterface;

use polkadot_node_primitives::CollationResult;

use futures::prelude::*;
use sc_client_api::{backend::AuxStore, BlockBackend, BlockOf};
use sc_consensus::BlockImport;
use sp_api::ProvideRuntimeApi;
use sp_application_crypto::AppPublic;
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_consensus_aura::{sr25519::AuthorityId, AuraApi};
use sp_core::{crypto::Pair, ByteArray};
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::{
	traits::{Block as BlockT, Header as HeaderT, Member},
	DigestItem,
};
use std::convert::TryFrom;

use crate::{collator as collator_util, collators::basic::Params as BasicParams};

pub trait DigestsProvider<Id, BlockHash> {
	type Digests: IntoIterator<Item = DigestItem>;
	fn provide_digests(&self, id: Id, parent: BlockHash) -> Self::Digests;
}

impl<Id, BlockHash> DigestsProvider<Id, BlockHash> for () {
	type Digests = [DigestItem; 0];
	fn provide_digests(&self, _id: Id, _parent: BlockHash) -> Self::Digests {
		[]
	}
}

impl<F, Id, BlockHash, D> DigestsProvider<Id, BlockHash> for F
where
	F: Fn(Id, BlockHash) -> D,
	D: IntoIterator<Item = DigestItem>,
{
	type Digests = D;

	fn provide_digests(&self, id: Id, parent: BlockHash) -> Self::Digests {
		(*self)(id, parent)
	}
}

/// Parameters for [`run`].
pub struct Params<BI, CIDP, Client, RClient, SO, Proposer, CS, DP> {
	pub basic_params: BasicParams<BI, CIDP, Client, RClient, SO, Proposer, CS>,
	pub digest_provider: DP,
}

/// Run bare Aura consensus as a relay-chain-driven collator.
pub fn run<Block, P, BI, CIDP, Client, RClient, SO, Proposer, CS, DP>(
	params: Params<BI, CIDP, Client, RClient, SO, Proposer, CS, DP>,
) -> impl Future<Output = ()> + Send + 'static
where
	Block: BlockT + Send,
	Client: ProvideRuntimeApi<Block>
		+ BlockOf
		+ AuxStore
		+ HeaderBackend<Block>
		+ BlockBackend<Block>
		+ Send
		+ Sync
		+ 'static,
	Client::Api: AuraApi<Block, P::Public> + CollectCollationInfo<Block>,
	RClient: RelayChainInterface + Send + Clone + 'static,
	CIDP: CreateInherentDataProviders<Block, ()> + Send + 'static,
	CIDP::InherentDataProviders: Send,
	BI: BlockImport<Block> + ParachainBlockImportMarker + Send + Sync + 'static,
	SO: SyncOracle + Send + Sync + Clone + 'static,
	Proposer: ProposerInterface<Block> + Send + Sync + 'static,
	CS: CollatorServiceInterface<Block> + Send + Sync + 'static,
	P: Pair,
	P::Public: AppPublic + Member + Codec,
	P::Signature: TryFrom<Vec<u8>> + Member + Codec,
	DP: DigestsProvider<AuthorityId, Block::Hash> + Send + Sync + 'static,
{
	async move {
		let basic_params = params.basic_params;
		let mut collation_requests = cumulus_client_collator::relay_chain_driven::init(
			basic_params.collator_key,
			basic_params.para_id,
			basic_params.overseer_handle,
		)
		.await;

		let mut collator = {
			let basic_params = collator_util::Params {
				create_inherent_data_providers: basic_params.create_inherent_data_providers,
				block_import: basic_params.block_import,
				relay_client: basic_params.relay_client.clone(),
				keystore: basic_params.keystore.clone(),
				para_id: basic_params.para_id,
				proposer: basic_params.proposer,
				collator_service: basic_params.collator_service,
			};

			collator_util::Collator::<Block, P, _, _, _, _, _>::new(basic_params)
		};

		while let Some(request) = collation_requests.next().await {
			macro_rules! reject_with_error {
				($err:expr) => {{
					request.complete(None);
					tracing::error!(target: crate::LOG_TARGET, err = ?{ $err });
					continue;
				}};
			}

			macro_rules! try_request {
				($x:expr) => {{
					match $x {
						Ok(x) => x,
						Err(e) => reject_with_error!(e),
					}
				}};
			}

			let validation_data = request.persisted_validation_data();

			let parent_header =
				try_request!(Block::Header::decode(&mut &validation_data.parent_head.0[..]));

			let parent_hash = parent_header.hash();

			if !collator.collator_service().check_block_status(parent_hash, &parent_header) {
				continue
			}

			let relay_parent_header = match basic_params
				.relay_client
				.header(RBlockId::hash(*request.relay_parent()))
				.await
			{
				Err(e) => reject_with_error!(e),
				Ok(None) => continue, // sanity: would be inconsistent to get `None` here
				Ok(Some(h)) => h,
			};

			let claim = match collator_util::claim_slot::<_, _, P>(
				&*basic_params.para_client,
				parent_hash,
				&relay_parent_header,
				basic_params.slot_duration,
				basic_params.relay_chain_slot_duration,
				&basic_params.keystore,
			)
			.await
			{
				Ok(None) => continue,
				Ok(Some(c)) => c,
				Err(e) => reject_with_error!(e),
			};

			let (parachain_inherent_data, other_inherent_data) = try_request!(
				collator
					.create_inherent_data(
						*request.relay_parent(),
						&validation_data,
						parent_hash,
						claim.timestamp(),
					)
					.await
			);

			let authority_id =
				try_request!(AuthorityId::from_slice(&claim.author_pub().to_raw_vec()));
			let digest = params
				.digest_provider
				.provide_digests(authority_id, parent_hash)
				.into_iter()
				.collect();
			let (collation, _, post_hash) = try_request!(
				collator
					.collate(
						&parent_header,
						&claim,
						Some(digest),
						(parachain_inherent_data, other_inherent_data),
						basic_params.authoring_duration,
						// Set the block limit to 50% of the maximum PoV size.
						//
						// TODO: If we got benchmarking that includes the proof size,
						// we should be able to use the maximum pov size.
						(validation_data.max_pov_size / 2) as usize,
					)
					.await
			);

			let result_sender = Some(collator.collator_service().announce_with_barrier(post_hash));
			request.complete(Some(CollationResult { collation, result_sender }));
		}
	}
}
