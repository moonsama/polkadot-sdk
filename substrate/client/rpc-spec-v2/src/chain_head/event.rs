// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The chain head's event returned as json compatible object.

use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use sp_api::ApiError;
use sp_version::RuntimeVersion;
use std::collections::BTreeMap;
use thiserror::Error;

/// The operation could not be processed due to an error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorEvent {
	/// Reason of the error.
	pub error: String,
}

/// The runtime specification of the current block.
///
/// This event is generated for:
///   - the first announced block by the follow subscription
///   - blocks that suffered a change in runtime compared with their parents
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
	rename_all = "camelCase",
	try_from = "RuntimeVersionEventWrapper",
	into = "RuntimeVersionEventWrapper"
)]
pub struct RuntimeVersionEvent {
	/// The runtime version.
	pub spec: RuntimeVersion,
}

// Note: PartialEq mainly used in tests, manual implementation necessary, because BTreeMap in
// RuntimeVersionWrapper does not preserve order of apis vec.
impl PartialEq for RuntimeVersionEvent {
	fn eq(&self, other: &Self) -> bool {
		RuntimeVersionWrapper::from(self.spec.clone()) ==
			RuntimeVersionWrapper::from(other.spec.clone())
	}
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
struct RuntimeVersionEventWrapper {
	spec: RuntimeVersionWrapper,
}

impl TryFrom<RuntimeVersionEventWrapper> for RuntimeVersionEvent {
	type Error = ApiFromHexError;

	fn try_from(val: RuntimeVersionEventWrapper) -> Result<Self, Self::Error> {
		let spec = val.spec.try_into()?;
		Ok(Self { spec })
	}
}

impl From<RuntimeVersionEvent> for RuntimeVersionEventWrapper {
	fn from(val: RuntimeVersionEvent) -> Self {
		Self { spec: val.spec.into() }
	}
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeVersionWrapper {
	pub spec_name: String,
	pub impl_name: String,
	pub spec_version: u32,
	pub impl_version: u32,
	pub apis: BTreeMap<String, u32>,
	pub transaction_version: u32,
}

#[derive(Error, Debug)]
enum ApiFromHexError {
	#[error("invalid hex string provided")]
	FromHexError(#[from] sp_core::bytes::FromHexError),
	#[error("buffer must be 8 bytes long")]
	InvalidLength,
}

impl TryFrom<RuntimeVersionWrapper> for RuntimeVersion {
	type Error = ApiFromHexError;

	fn try_from(val: RuntimeVersionWrapper) -> Result<Self, Self::Error> {
		let apis = val
			.apis
			.into_iter()
			.map(|(api, version)| -> Result<([u8; 8], u32), ApiFromHexError> {
				let bytes_vec = sp_core::bytes::from_hex(&api)?;
				let api: [u8; 8] =
					bytes_vec.try_into().map_err(|_| ApiFromHexError::InvalidLength)?;
				Ok((api, version))
			})
			.collect::<Result<sp_version::ApisVec, ApiFromHexError>>()?;
		Ok(Self {
			spec_name: sp_runtime::RuntimeString::Owned(val.spec_name),
			impl_name: sp_runtime::RuntimeString::Owned(val.impl_name),
			spec_version: val.spec_version,
			impl_version: val.impl_version,
			apis,
			transaction_version: val.transaction_version,
			..Default::default()
		})
	}
}

impl From<RuntimeVersion> for RuntimeVersionWrapper {
	fn from(val: RuntimeVersion) -> Self {
		Self {
			spec_name: val.spec_name.into(),
			impl_name: val.impl_name.into(),
			spec_version: val.spec_version,
			impl_version: val.impl_version,
			apis: val
				.apis
				.into_iter()
				.map(|(api, version)| (sp_core::bytes::to_hex(api, false), *version))
				.collect(),
			transaction_version: val.transaction_version,
		}
	}
}

/// The runtime event generated if the `follow` subscription
/// has set the `with_runtime` flag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum RuntimeEvent {
	/// The runtime version of this block.
	Valid(RuntimeVersionEvent),
	/// The runtime could not be obtained due to an error.
	Invalid(ErrorEvent),
}

impl From<ApiError> for RuntimeEvent {
	fn from(err: ApiError) -> Self {
		RuntimeEvent::Invalid(ErrorEvent { error: format!("Api error: {}", err) })
	}
}

/// Contain information about the latest finalized block.
///
/// # Note
///
/// This is the first event generated by the `follow` subscription
/// and is submitted only once.
///
/// If the `with_runtime` flag is set, then this event contains
/// the `RuntimeEvent`, otherwise the `RuntimeEvent` is not present.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Initialized<Hash> {
	/// The hash of the latest finalized block.
	pub finalized_block_hash: Hash,
	/// The runtime version of the finalized block.
	///
	/// # Note
	///
	/// This is present only if the `with_runtime` flag is set for
	/// the `follow` subscription.
	pub finalized_block_runtime: Option<RuntimeEvent>,
	/// Privately keep track if the `finalized_block_runtime` should be
	/// serialized.
	#[serde(default)]
	pub(crate) with_runtime: bool,
}

impl<Hash: Serialize> Serialize for Initialized<Hash> {
	/// Custom serialize implementation to include the `RuntimeEvent` depending
	/// on the internal `with_runtime` flag.
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		if self.with_runtime {
			let mut state = serializer.serialize_struct("Initialized", 2)?;
			state.serialize_field("finalizedBlockHash", &self.finalized_block_hash)?;
			state.serialize_field("finalizedBlockRuntime", &self.finalized_block_runtime)?;
			state.end()
		} else {
			let mut state = serializer.serialize_struct("Initialized", 1)?;
			state.serialize_field("finalizedBlockHash", &self.finalized_block_hash)?;
			state.end()
		}
	}
}

/// Indicate a new non-finalized block.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewBlock<Hash> {
	/// The hash of the new block.
	pub block_hash: Hash,
	/// The parent hash of the new block.
	pub parent_block_hash: Hash,
	/// The runtime version of the new block.
	///
	/// # Note
	///
	/// This is present only if the `with_runtime` flag is set for
	/// the `follow` subscription.
	pub new_runtime: Option<RuntimeEvent>,
	/// Privately keep track if the `finalized_block_runtime` should be
	/// serialized.
	#[serde(default)]
	pub(crate) with_runtime: bool,
}

impl<Hash: Serialize> Serialize for NewBlock<Hash> {
	/// Custom serialize implementation to include the `RuntimeEvent` depending
	/// on the internal `with_runtime` flag.
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		if self.with_runtime {
			let mut state = serializer.serialize_struct("NewBlock", 3)?;
			state.serialize_field("blockHash", &self.block_hash)?;
			state.serialize_field("parentBlockHash", &self.parent_block_hash)?;
			state.serialize_field("newRuntime", &self.new_runtime)?;
			state.end()
		} else {
			let mut state = serializer.serialize_struct("NewBlock", 2)?;
			state.serialize_field("blockHash", &self.block_hash)?;
			state.serialize_field("parentBlockHash", &self.parent_block_hash)?;
			state.end()
		}
	}
}

/// Indicate the block hash of the new best block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BestBlockChanged<Hash> {
	/// The block hash of the new best block.
	pub best_block_hash: Hash,
}

/// Indicate the finalized and pruned block hashes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finalized<Hash> {
	/// Block hashes that are finalized.
	pub finalized_block_hashes: Vec<Hash>,
	/// Block hashes that are pruned (removed).
	pub pruned_block_hashes: Vec<Hash>,
}

/// Indicate the operation id of the event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationId {
	/// The operation id of the event.
	pub operation_id: String,
}

/// The response of the `chainHead_body` method.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationBodyDone {
	/// The operation id of the event.
	pub operation_id: String,
	/// Array of hexadecimal-encoded scale-encoded extrinsics found in the block.
	pub value: Vec<String>,
}

/// The response of the `chainHead_call` method.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationCallDone {
	/// The operation id of the event.
	pub operation_id: String,
	/// Hexadecimal-encoded output of the runtime function call.
	pub output: String,
}

/// The response of the `chainHead_call` method.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationStorageItems {
	/// The operation id of the event.
	pub operation_id: String,
	/// The resulting items.
	pub items: Vec<StorageResult>,
}

/// Indicate a problem during the operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationError {
	/// The operation id of the event.
	pub operation_id: String,
	/// The reason of the error.
	pub error: String,
}

/// The event generated by the `follow` method.
///
/// The block events are generated in the following order:
/// 1. Initialized - generated only once to signal the latest finalized block
/// 2. NewBlock - a new block was added.
/// 3. BestBlockChanged - indicate that the best block is now the one from this event. The block was
///    announced priorly with the `NewBlock` event.
/// 4. Finalized - State the finalized and pruned blocks.
///
/// The following events are related to operations:
/// - OperationBodyDone: The response of the `chianHead_body`
/// - OperationCallDone: The response of the `chianHead_call`
/// - OperationStorageItems: Items produced by the `chianHead_storage`
/// - OperationWaitingForContinue: Generated after OperationStorageItems and requires the user to
///   call `chainHead_continue`
/// - OperationStorageDone: The `chianHead_storage` method has produced all the results
/// - OperationInaccessible: The server was unable to provide the result, retries might succeed in
///   the future
/// - OperationError: The server encountered an error, retries will not succeed
///
/// The stop event indicates that the JSON-RPC server was unable to provide a consistent list of
/// the blocks at the head of the chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "event")]
pub enum FollowEvent<Hash> {
	/// The latest finalized block.
	///
	/// This event is generated only once.
	Initialized(Initialized<Hash>),
	/// A new non-finalized block was added.
	NewBlock(NewBlock<Hash>),
	/// The best block of the chain.
	BestBlockChanged(BestBlockChanged<Hash>),
	/// A list of finalized and pruned blocks.
	Finalized(Finalized<Hash>),
	/// The response of the `chainHead_body` method.
	OperationBodyDone(OperationBodyDone),
	/// The response of the `chainHead_call` method.
	OperationCallDone(OperationCallDone),
	/// Yield one or more items found in the storage.
	OperationStorageItems(OperationStorageItems),
	/// Ask the user to call `chainHead_continue` to produce more events
	/// regarding the operation id.
	OperationWaitingForContinue(OperationId),
	/// The responses of the `chainHead_storage` method have been produced.
	OperationStorageDone(OperationId),
	/// The RPC server was unable to provide the response of the following operation id.
	///
	/// Repeating the same operation in the future might succeed.
	OperationInaccessible(OperationId),
	/// The RPC server encountered an error while processing an operation id.
	///
	/// Repeating the same operation in the future will not succeed.
	OperationError(OperationError),
	/// The subscription is dropped and no further events
	/// will be generated.
	Stop,
}

/// The storage item received as paramter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageQuery<Key> {
	/// The provided key.
	pub key: Key,
	/// The type of the storage query.
	#[serde(rename = "type")]
	pub query_type: StorageQueryType,
}

/// The type of the storage query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StorageQueryType {
	/// Fetch the value of the provided key.
	Value,
	/// Fetch the hash of the value of the provided key.
	Hash,
	/// Fetch the closest descendant merkle value.
	ClosestDescendantMerkleValue,
	/// Fetch the values of all descendants of they provided key.
	DescendantsValues,
	/// Fetch the hashes of the values of all descendants of they provided key.
	DescendantsHashes,
}

/// The storage result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageResult {
	/// The hex-encoded key of the result.
	pub key: String,
	/// The result of the query.
	#[serde(flatten)]
	pub result: StorageResultType,
}

/// The type of the storage query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StorageResultType {
	/// Fetch the value of the provided key.
	Value(String),
	/// Fetch the hash of the value of the provided key.
	Hash(String),
	/// Fetch the closest descendant merkle value.
	ClosestDescendantMerkleValue(String),
}

/// The method respose of `chainHead_body`, `chainHead_call` and `chainHead_storage`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "result")]
pub enum MethodResponse {
	/// The method has started.
	Started(MethodResponseStarted),
	/// The RPC server cannot handle the request at the moment.
	LimitReached,
}

/// The `started` result of a method.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodResponseStarted {
	/// The operation id of the response.
	pub operation_id: String,
	/// The number of items from the back of the `chainHead_storage` that have been discarded.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(default)]
	pub discarded_items: Option<usize>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn follow_initialized_event_no_updates() {
		// Runtime flag is false.
		let event: FollowEvent<String> = FollowEvent::Initialized(Initialized {
			finalized_block_hash: "0x1".into(),
			finalized_block_runtime: None,
			with_runtime: false,
		});

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"event":"initialized","finalizedBlockHash":"0x1"}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn follow_initialized_event_with_updates() {
		// Runtime flag is true, block runtime must always be reported for this event.
		let runtime = RuntimeVersion {
			spec_name: "ABC".into(),
			impl_name: "Impl".into(),
			spec_version: 1,
			..Default::default()
		};

		let runtime_event = RuntimeEvent::Valid(RuntimeVersionEvent { spec: runtime });
		let mut initialized = Initialized {
			finalized_block_hash: "0x1".into(),
			finalized_block_runtime: Some(runtime_event),
			with_runtime: true,
		};
		let event: FollowEvent<String> = FollowEvent::Initialized(initialized.clone());

		let ser = serde_json::to_string(&event).unwrap();
		let exp = concat!(
			r#"{"event":"initialized","finalizedBlockHash":"0x1","#,
			r#""finalizedBlockRuntime":{"type":"valid","spec":{"specName":"ABC","implName":"Impl","#,
			r#""specVersion":1,"implVersion":0,"apis":{},"transactionVersion":0}}}"#,
		);
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		// The `with_runtime` field is used for serialization purposes.
		initialized.with_runtime = false;
		assert!(matches!(
			event_dec, FollowEvent::Initialized(ref dec) if dec == &initialized
		));
	}

	#[test]
	fn follow_new_block_event_no_updates() {
		// Runtime flag is false.
		let event: FollowEvent<String> = FollowEvent::NewBlock(NewBlock {
			block_hash: "0x1".into(),
			parent_block_hash: "0x2".into(),
			new_runtime: None,
			with_runtime: false,
		});

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"event":"newBlock","blockHash":"0x1","parentBlockHash":"0x2"}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn follow_new_block_event_with_updates() {
		// Runtime flag is true, block runtime must always be reported for this event.
		let runtime = RuntimeVersion {
			spec_name: "ABC".into(),
			impl_name: "Impl".into(),
			spec_version: 1,
			apis: vec![([0, 0, 0, 0, 0, 0, 0, 0], 2), ([1, 0, 0, 0, 0, 0, 0, 0], 3)].into(),
			..Default::default()
		};

		let runtime_event = RuntimeEvent::Valid(RuntimeVersionEvent { spec: runtime });
		let mut new_block = NewBlock {
			block_hash: "0x1".into(),
			parent_block_hash: "0x2".into(),
			new_runtime: Some(runtime_event),
			with_runtime: true,
		};

		let event: FollowEvent<String> = FollowEvent::NewBlock(new_block.clone());

		let ser = serde_json::to_string(&event).unwrap();
		let exp = concat!(
			r#"{"event":"newBlock","blockHash":"0x1","parentBlockHash":"0x2","#,
			r#""newRuntime":{"type":"valid","spec":{"specName":"ABC","implName":"Impl","#,
			r#""specVersion":1,"implVersion":0,"apis":{"0x0000000000000000":2,"0x0100000000000000":3},"transactionVersion":0}}}"#,
		);
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		// The `with_runtime` field is used for serialization purposes.
		new_block.with_runtime = false;
		assert!(matches!(
			event_dec, FollowEvent::NewBlock(ref dec) if dec == &new_block
		));

		// Runtime flag is true, runtime didn't change compared to parent.
		let mut new_block = NewBlock {
			block_hash: "0x1".into(),
			parent_block_hash: "0x2".into(),
			new_runtime: None,
			with_runtime: true,
		};
		let event: FollowEvent<String> = FollowEvent::NewBlock(new_block.clone());

		let ser = serde_json::to_string(&event).unwrap();
		let exp =
			r#"{"event":"newBlock","blockHash":"0x1","parentBlockHash":"0x2","newRuntime":null}"#;
		assert_eq!(ser, exp);
		new_block.with_runtime = false;
		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert!(matches!(
			event_dec, FollowEvent::NewBlock(ref dec) if dec == &new_block
		));
	}

	#[test]
	fn follow_best_block_changed_event() {
		let event: FollowEvent<String> =
			FollowEvent::BestBlockChanged(BestBlockChanged { best_block_hash: "0x1".into() });

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"event":"bestBlockChanged","bestBlockHash":"0x1"}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn follow_finalized_event() {
		let event: FollowEvent<String> = FollowEvent::Finalized(Finalized {
			finalized_block_hashes: vec!["0x1".into()],
			pruned_block_hashes: vec!["0x2".into()],
		});

		let ser = serde_json::to_string(&event).unwrap();
		let exp =
			r#"{"event":"finalized","finalizedBlockHashes":["0x1"],"prunedBlockHashes":["0x2"]}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn follow_op_body_event() {
		let event: FollowEvent<String> = FollowEvent::OperationBodyDone(OperationBodyDone {
			operation_id: "123".into(),
			value: vec!["0x1".into()],
		});

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"event":"operationBodyDone","operationId":"123","value":["0x1"]}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn follow_op_call_event() {
		let event: FollowEvent<String> = FollowEvent::OperationCallDone(OperationCallDone {
			operation_id: "123".into(),
			output: "0x1".into(),
		});

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"event":"operationCallDone","operationId":"123","output":"0x1"}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn follow_op_storage_items_event() {
		let event: FollowEvent<String> =
			FollowEvent::OperationStorageItems(OperationStorageItems {
				operation_id: "123".into(),
				items: vec![StorageResult {
					key: "0x1".into(),
					result: StorageResultType::Value("0x123".to_string()),
				}],
			});

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"event":"operationStorageItems","operationId":"123","items":[{"key":"0x1","value":"0x123"}]}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn follow_op_wait_event() {
		let event: FollowEvent<String> =
			FollowEvent::OperationWaitingForContinue(OperationId { operation_id: "123".into() });

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"event":"operationWaitingForContinue","operationId":"123"}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn follow_op_storage_done_event() {
		let event: FollowEvent<String> =
			FollowEvent::OperationStorageDone(OperationId { operation_id: "123".into() });

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"event":"operationStorageDone","operationId":"123"}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn follow_op_inaccessible_event() {
		let event: FollowEvent<String> =
			FollowEvent::OperationInaccessible(OperationId { operation_id: "123".into() });

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"event":"operationInaccessible","operationId":"123"}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn follow_op_error_event() {
		let event: FollowEvent<String> = FollowEvent::OperationError(OperationError {
			operation_id: "123".into(),
			error: "reason".into(),
		});

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"event":"operationError","operationId":"123","error":"reason"}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn follow_stop_event() {
		let event: FollowEvent<String> = FollowEvent::Stop;

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"event":"stop"}"#;
		assert_eq!(ser, exp);

		let event_dec: FollowEvent<String> = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn method_response() {
		// Response of `call` and `body`
		let event = MethodResponse::Started(MethodResponseStarted {
			operation_id: "123".into(),
			discarded_items: None,
		});

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"result":"started","operationId":"123"}"#;
		assert_eq!(ser, exp);

		let event_dec: MethodResponse = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);

		// Response of `storage`
		let event = MethodResponse::Started(MethodResponseStarted {
			operation_id: "123".into(),
			discarded_items: Some(1),
		});

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"result":"started","operationId":"123","discardedItems":1}"#;
		assert_eq!(ser, exp);

		let event_dec: MethodResponse = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);

		// Limit reached.
		let event = MethodResponse::LimitReached;

		let ser = serde_json::to_string(&event).unwrap();
		let exp = r#"{"result":"limitReached"}"#;
		assert_eq!(ser, exp);

		let event_dec: MethodResponse = serde_json::from_str(exp).unwrap();
		assert_eq!(event_dec, event);
	}

	#[test]
	fn chain_head_storage_query() {
		// Item with Value.
		let item = StorageQuery { key: "0x1", query_type: StorageQueryType::Value };
		// Encode
		let ser = serde_json::to_string(&item).unwrap();
		let exp = r#"{"key":"0x1","type":"value"}"#;
		assert_eq!(ser, exp);
		// Decode
		let dec: StorageQuery<&str> = serde_json::from_str(exp).unwrap();
		assert_eq!(dec, item);

		// Item with Hash.
		let item = StorageQuery { key: "0x1", query_type: StorageQueryType::Hash };
		// Encode
		let ser = serde_json::to_string(&item).unwrap();
		let exp = r#"{"key":"0x1","type":"hash"}"#;
		assert_eq!(ser, exp);
		// Decode
		let dec: StorageQuery<&str> = serde_json::from_str(exp).unwrap();
		assert_eq!(dec, item);

		// Item with DescendantsValues.
		let item = StorageQuery { key: "0x1", query_type: StorageQueryType::DescendantsValues };
		// Encode
		let ser = serde_json::to_string(&item).unwrap();
		let exp = r#"{"key":"0x1","type":"descendantsValues"}"#;
		assert_eq!(ser, exp);
		// Decode
		let dec: StorageQuery<&str> = serde_json::from_str(exp).unwrap();
		assert_eq!(dec, item);

		// Item with DescendantsHashes.
		let item = StorageQuery { key: "0x1", query_type: StorageQueryType::DescendantsHashes };
		// Encode
		let ser = serde_json::to_string(&item).unwrap();
		let exp = r#"{"key":"0x1","type":"descendantsHashes"}"#;
		assert_eq!(ser, exp);
		// Decode
		let dec: StorageQuery<&str> = serde_json::from_str(exp).unwrap();
		assert_eq!(dec, item);

		// Item with Merkle.
		let item =
			StorageQuery { key: "0x1", query_type: StorageQueryType::ClosestDescendantMerkleValue };
		// Encode
		let ser = serde_json::to_string(&item).unwrap();
		let exp = r#"{"key":"0x1","type":"closestDescendantMerkleValue"}"#;
		assert_eq!(ser, exp);
		// Decode
		let dec: StorageQuery<&str> = serde_json::from_str(exp).unwrap();
		assert_eq!(dec, item);
	}

	#[test]
	fn chain_head_storage_result() {
		// Item with Value.
		let item =
			StorageResult { key: "0x1".into(), result: StorageResultType::Value("res".into()) };
		// Encode
		let ser = serde_json::to_string(&item).unwrap();
		let exp = r#"{"key":"0x1","value":"res"}"#;
		assert_eq!(ser, exp);
		// Decode
		let dec: StorageResult = serde_json::from_str(exp).unwrap();
		assert_eq!(dec, item);

		// Item with Hash.
		let item =
			StorageResult { key: "0x1".into(), result: StorageResultType::Hash("res".into()) };
		// Encode
		let ser = serde_json::to_string(&item).unwrap();
		let exp = r#"{"key":"0x1","hash":"res"}"#;
		assert_eq!(ser, exp);
		// Decode
		let dec: StorageResult = serde_json::from_str(exp).unwrap();
		assert_eq!(dec, item);

		// Item with DescendantsValues.
		let item = StorageResult {
			key: "0x1".into(),
			result: StorageResultType::ClosestDescendantMerkleValue("res".into()),
		};
		// Encode
		let ser = serde_json::to_string(&item).unwrap();
		let exp = r#"{"key":"0x1","closestDescendantMerkleValue":"res"}"#;
		assert_eq!(ser, exp);
		// Decode
		let dec: StorageResult = serde_json::from_str(exp).unwrap();
		assert_eq!(dec, item);
	}
}
