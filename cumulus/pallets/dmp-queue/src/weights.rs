// Copyright Parity Technologies (UK) Ltd.
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

//! Autogenerated weights for `cumulus_pallet_xcmp_queue`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-08-29, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `i9`, CPU: `13th Gen Intel(R) Core(TM) i9-13900K`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("westmint-dev")`, DB CACHE: `1024`

// Executed Command:
// ./target/release/polkadot-parachain
// benchmark
// pallet
// --chain=westmint-dev
// --pallet=cumulus_pallet_xcmp_queue
// --extrinsic=
// --wasm-execution=compiled
// --steps=50
// --repeat=20
// --template
// substrate/.maintain/frame-weight-template.hbs
// --output=cumulus/pallets/xcmp-queue/src/weights.rs
// --header
// cumulus/file_header.txt

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for `cumulus_pallet_xcmp_queue`.
pub trait WeightInfo {
	fn on_idle() -> Weight;
}

/// Weights for `cumulus_pallet_xcmp_queue` using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn on_idle() -> Weight {
		Weight::from_all(1) // FAIL-CI
	}
}

// For backwards compatibility and tests.
impl WeightInfo for () {
	fn on_idle() -> Weight {
		Weight::from_all(1)
	}
}
