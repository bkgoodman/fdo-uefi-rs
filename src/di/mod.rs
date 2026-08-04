// Copyright 2026 Dell Technologies, All Rights Reserved
// Author: Brad Goodman <bradley.goodman@dell.com>
// SPDX-License-Identifier: Apache-2.0
//
// FDO Device Initialization (DI) Protocol for UEFI
//
// Minimal implementation per fdo-appnote-device-mfg-info.bs spec.
// This is a reference implementation, not production-ready.

pub mod mfginfo;
pub mod protocol;

pub use protocol::run_di_protocol;
