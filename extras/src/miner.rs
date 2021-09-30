use forest_address::Address;
use forest_bitfield::UnvalidatedBitField;
use forest_encoding::tuple::*;
use forest_vm::{TokenAmount, METHOD_CONSTRUCTOR};
use num_bigint::bigint_ser;
use num_derive::FromPrimitive;
use serde::{Serialize, Deserialize};

#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct WithdrawBalanceParams {
    #[serde(with = "bigint_ser")]
    pub amount: TokenAmount,
}

#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct CompactSectorNumbersParams {
    pub mask_sector_numbers: UnvalidatedBitField,
}

#[derive(Serialize, Deserialize)]
pub struct ChangeOwnerAddressParams(pub Address);

/// Multisig actor methods available
#[repr(u64)]
#[derive(FromPrimitive)]
pub enum MethodStorageMiner {
    Constructor = METHOD_CONSTRUCTOR,
    WithdrawBalance = 16,
    CompactSectorNumbers = 20,
    ChangeOwnerAddress = 23,
}
