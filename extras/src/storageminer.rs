use forest_encoding::tuple::*;
use forest_vm::{TokenAmount, METHOD_CONSTRUCTOR};
use num_bigint::bigint_ser;
use num_derive::FromPrimitive;

#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct WithdrawBalanceParams {
    #[serde(with = "bigint_ser")]
    pub amount: TokenAmount,
}

/// Multisig actor methods available
#[repr(u64)]
#[derive(FromPrimitive)]
pub enum MethodStorageMiner {
    Constructor = METHOD_CONSTRUCTOR,
    WithdrawBalance = 16,
}
