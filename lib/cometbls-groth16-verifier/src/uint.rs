pub struct U256(pub primitive_types::U256);

impl U256 {
    pub const MAX: Self = Self::from_limbs([u64::MAX; 4]);
    pub const ZERO: Self = Self::from_limbs([0; 4]);
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self(primitive_types::U256::from(value))
    }
}

impl TryFrom<U256> for u64 {
    type Error = ();

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value.0.as_u128() > U256::from(u64::MAX).0.as_u128() {
            Err(())
        } else {
            Ok(value.0.as_u64())
        }
    }
}

impl From<primitive_types::U256> for U256 {
    fn from(value: primitive_types::U256) -> Self {
        Self(value)
    }
}

impl From<U256> for primitive_types::U256 {
    fn from(value: U256) -> Self {
        value.0
    }
}

impl U256 {
    #[must_use]
    pub fn leading_zeros(&self) -> u32 {
        self.0.leading_zeros()
    }

    #[must_use]
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut buf = [0; 32];
        self.0.to_little_endian(&mut buf);
        buf
    }

    #[must_use]
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut buf = [0; 32];
        self.0.to_big_endian(&mut buf);
        buf
    }

    #[must_use]
    pub fn from_be_bytes(bz: [u8; 32]) -> Self {
        Self(primitive_types::U256::from_big_endian(&bz))
    }

    #[must_use]
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(primitive_types::U256(limbs))
    }

    #[must_use]
    pub const fn as_limbs(&self) -> [u64; 4] {
        self.0 .0
    }

}
