macro_rules! bounded_int {
    ($(
        $(#[non_zero($NonZero:ty)])?
        pub $Struct:ident($ty:ty);
    )+) => {
        $(
            #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
            pub struct $Struct<const MIN: $ty, const MAX: $ty = { <$ty>::MAX }>($ty);

            impl<const MIN: $ty, const MAX: $ty> $Struct<MIN, MAX> {
                #[must_use]
                pub const fn inner(self) -> $ty {
                    self.0
                }

                #[must_use]
                pub fn add(&self, other: &$ty) -> Self {
                    Self::new(self.inner() + other).expect("arithmetic overflow")
                }
            }

            impl<const MIN: $ty, const MAX: $ty> core::fmt::Debug for $Struct<MIN, MAX> {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_fmt(format_args!("{}<{MIN}, {MAX}>({})", stringify!($Struct), self.0))
                }
            }

            impl<const MIN: $ty, const MAX: $ty> serde::Serialize for $Struct<MIN, MAX> {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    self.0.serialize(serializer)
                }
            }

            impl<const MIN: $ty, const MAX: $ty> TryFrom<$ty> for $Struct<MIN, MAX> {
                type Error = BoundedIntError<$ty>;

                fn try_from(n: $ty) -> Result<Self, Self::Error> {
                    Self::new(n)
                }
            }

            impl<const MIN: $ty, const MAX: $ty> From<$Struct<MIN, MAX>> for $ty {
                fn from(value: $Struct<MIN, MAX>) -> Self {
                    value.0
                }
            }

            impl<const MIN: $ty, const MAX: $ty> $Struct<MIN, MAX> {
                pub const fn new(n: $ty) -> Result<Self, BoundedIntError<$ty>> {
                    const { assert!(MIN < MAX) };

                    if n >= MIN && n <= MAX {
                        Ok(Self(n))
                    } else {
                        Err(BoundedIntError {
                            max: MAX,
                            min: MIN,
                            found: n,
                        })
                    }
                }
            }

            impl<const MIN: $ty, const MAX: $ty> core::str::FromStr for $Struct<MIN, MAX> {
                type Err = BoundedIntParseError<$ty>;

                fn from_str(s: &str) -> Result<Self, Self::Err> {
                    s.parse::<$ty>()
                        .map_err(BoundedIntParseError::Parse)
                        .and_then(|n| n.try_into().map_err(BoundedIntParseError::Value))
                }
            }

            impl<const MIN: $ty, const MAX: $ty> core::fmt::Display for $Struct<MIN, MAX> {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "{}", self.0)
                }
            }

            $(
                const _: () = assert!(
                    <$ty>::MIN.abs_diff(0) == 0,
                    concat!(
                        "Extra assertion that [`",
                        stringify!($NonZero),
                        "`]",
                        " is the same as [`",
                        stringify!($Struct),
                        "<1, ",
                        stringify!($ty),
                        ">`]."
                    ),
                );

                const _: $ty = match <$NonZero>::new(1) {
                    Some(n) => n.get(),
                    None => unreachable!(),
                };

                impl From<$NonZero> for $Struct<1, { <$ty>::MAX }> {
                    fn from(value: $NonZero) -> Self {
                        Self(value.get())
                    }
                }

                impl From<$Struct<1, { <$ty>::MAX }>> for $NonZero {
                    fn from(value: $Struct<1, { <$ty>::MAX }>) -> Self {
                        Self::new(value.inner()).expect("value is > 0 as per const bounds; qed;")
                    }
                }
            )?
        )+
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BoundedIntError<T> {
    min: T,
    max: T,
    found: T,
}

impl<T> BoundedIntError<T> {
    pub fn min(&self) -> &T {
        &self.min
    }

    pub fn max(&self) -> &T {
        &self.max
    }

    pub fn found(&self) -> &T {
        &self.found
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BoundedIntParseError<T> {
    Parse(core::num::ParseIntError),
    Value(BoundedIntError<T>),
}

bounded_int! {
    pub BoundedI8(i8);
    pub BoundedI16(i16);
    pub BoundedI32(i32);
    pub BoundedI64(i64);
    pub BoundedI128(i128);

    #[non_zero(core::num::NonZeroU8)]
    pub BoundedU8(u8);
    #[non_zero(core::num::NonZeroU16)]
    pub BoundedU16(u16);
    #[non_zero(core::num::NonZeroU32)]
    pub BoundedU32(u32);
    #[non_zero(core::num::NonZeroU64)]
    pub BoundedU64(u64);
    #[non_zero(core::num::NonZeroU128)]
    pub BoundedU128(u128);

    pub BoundedIsize(isize);
    #[non_zero(core::num::NonZeroUsize)]
    pub BoundedUsize(usize);
}

