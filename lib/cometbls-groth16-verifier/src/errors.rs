use core::fmt::Debug;

#[derive(Debug, Clone, PartialEq)]
pub struct UnknownEnumVariant<T>(pub T);

/// A protobuf field was none unexpectedly.
#[derive(Debug, Clone, PartialEq)]
pub struct MissingField(pub &'static str);

#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
pub enum ExpectedLength {
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidValue<T> {
    pub expected: T,
    pub found: T,
}
