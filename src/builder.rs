use bitcoin::blockdata::opcodes::Opcode;

use bitcoin::blockdata::script::{PushBytes, PushBytesBuf, ScriptBuf};
use bitcoin::opcodes::{OP_0, OP_TRUE};
use bitcoin::script::write_scriptint;
use bitcoin::Witness;
use std::convert::TryFrom;
use std::hash::Hash;
use std::hash::Hasher;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Hash, PartialEq)]
pub enum Block {
    Call(u64),
    Script(ScriptBuf),
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Hash)]
#[derive(Clone, Debug, PartialEq)]
pub struct StructuredScript(ScriptBuf);

impl StructuredScript {
    pub fn new(_: &str) -> Self {
        Self(ScriptBuf::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push_opcode(mut self, data: Opcode) -> StructuredScript {
        self.0.push_opcode(data);
        self
    }

    pub fn push_slice<T: AsRef<PushBytes>>(mut self, data: T) -> StructuredScript {
        self.0.push_slice(data);
        self
    }

    pub fn push_script(self, data: ScriptBuf) -> StructuredScript {
        let mut inner = self.0.into_bytes();
        inner.append(&mut data.into_bytes());

        Self(ScriptBuf::from_bytes(inner))
    }
    pub fn push_env_script(self, data: StructuredScript) -> StructuredScript {
        self.push_script(data.0)
    }

    pub fn compile(self) -> ScriptBuf {
        self.0
    }
}

impl StructuredScript {
    pub fn push_int(self, data: i64) -> StructuredScript {
        // We can special-case -1, 1-16
        if data == -1 || (1..=16).contains(&data) {
            let opcode = Opcode::from((data - 1 + OP_TRUE.to_u8() as i64) as u8);
            self.push_opcode(opcode)
        }
        // We can also special-case zero
        else if data == 0 {
            self.push_opcode(OP_0)
        }
        // Otherwise encode it as data
        else {
            self.push_int_non_minimal(data)
        }
    }

    pub fn push_key(self, key: &::bitcoin::PublicKey) -> StructuredScript {
        if key.compressed {
            self.push_slice(key.inner.serialize())
        } else {
            self.push_slice(key.inner.serialize_uncompressed())
        }
    }

    pub fn push_x_only_key(self, x_only_key: &::bitcoin::XOnlyPublicKey) -> StructuredScript {
        self.push_slice(x_only_key.serialize())
    }

    pub fn push_expression<T: Pushable>(self, expression: T) -> StructuredScript {
        expression.bitcoin_script_push(self)
    }

    fn push_int_non_minimal(self, data: i64) -> StructuredScript {
        let mut buf = [0u8; 8];
        let len = write_scriptint(&mut buf, data);
        self.push_slice(&<&PushBytes>::from(&buf)[..len])
    }
}

// We split up the bitcoin_script_push function to allow pushing a single u8 value as
// an integer (i64), Vec<u8> as raw data and Vec<T> for any T: Pushable object that is
// not a u8. Otherwise the Vec<u8> and Vec<T: Pushable> definitions conflict.
trait NotU8Pushable {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript;
}
impl NotU8Pushable for i64 {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_int(self)
    }
}
impl NotU8Pushable for i32 {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_int(self as i64)
    }
}
impl NotU8Pushable for u32 {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_int(self as i64)
    }
}
impl NotU8Pushable for usize {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_int(i64::try_from(self).expect("Usize does not fit in i64"))
    }
}
impl NotU8Pushable for Vec<u8> {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        // Push the element with a minimal opcode if it is a single number.
        if self.len() == 1 {
            builder.push_int(self[0].into())
        } else {
            builder.push_slice(PushBytesBuf::try_from(self.to_vec()).unwrap())
        }
    }
}
impl NotU8Pushable for ::bitcoin::PublicKey {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_key(&self)
    }
}
impl NotU8Pushable for ::bitcoin::XOnlyPublicKey {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_x_only_key(&self)
    }
}
impl NotU8Pushable for Witness {
    fn bitcoin_script_push(self, mut builder: StructuredScript) -> StructuredScript {
        for element in self.into_iter() {
            // Push the element with a minimal opcode if it is a single number.
            if element.len() == 1 {
                builder = builder.push_int(element[0].into());
            } else {
                builder = builder.push_slice(PushBytesBuf::try_from(element.to_vec()).unwrap());
            }
        }
        builder
    }
}
impl NotU8Pushable for StructuredScript {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_env_script(self)
    }
}
impl<T: NotU8Pushable> NotU8Pushable for Vec<T> {
    fn bitcoin_script_push(self, mut builder: StructuredScript) -> StructuredScript {
        for pushable in self {
            builder = pushable.bitcoin_script_push(builder);
        }
        builder
    }
}
impl NotU8Pushable for ScriptBuf {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_script(self)
    }
}

pub trait Pushable {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript;
}
impl<T: NotU8Pushable> Pushable for T {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        NotU8Pushable::bitcoin_script_push(self, builder)
    }
}

impl Pushable for u8 {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_int(self as i64)
    }
}
