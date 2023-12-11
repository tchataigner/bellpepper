//! Circuit for the [`Sha3-256`] function.
//!
//! [`Sha3-256`]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::PrimeField;

use super::boolean::Boolean;

/// Round constants used in the Keccak-f[1600] permutation of SHA-3.
///
/// In the SHA-3 hashing algorithm, based on the Keccak cryptographic function,
/// these constants are used in each of the 24 rounds of the Keccak-f[1600] permutation.
/// There are 24 constants, one for each round.
///
/// These constants are derived from the binary expansion of the first 24 cube roots of primes.
/// In the Keccak-f[1600] permutation, these constants are XORed with the state.
///
/// The constants can be found in the [keccak specifications](https://keccak.team/keccak_specs_summary.html).
///
/// # Format
///
/// Each constant is a 64-bit unsigned integer (`u64`), making them suitable for the
/// 64-bit word size used in the SHA-3 state matrix.
#[allow(clippy::unreadable_literal)]
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];


/// `MD_SIZE` is the size of the expected output, 256 bits.
const MD_SIZE: usize = 256;

/// Bit rate for our implementation. Defined as: `maximal_state_bit_size - capcity`. Per the specifications,
/// `maximal_state_bit_size = 1600` and `capcity` is `md_size * 2`.
///  In our case: 1600 - 256 * 2 = 1088.
const BIT_RATE: usize = 1088;

/// Represents the state of the SHA-3 Keccak permutation function.
///
/// SHA-3 utilizes a 5x5 matrix of 64-bit words for its internal state, making up
/// a total of 1600 bits. This state is manipulated through a series of permutation
/// rounds as part of the Keccak algorithm.
///
/// The state is central to the SHA-3 hash function's sponge construction, where
/// it absorbs input bits and then squeezes out the hash output.
///
/// For more details on the SHA-3 algorithm and its internal state, refer to the
/// [SHA-3 Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf).
///
/// # Usage
///
/// This struct is typically used internally by the SHA-3 hashing functions and
/// is manipulated using the Keccak permutation rounds. It is initialized to all
/// zeros and then modified by absorbing the input message and subsequently by
/// the permutation rounds.
#[derive(Default)]
pub struct Sha3State {
    /// The 5x5 matrix of 64-bit words constituting the state.
    /// Each word is represented as `u64`, making the total size of the state 1600 bits.
    pub matrix: [[u64; 5]; 5],
}

impl Sha3State {
    /// Creates a new `Sha3State` with an initial value.
    ///
    /// All elements of the state matrix are initialized to zero,
    /// which is the starting state for the SHA-3 Keccak function.
    ///
    /// # Returns
    ///
    /// A new `Sha3State` with all elements set to zero.
    pub fn new() -> Self {
        Sha3State {
            matrix: [[0; 5]; 5],
        }
    }

    // Additional methods for manipulating the state can be added here
}

pub fn sha3<Scalar, CS>(mut cs: CS, input: &[Boolean]) -> Result<Vec<Boolean>, SynthesisError>
    where
        Scalar: PrimeField,
        CS: ConstraintSystem<Scalar>,
{
    let mut sha3_state = Sha3State::default();

    let mut padded = input.to_vec();

    // Pad our input.
    pad10_1(&mut padded);

    // Ensure that our message is modulo 512 bits.
    assert!(padded.len() % 512 == 0);

    for (i, block) in padded.chunks(512).enumerate() {
        // TODO split into 64 bits block, set it in state

        // TODO permute the state based on specifications
    }

    // TODO encode as hex and output the digest

}

/// Applies the pad10*1 padding scheme to a message for SHA-3.
///
/// This function pads the given message according to the pad10*1 scheme as specified in
/// section 5.1 of [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
/// which is the standard for SHA-3. The pad10*1 padding is designed to extend the message
/// so that its length is congruent to `BIT_RATE - 1` modulo [`BIT_RATE`].
///
/// The padding process involves appending a '1' bit to the message, followed by as many '0' bits
/// as required, and concluding with another '1' bit. This ensures that the total length of the
/// message, including padding, is a multiple of [`BIT_RATE`].
///
/// # Arguments
///
/// * `input` - A `Vec<Boolean>` representing the message to be padded.
///
/// # Examples
///
/// ```
/// let mut message = vec![/* ... your message bits ... */];
/// pad10_1(&mut message);
/// // `message` is now padded according to pad10*1
/// ```
///
/// # References
///
/// * [NIST FIPS 202: SHA-3 Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
/// * Section 5.1 "Specification of pad10*1"
fn pad10_1(input: &mut Vec<Boolean>) {
    // Append a '1' bit
    input.push(Boolean::constant(true));

    // Calculate the number of '0' bits to append
    let zero_bits_to_append = (BIT_RATE - 1 - input.len() % BIT_RATE) % BIT_RATE;

    // Append '0' bits
    for _ in 0..zero_bits_to_append {
        input.push(Boolean::constant(false));
    }

    // Append another '1' bit
    input.push(Boolean::constant(true));
}