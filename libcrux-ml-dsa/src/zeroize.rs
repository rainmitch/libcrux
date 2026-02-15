use crate::{
    polynomial::{
        PolynomialRingElement,

    },
    simd::{portable::PortableSIMDUnit, traits::Operations},
    MLDSAKeyPair, MLDSASigningKey
};

#[cfg(feature = "simd256")]
use crate::simd::avx2::AVX2SIMDUnit;

impl<const SIZE: usize> zeroize::Zeroize for MLDSASigningKey<SIZE> {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}
impl<const SIZE: usize> zeroize::ZeroizeOnDrop for MLDSASigningKey<SIZE> {}

impl<const PRIVATE_KEY_SIZE: usize, const PUBLIC_KEY_SIZE: usize> zeroize::Zeroize
    for MLDSAKeyPair<PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE>
{
    fn zeroize(&mut self) {
        self.signing_key.zeroize();
    }
}
impl<const PRIVATE_KEY_SIZE: usize, const PUBLIC_KEY_SIZE: usize> zeroize::ZeroizeOnDrop
    for MLDSAKeyPair<PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE>
{
}

impl<Vector: Operations + zeroize::Zeroize> zeroize::Zeroize for PolynomialRingElement<Vector> {
    fn zeroize(&mut self) {
        self.simd_units.zeroize();
    }
}
impl<Vector: Operations + zeroize::Zeroize> zeroize::ZeroizeOnDrop
    for PolynomialRingElement<Vector>
{
}

// Don't implement ZeroizeOnDrop for vector types for performance reasons
impl zeroize::Zeroize for PortableSIMDUnit {
    fn zeroize(&mut self) {
        self.values.zeroize();
    }
}

#[cfg(feature = "simd256")]
impl zeroize::Zeroize for AVX2SIMDUnit {
    fn zeroize(&mut self) {
        // AVX2 registers implemented natively by zeroize crate
        self.value.zeroize();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::MLDSAVerificationKey;
    use zeroize::Zeroize;

    trait CheckZero {
        fn is_zero(slice: &[Self]) -> bool where Self: Sized;
    }

    impl CheckZero for u8 {
        #[inline(never)]
        fn is_zero(slice: &[u8]) -> bool {
            slice.iter().all(|&byte| core::hint::black_box(byte) == 0)
        }
    }

    impl CheckZero for i32 {
        #[inline(never)]
        fn is_zero(slice: &[i32]) -> bool {
            slice.iter().all(|&val| core::hint::black_box(val) == 0)
        }
    }


    #[test]
    fn mldsa_signing_key_zeroize() {
        const SIG_KEY_SIZE: usize = 4032; 
        let mut sk = MLDSASigningKey::<SIG_KEY_SIZE>::new([0xFFu8; SIG_KEY_SIZE]);

        assert!(!u8::is_zero(sk.as_ref()), "Key should start non-zero");
        
        sk.zeroize();

        assert!(u8::is_zero(sk.as_ref()), "Key should be zeroed after zeroize()");
    }

    #[test]
    fn mldsa_keypair_cascade() {
        const VERIF_SIZE: usize = 1952;
        const SIG_SIZE: usize = 4032;

        let mut keypair = MLDSAKeyPair {
            signing_key: MLDSASigningKey::<SIG_SIZE>::new([0xAAu8; SIG_SIZE]),
            verification_key: MLDSAVerificationKey::<VERIF_SIZE>::new([0xBBu8; VERIF_SIZE]),
        };

        keypair.zeroize();

        assert!(u8::is_zero(keypair.signing_key.as_ref()), "Signing key should be zeroed");
        
        // Verification key is public, so we don't care if it's zeroed, 
        // but confirm the implementation didn't touch it.
        assert!(!u8::is_zero(keypair.verification_key.as_ref()), "Public key should remain");
    }

    #[test]
    fn portable_simd_unit_zeroize() {
        let mut unit = PortableSIMDUnit { values: [0x7FFFFFFF; 8] };
        
        unit.zeroize();

        assert!(i32::is_zero(&unit.values), "Portable values were not zeroed");
    }

    #[test]
    #[cfg(feature = "simd256")]
    fn avx2_simd_unit_zeroize() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        let mut unit = AVX2SIMDUnit {
            value: libcrux_intrinsics::avx2::mm256_set1_epi32(0x12345678)
        };

        unit.zeroize();

        let opaque_unit = core::hint::black_box(unit);
        
        assert!(
            libcrux_intrinsics::avx2::mm256_testz_si256(opaque_unit.value, opaque_unit.value) != 0,
            "AVX2 register was not zeroed"
        );
    }

    #[test]
    fn polynomial_ring_element_zeroize() {
        let mut poly = PolynomialRingElement::<PortableSIMDUnit>::zero();
        
        for unit in poly.simd_units.iter_mut() {
            unit.values = [0xFF; 8]
        }

        poly.zeroize();

        for unit in poly.simd_units.iter() {
            assert!(i32::is_zero(&unit.values), "Polynomial coefficient block was not zeroed");
        }
    }
}