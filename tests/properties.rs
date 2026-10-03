#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "Integration fixtures and assertions deliberately fail the test on error."
)]
use proptest::prelude::*;
use secretsd_protocol::*;

proptest! {
    #[test]
    fn arbitrary_frames_never_accept_inconsistent_lengths(bytes in prop::collection::vec(any::<u8>(),0..70_000)) {
        if let Ok(frame) = Frame::decode(&bytes) {
            prop_assert!(bytes.len() <= MAX_FRAME);
            prop_assert_eq!(frame.payload.len() + HEADER_LEN, bytes.len());
            let roundtrip = encode_frame(frame.request_id, frame.message_type, frame.payload).unwrap();
            prop_assert_eq!(&roundtrip,&bytes);
        }
    }
    #[test]
    fn bounded_header_roundtrip_preserves_all_typed_fields(payload in prop::collection::vec(any::<u8>(),0..4096), kind in any::<u16>(),id in any::<[u8;16]>()) {
        prop_assume!(id != [0;16]);
        let encoded = encode_frame(OperationId(id),kind,&payload).unwrap();
        let decoded = Frame::decode(&encoded).unwrap();
        prop_assert_eq!(decoded.request_id,OperationId(id));
        prop_assert_eq!(decoded.message_type,kind);
        prop_assert_eq!(decoded.payload,payload);
        let mut length_tampered = encoded;
        length_tampered[27] ^= 1;
        prop_assert!(Frame::decode(&length_tampered).is_err());
    }
}
