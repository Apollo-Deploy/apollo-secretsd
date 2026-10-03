#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;
use secretsd_protocol::*;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(frame) = Frame::decode(bytes) {
        assert_eq!(frame.payload.len() + HEADER_LEN, bytes.len());

        assert_eq!(
            encode_frame(frame.request_id, frame.message_type, frame.payload).unwrap(),
            bytes
        );

        if let Ok(redeem) = Redeem::decode(&frame) {
            assert_eq!(frame.message_type, REDEEM_REQUEST);

            assert_eq!(redeem.token().as_slice(), frame.payload);

            assert_eq!(format!("{redeem:?}"), "Redeem([REDACTED])");
        }
    }

    if let Ok(request) = decode_canonical::<AdminRequest>(bytes) {
        assert_eq!(request.encode_to_vec(), bytes);
    }

    if let Ok(response) = decode_canonical::<Response>(bytes) {
        assert_eq!(response.encode_to_vec(), bytes);
    }
});
