use cometbls_groth16_verifier::{handle_verify_zkp_request, VerifyZkpRequest};
use risc0_zkvm::guest::env;

fn main() {
    let request: VerifyZkpRequest = env::read();
    let result = handle_verify_zkp_request(request);
    env::commit(&result.is_ok());
}
