# risczero-poc

Objective: evaluate performance of a bn254 proof verification using risczero.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
export PATH=$PATH:$HOME/.cargo/bin
curl -L https://risczero.com/install | bash
export PATH=$PATH:$HOME/.risc0/bin
rzup install
```