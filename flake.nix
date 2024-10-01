{
  description = "risc0 project template";

  nixConfig = {
    extra-substituters = [
      "https://risc0pkgs.cachix.org"
    ];
    extra-trusted-public-keys = [
      "risc0pkgs.cachix.org-1:EY5UazX0/Q7hGCm6xQSgKX6UkpzyOf07pxjfhhRK7kE="
    ];
  };

  inputs = {
    nixpkgs.follows = "risc0pkgs/nixpkgs";
    # Always use the commit hash that is being updated
    risc0pkgs.url = "github:cspr-rad/risc0pkgs";
  };

  outputs = { self, nixpkgs, risc0pkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSystem = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forEachSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          risc0package =
            risc0pkgs.lib.${system}.buildRisc0Package {
              pname = "risc0package";
              version = "0.0.1";
              src = ./.;
              cargoHash = "sha256-bIIapns/yVyqK9PCi50N4mvhdUc+b6C17+MEBK0PuSE=";
              nativeBuildInputs = [ pkgs.makeWrapper ];
              postInstall = ''
                wrapProgram $out/bin/host \
                  --set PATH ${pkgs.lib.makeBinPath [ risc0pkgs.packages.${system}.r0vm ]}
              '';
            };
        });

      devShells = forEachSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            RISC0_RUST_SRC = "${self.packages.${system}.risc0package.toolchain}/lib/rustlib/src/rust";
            RISC0_DEV_MODE = 1;
            inputsFrom = [ self.packages.${system}.risc0package ];
            nativeBuildInputs = [ risc0pkgs.packages.${system}.r0vm ];
          };
        });
    };
}
