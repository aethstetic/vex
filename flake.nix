{
  description = "Vex - A typed shell with structured data pipelines";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "vex";
          version = "0.1.2";

          src = ./.;

          buildInputs = [ pkgs.glibc ];
          nativeBuildInputs = [ pkgs.gcc pkgs.gnumake ];

          buildPhase = ''
            make PREFIX=$out
          '';

          installPhase = ''
            make PREFIX=$out DESTDIR= install
          '';

          meta = with pkgs.lib; {
            description = "A typed shell with structured data pipelines, written in C";
            homepage = "https://github.com/aethstetic/vex";
            license = licenses.mit;
            platforms = platforms.linux;
            mainProgram = "vex";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [ pkgs.gcc pkgs.gnumake ];
        };
      }
    );
}
