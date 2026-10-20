{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    kmax = {
      url = "github:paulgazz/kmax/v4.10";
      flake = false;
    };
  };

  outputs = { nixpkgs, kmax, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      python = pkgs.python3;

      # Kismet imports all parser versions, including for x86.
      kismetNative = python.pkgs.buildPythonPackage {
        pname = "kismet-native";
        version = "4.10";
        src = kmax;
        format = "other";
        nativeBuildInputs = [ python.pkgs.setuptools ];

        # The older Kconfig parsers need the C standard used before GCC 15.
        env.NIX_CFLAGS_COMPILE = "-std=gnu17";

        buildPhase = ''
          runHook preBuild
          python setup.py build_ext
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          mkdir -p "$out/${python.sitePackages}"
          cp build/lib*/kextractor*.so "$out/${python.sitePackages}/"
          runHook postInstall
        '';
        pythonImportsCheck = [
          "kextractor_v7_1"
          "kextractor_next_20251023"
          "kextractor_next_20210426"
          "kextractor_next_20200430"
          "kextractor_3_19"
          "kextractor_4_12_8"
          "kextractor_4_18"
          "kextractor_3_2"
        ];
      };
      kismetPython = python.withPackages (ps: [
        kismetNative
        ps.networkx
        ps.packaging
        ps.regex
        ps.requests
        ps.tqdm
        ps.whatthepatch
        ps.z3-solver
      ]);
      defaultShell = pkgs.mkShell {
        packages = with pkgs; [ cargo rustc rustfmt pkg-config ];
        buildInputs = with pkgs; [ curl openssl z3 ];
      };
    in {
      devShells.${system} = {
        default = defaultShell;
        kismet = pkgs.mkShell {
          inputsFrom = [ defaultShell ];
          # mkShell supplies GCC, binutils, make, Bash, and standard Unix tools.
          packages = with pkgs; [
            kismetPython
            bc
            bison
            flex
            git
            pahole
            perl
            time
            util-linux
          ];
          buildInputs = with pkgs; [ elfutils ];

          # Use the interpreter that contains the Kismet dependencies.
          KISMET_PYTHON = "${kismetPython}/bin/python3";
          TIME_BINARY = "${pkgs.time}/bin/time";
        };
      };
    };
}
