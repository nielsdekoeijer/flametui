find ./src -type f \( -name '*.md' -o -name '*.zig' -o -name '*.h' -o -name '*.c' -o -name '*.nix' \) -print0 | sort -z | xargs -0 -I{} sh -c 'printf "\n// ==== %s ====\n" "{}"; cat "{}"' | vi
