#!/usr/bin/env bash
set -euo pipefail
project_dir="$(realpath "${1:?Pass the desktop project directory}")"
test -f "$project_dir/PiiExplorer.slnx"
package_dir="$project_dir/dist/linux-x64"
test -f "$package_dir/PiiExplorer"
mkdir -p "$package_dir/assets/java" "$package_dir/assets/ocr/lib" "$package_dir/assets/ocr/tessdata" "$package_dir/licenses/linux"
echo '2413149700df0f7d440500a84a8f764c535f21e5a5e87d38328b64eec2c5b500  '"$project_dir/.build-tools/linux-jre.tar.gz" | sha256sum -c -
tar -xzf "$project_dir/.build-tools/linux-jre.tar.gz" --strip-components=1 -C "$package_dir/assets/java"
cp /usr/bin/tesseract "$package_dir/assets/ocr/"
cp /usr/share/tesseract-ocr/5/tessdata/{eng,osd}.traineddata "$package_dir/assets/ocr/tessdata/"
cp -r /usr/share/tesseract-ocr/5/tessdata/configs "$package_dir/assets/ocr/tessdata/"
# ldd includes transitive shared dependencies. The system supplies glibc and its loader.
while IFS= read -r library; do
    case "$(basename "$library")" in libc.so.*|libm.so.*|libpthread.so.*|libdl.so.*|librt.so.*|ld-linux*) continue ;; esac
    cp -L "$library" "$package_dir/assets/ocr/lib/"
done < <(ldd /usr/bin/tesseract | awk '/=> \// {print $3}')
for doc in /usr/share/doc/*/copyright; do
    cp "$doc" "$package_dir/licenses/linux/$(basename "$(dirname "$doc")").copyright"
done
cp /etc/os-release "$package_dir/licenses/linux/build-system.txt"
dpkg-query -W > "$package_dir/licenses/linux/build-packages.txt"
chmod +x "$package_dir/PiiExplorer" "$package_dir/assets/ocr/tesseract" "$package_dir/assets/java/bin/"*
echo "Linux runtime bundled in $package_dir"
