# Build recipe: zlib 1.2.11 (manifest contributor fixture)

Reproducible source build for verifying `deflate` symbol presence when
contributing `CVE-2018-25032` candidate entries.

```bash
curl -fsSL -o zlib-1.2.11.tar.gz https://zlib.net/fossils/zlib-1.2.11.tar.gz
echo "c3e5a2f47e2ead812f7b47b578065e6751a47189" zlib-1.2.11.tar.gz | sha1sum -c -
tar xf zlib-1.2.11.tar.gz
cd zlib-1.2.11
./configure --prefix=/tmp/zlib-1.2.11
make -j"$(nproc)"
# shared object for nm/objdump verification:
make -f Makefile.in shared
cp libz.so ../zlib-1.2.11.so
nm -D ../zlib-1.2.11.so | grep deflate
```

Attach `zlib-1.2.11.so` under `testdata/manifest-fixtures/` in your PR, or
link this recipe in the PR template **build recipe** field.
