These inputs contain only invented test data. `schema.sql` is a minimal Signal
profile with a marker, image reference and poll.

`signal-keys.json` and `signal-macos.keychain-db` are copied from the artefacts
crate's `src/recovery/fixtures/` after running its
`tools/fixtures/generate_signal_vectors.py`. That independent Python generator uses
PyCryptodome and Impacket; the Keychain preserves native synthetic crypto records
and relabels only the unauthenticated service/account selectors. Neither native
credential APIs nor acquired user files are needed to run these tests.

The `linux-*` files contain invented data from the artefacts crate's Linux
generators. `tools/fixtures.py sync --artefacts ../exhume_artefacts` copies those inputs and
independently generates a GNOME collection with the exact `Signal Beta`
application attribute. The KWallet vector uses KDE's historical checksum
compatibility, verified by the artefacts tests against compiled upstream code.
The database key is shared with the existing invented indexer vectors so tests
can build the small `schema.sql` database through SQLCipher. These are not lab
acquisitions and contain no user credentials or messages.

`tools/fixture-copies.json` lists the canonical artefacts input for every copied file;
`tools/fixture-hashes.json` also pins the independently generated beta collection and
local schema. Run `python3 tools/fixtures.py check --artefacts ../exhume_artefacts`
without crypto dependencies, or use the artefacts fixture driver's `--indexer` option.
Copies are packaged here so this crate's tests work independently after publication.
