# vendor/ — offline wheel-house

Wheels for every pinned dependency in `requirements.txt`, so the project installs with
no index access (M0.2, and the M12.6 demo-laptop constraint):

```
pip install --no-index --find-links vendor -r requirements.txt
```

The wheels themselves are **not committed** (see `.gitignore`); rebuild the wheel-house
on any connected machine with:

```
scripts\build_vendor.ps1
```

which runs `pip download -r requirements.txt -d vendor` using the same Python version
(3.12, win_amd64) as the demo machine. Rebuild it whenever `requirements.txt` changes,
and carry `vendor/` to the demo laptop on disk.
