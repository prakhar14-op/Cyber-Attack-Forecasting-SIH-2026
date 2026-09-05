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

**Windows path-length caveat (hit for real on 2026-09-05):** torch ships header paths
deep enough that installing into a venv under a long prefix dies with
`[Errno 2] ... mem_eff_attention\epilogue\epilogue_rescale_output.h`. On the demo
laptop either enable NTFS long paths or create the venv at a short path (e.g.
`C:\sih26\.venv`). The M0.2 proof used a fresh venv at a short path.
