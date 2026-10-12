# Webfonts

Served from this box; nothing here is fetched from the internet at runtime.
Two reasons: the panel has to look the same on an IDS appliance with no route to
the outside world, and a font CDN would leak every page view to a third party.

## Where they come from

Both faces are Debian packages, so they satisfy the project rule of installing
only from Debian repositories:

| File | Debian package | Licence |
|---|---|---|
| `InterVariable.woff2` | `fonts-inter-variable` | OFL-1.1 |
| `JetBrainsMono-Regular.woff2`, `-Medium.woff2` | `fonts-jetbrains-mono-web` | Apache-2.0 |

Full licence texts sit beside them as `*-LICENSE.txt`. Both permit
redistribution and web embedding, which is what shipping them in an image does.

## Regenerating

`fonts-inter-variable` ships a variable TTF rather than a webfont, so it is
converted here (`woff2` package, ~850 kB -> ~350 kB). JetBrains Mono is packaged
as WOFF2 already.

```bash
sudo apt install fonts-inter-variable fonts-jetbrains-mono-web woff2
cp /usr/share/fonts/truetype/inter-vf/InterVariable.ttf .
woff2_compress InterVariable.ttf && rm InterVariable.ttf
cp /usr/share/fonts/woff2/jetbrains-mono/JetBrainsMono-{Regular,Medium}.woff2 .
```

One variable file covers every weight the panel uses, so adding a weight in CSS
costs no extra download.
