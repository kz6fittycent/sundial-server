# <img src="assets/icon.svg" width="32" alt=""> Sundial Server

The optional parent server for [Sundial](https://github.com/kz6fittycent/sundial), which sets screen time limits on Linux computers. The child's computer connects out to the server, so parents can see and change things wherever the child is. Limits keep working when the server can't be reached.

> **Work in progress.** The snap is in the candidate channel (`sudo snap install sundial-server --channel candidate`). Let's Encrypt certificates are planned; the server uses a self-signed certificate today. The child's computer needs Sundial's `two-snaps` branch, not a released version.

## Screenshots

The accounts and activity shown are made up.

| Parent page | On a phone, dark mode |
|---|---|
| <img src="docs/images/dashboard.png" width="460" alt="Parent page for a paired computer: time left, usage chart, override buttons and today's activity"> | <img src="docs/images/phone-dark.png" width="260" alt="The parent page on a phone in dark mode"> |

Setup, and adding a computer:

<img src="docs/images/setup-welcome.png" width="420" alt="Setup: make a login for yourself"> <img src="docs/images/add-computer.png" width="420" alt="The pairing command and code, with Copy buttons">

## How it works

- One server can manage several computers; choose a child at the top of the page. Each shows the same information and controls as Sundial's own page, activity included.
- Optional location: see where a computer is, off until a parent turns it on. The child sees that it's on.
- Only the server needs to be reachable. Nothing is opened on the child's computer or network.
- A change made while a computer is offline waits for it. Extra time expires after 30 minutes, so it can't turn up the next day.
- The pairing code works once, for 15 minutes. With a self-signed certificate it also lets the computer recognize the server.

## Build

```sh
git clone https://github.com/kz6fittycent/sundial-server
cd sundial-server
cargo build --release
sudo target/release/sundial-server run
```

Then open `https://<server>:8461/` from your home network. The first visit sets up the parents. `sundial-server passwd NAME` works too.

## Versions

Versions are `x.y.z`. Releases count in threes: 0.1.0, 0.1.1, 0.1.2, then 0.2.0.

More in the [wiki](https://github.com/kz6fittycent/sundial-server/wiki).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
