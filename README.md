## Artifacts

### Railgun
 - https://github.com/Railgun-Privacy/circuits-v2/tree/main
 - https://ipfs-lb.com/ipfs/QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU/circuits/01x02/

### Railgun PPOI
 - https://github.com/Railgun-Privacy/circuits-ppoi/tree/main
 - https://ipfs-lb.com/ipfs/QmZrP9zaZw2LwErT2yA6VpMWm65UdToQiKj4DtStVsUJHr/

## Secret Management

Development secret management is handled via [SOPS](https://github.com/getsops/sops).

To edit secrets: 
 - `sops secrets/secrets.yaml`

To add a new contributor: 
 - Have them run `age-keygen -o ~/.config/sops/age/keys.txt` and share the public key.
 - Add the public key to `.sops.yaml`.
 - Run `sops updatekeys secrets/secrets.yaml` to update the encrypted secrets file for the new key.
