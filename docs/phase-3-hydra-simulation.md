# Phase 3 — Hydra Brute-Force Simulation

## Goal

Generate a realistic SSH brute-force attack against the EC2 victim server, captured
end-to-end in Splunk, to provide real attack data for detection engineering in Phase 4.

## Preparing the Target

By default, the EC2 victim server only accepts key-based SSH auth, which Hydra can't
brute-force in a realistic way. To simulate a genuine credential-based attack:

1. Temporarily enabled password authentication on the victim server:
   ```
   # /etc/ssh/sshd_config
   PasswordAuthentication yes
   ```
2. Set the `ubuntu` user's password to an intentionally weak value (`password`) —
   representative of the kind of weak-credential scenario this detection is meant
   to catch.
3. Restarted `sshd` to apply the change.

**Gotcha:** AWS Ubuntu AMIs can carry an override file at
`/etc/ssh/sshd_config.d/*.conf` (e.g. `50-cloud-init.conf`) that silently re-forces
`PasswordAuthentication no`, even after editing the main config. Both locations need
to be checked if password auth doesn't seem to take effect.

## Running the Attack

Hydra was run against the victim server's SSH service, targeting the `ubuntu` account
with a wordlist containing the correct password among several incorrect guesses.

Hydra successfully cracked `ubuntu:password` after a small number of failed attempts —
the run stopped as soon as it found a valid credential (default Hydra behavior), which
means the resulting failed-attempt volume (3 failures) is on the low end compared to a
real-world brute-force campaign that might run into the hundreds or thousands of
attempts.

Source IP observed for the attack: `72.255.58.137`

## Verifying Capture in Splunk

Confirmed both event types landed in the index:

```spl
index=* host="ip-172-31-13-183" "Failed password"
```
```spl
index=* host="ip-172-31-13-183" "Accepted password"
```

Both queries returned results correlating with the Hydra run — failed attempts for
incorrect guesses, followed by one accepted-password event for the successful guess.

## Outcome

Real, Splunk-indexed brute-force attack data now exists for the account/detection
work in Phase 4. This dataset reflects an early-stopping attack; a larger-scale or
no-early-stop Hydra run is planned to produce a more realistic failed-attempt volume
and validate detection thresholds at production-like scale.

## Post-Simulation Cleanup (Pending)

Password authentication and the weak `ubuntu` password remain enabled on the victim
server for now, in case further Hydra runs are needed. Reverting to key-only SSH auth
is planned once attack-simulation work is fully complete, for realism/security hygiene.
