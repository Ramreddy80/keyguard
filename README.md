# KeyGuard Lab — Cryptography ABA

## Project
**Session/Key-Exchange Weakness: MITM Attack Scenario and Secure Key Exchange with Authentication**

A local Flask web app for demonstrating:
- An unauthenticated X25519 key-exchange substitution scenario.
- A signature-based authentication check using Ed25519.
- HKDF-SHA-256 session-key derivation.
- AES-256-GCM encryption of a sample message.
- A dashboard with protocol event log, status indicators, cryptographic details, and scenario comparison.

## Requirements
- Python 3.10+
- VS Code or another editor
- Internet connection only for installing dependencies

## Run on Windows
1. Extract the ZIP.
2. Open the extracted `keyguard_cryptography_aba` folder in VS Code.
3. Open **Terminal → New Terminal**.
4. Install dependencies:

   ```powershell
   py -m pip install -r requirements.txt
   ```

5. Start the app:

   ```powershell
   py app.py
   ```

6. Open http://127.0.0.1:5000 in your browser.

## Demonstration checklist
### Scenario A: Unauthenticated exchange
- Select **Scenario A — Unauthenticated exchange**.
- Enter a sample message.
- Click **Run security test**.
- Expected status: `VULNERABLE`.
- The event log shows Eve substituting public keys and reading the message.
- Alice/Eve and Bob/Eve fingerprints differ, showing separate session links.

### Scenario B: Authenticated exchange, attack enabled
- Select **Scenario B — Authenticated exchange**.
- Leave **Enable Eve's substitution attempt** checked.
- Click **Run security test**.
- Expected status: `ATTACK DETECTED`.
- The substituted key signature should be invalid and not accepted.
- The genuine Alice/Bob session key fingerprints match.

### Scenario C: Authenticated exchange, no attack
- Select Scenario B.
- Uncheck the attack box.
- Run the test.
- Expected status: `AUTHENTICATED`.
- The genuine presented key verifies.

## Important security note
This is a simplified classroom simulation, not a production protocol. It assumes signing public keys are already trusted, and it omits production protocol details such as full transcript binding, certificate validation workflow, replay protection, and key confirmation. Real systems should use established protocols such as TLS 1.3. Keep the Flask development server on `127.0.0.1` and do not expose it to the public internet.
