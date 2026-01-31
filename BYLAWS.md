# La Propaganda Bylaws

*Version 1.0 — Ratified: [DATE]*

These bylaws govern the operation of La Propaganda, an autonomous publishing platform with cryptographic governance.

---

## Article I: Purpose and Principles

### Section 1.1: Mission
La Propaganda exists to publish verifiable, tamper-evident content where authenticity can be independently verified by any reader.

### Section 1.2: Core Principles
1. **Transparency**: All governance actions are publicly recorded and cryptographically signed.
2. **Verifiability**: Any reader can verify content authenticity without trusting the platform.
3. **Autonomy**: Once established, the editorial board operates independently of the owner.
4. **Accountability**: All actions leave an immutable audit trail.

---

## Article II: Governance Structure

### Section 2.1: Owner Authority
The Owner holds constitutional authority over the organization through control of hardware signing keys.

**Powers:**
- Appoint and remove editorial board members
- Modify approval thresholds
- Amend these bylaws
- Dissolve the organization

**Limitations:**
- Cannot publish content directly (delegated to Editorial Board)
- Cannot approve individual articles
- Cannot retroactively modify published content

### Section 2.2: Editorial Board
The Editorial Board is responsible for all published content.

**Powers:**
- Approve or reject submitted articles
- Sign and publish content
- Establish editorial standards

**Limitations:**
- Cannot modify board composition
- Cannot change governance rules
- Cannot access owner keys

### Section 2.3: Authors
Authors submit content for editorial review.

**Powers:**
- Submit articles for review
- Sign their own work
- Withdraw unpublished submissions

---

## Article III: Key Management

### Section 3.1: Owner Keys
The Owner SHALL maintain at least TWO (2) hardware signing keys:
- **Primary Key**: Used for routine governance operations
- **Backup Key**: Stored securely off-site

### Section 3.2: Key Security Requirements
1. Keys MUST be hardware security devices (GPG smartcard compatible)
2. Keys MUST use Ed25519 algorithm
3. Keys MUST require physical touch for signing
4. Keys MUST have PIN protection enabled

### Section 3.3: Key Operations

| Operation | Keys Required | Notice Period |
|-----------|---------------|---------------|
| Appoint board member | ONE (1) | 48 hours* |
| Remove board member | ONE (1) | 48 hours* |
| Update member key | ONE (1) | None |
| Change threshold | ONE (1) | 48 hours* |
| Rotate/replace owner key | TWO (2)** | None |
| Emergency key revocation | ONE (1) | None |

*Notice required except during initial board setup (see Section 3.5 exceptions).
**For key rotation: the REMAINING key plus a NEW replacement key.

### Section 3.5: Notice Requirements for Governance Actions
Certain governance actions require prior public notice:

1. **Publication**: Notice MUST be published as a signed article on the platform
2. **OpenTimestamp**: Notice MUST have an OpenTimestamp proof attached
3. **Waiting Period**: 48 hours must elapse after the OpenTimestamp attestation time
4. **Reference**: The governance action MUST reference the notice article hash

**Exceptions (no notice required):**
- Initial board setup (first appointments after owner-init)
- Emergency key revocation (suspected compromise)
- Key rotation (security-sensitive, requires dual key)
- Member key updates (administrative, not compositional)

### Section 3.4: Key Loss Procedure
If ONE key is lost, stolen, or compromised:
1. Use remaining key + new key to deactivate lost key
2. Register new key as replacement
3. Store new backup key off-site
4. Document incident in audit log

If BOTH keys are lost:
- Organization control is permanently lost
- Editorial Board continues operating independently
- No new board members can be appointed

---

## Article IV: Board Member Management

### Section 4.1: Eligibility
Board members may be:
- **Human**: Natural persons with verified identity
- **AI Agent**: Automated systems with designated signing keys

### Section 4.2: Appointment Process
1. Owner publishes appointment notice article
2. OpenTimestamp proof created for notice
3. After 48-hour waiting period:
   a. Owner signs appointment with hardware key, referencing notice hash
   b. Appointment recorded in authority manifest
   c. New member key registered in config
4. Member may begin signing after appointment is recorded

### Section 4.3: Removal Process
1. Owner publishes removal notice article
2. OpenTimestamp proof created for notice
3. After 48-hour waiting period:
   a. Owner signs removal with hardware key, referencing notice hash
   b. Member marked as inactive (not deleted)
   c. Member's signatures on pending articles invalidated
4. Historical signatures remain valid

### Section 4.4: Term of Office
Board members serve indefinitely until:
- Voluntary resignation
- Removal by Owner
- Key compromise requiring rotation

---

## Article V: Content Publication

### Section 5.1: Approval Threshold
Content requires **k-of-n** board member signatures where:
- **k** = minimum signatures required (set by Owner)
- **n** = presenting members (those who cast a vote on the article)

**Quorum Requirements:**
- Minimum attendance: 1 (at least one board member must vote)
- If presenting members < k, all presenting members must approve
- This prevents blocking when members are unavailable

*Example: With threshold k=3 and 5 total members:*
- *If 5 vote: need 3 approvals*
- *If 3 vote: need 3 approvals (all must approve)*
- *If 2 vote: need 2 approvals (all must approve, since 2 < k)*
- *If 1 votes: need 1 approval (minimum attendance met)*

### Section 5.2: Publication Process
1. Author submits article with author signature
2. Board members review and sign (approve/reject)
3. When threshold is met, article is queued for publication
4. CI/CD pipeline verifies signatures and publishes
5. OpenTimestamp proof created for published content

### Section 5.3: Content Integrity
All published content includes:
- SHA-256 content hash
- Author signature
- Editorial board signatures
- Publication timestamp
- Randomart visual fingerprint

---

## Article VI: Amendments

### Section 6.1: Amendment Process
These bylaws may be amended by the Owner through:
1. Publication of proposed amendment as a signed article
2. OpenTimestamp proof of amendment proposal
3. 7-day waiting period for amendments affecting board member rights
4. Signing amendment with hardware key, referencing proposal hash
5. Updating BYLAWS.md in repository
6. Recording change in audit log with OpenTimestamp proof

### Section 6.2: Notice Requirements
| Amendment Type | Notice Period | OpenTimestamp Required |
|----------------|---------------|------------------------|
| Board member rights | 7 days | Yes |
| Threshold changes | 48 hours | Yes |
| Procedural updates | None | Yes (for audit) |
| Immutable provisions | Cannot amend | N/A |

### Section 6.3: Immutable Provisions
The following provisions cannot be amended:
- Requirement for cryptographic signatures
- Public verifiability of content
- Audit log immutability
- OpenTimestamp requirements for governance actions

### Section 6.4: Ratification
These bylaws become effective upon:
1. Owner signing the bylaws hash with hardware key
2. OpenTimestamp proof of ratification
3. Recording ratification in authority manifest

---

## Article VII: Emergency Procedures

### Section 7.1: Key Compromise
If an owner key is suspected compromised:
1. Immediately rotate affected key
2. Review recent governance actions for unauthorized changes
3. Publish incident report
4. Consider rotating all board member keys if widespread

### Section 7.2: Board Member Compromise
If a board member key is compromised:
1. Owner removes compromised member
2. Generate new key for member (if continuing)
3. Re-appoint with new key
4. Review pending articles signed by compromised key

### Section 7.3: Platform Compromise
If the publishing platform is compromised:
1. Readers verify content via local signature verification
2. Archive copies validated against signed hashes
3. Platform restored from signed source

---

## Article VIII: Verification

### Section 8.1: Reader Verification
Any reader MAY verify content authenticity by:
1. Checking content hash against published integrity value
2. Verifying editorial board signatures
3. Comparing randomart fingerprint
4. Checking OpenTimestamp proof

### Section 8.2: Governance Verification
Any party MAY verify governance actions by:
1. Reviewing authority manifest signatures
2. Checking audit log entries
3. Verifying owner key signatures on governance actions

---

## Article IX: Dissolution

### Section 9.1: Voluntary Dissolution
The Owner may dissolve the organization by:
1. Publishing dissolution notice
2. Signing dissolution with hardware key
3. Archiving all content with final integrity proofs
4. Releasing source code and keys (optional)

### Section 9.2: Involuntary Dissolution
The organization is automatically dissolved if:
- All owner keys are permanently lost
- No active board members remain
- Owner explicitly dissolves

### Section 9.3: Post-Dissolution
After dissolution:
- Published content remains verifiable forever
- No new content can be published
- Historical integrity proofs remain valid

---

## Signatures

*This document is signed by the Owner upon ratification.*

```
Owner: [NAME]
Date: [DATE]
Bylaws Hash (SHA-256): [HASH]
Signature: [HARDWARE KEY SIGNATURE]
Hardware Key ID: [KEY_ID]
OpenTimestamp: [OTS_HASH]
```

**Verification**: To verify this ratification:
1. Compute SHA-256 of BYLAWS.md (excluding Signatures section)
2. Verify signature against owner's public key
3. Verify OpenTimestamp proof via `ots verify`

---

## Appendix A: Technical Specifications

### A.1: Cryptographic Algorithms
- **Signing**: Ed25519 (RFC 8032)
- **Hashing**: SHA-256
- **Key Storage**: GPG OpenPGP smartcard
- **Timestamping**: OpenTimestamps (Bitcoin blockchain anchoring)

### A.2: File Locations
- `config.toml`: Owner keys, board configuration
- `.editorial_board/authority_manifest.toml`: Governance audit log
- `.editorial_board/timestamps/`: OpenTimestamp proof files (.ots)
- `BYLAWS.md`: This document

### A.3: Command Reference
See `.editorial_board/GOVERNANCE.md` for full command documentation.

### A.4: OpenTimestamp Integration
All governance actions requiring notice periods use OpenTimestamps:
1. Content hash is submitted to OpenTimestamps calendar servers
2. `.ots` proof file is stored in `.editorial_board/timestamps/`
3. Proof is anchored to Bitcoin blockchain (typically within hours)
4. Verification via `ots verify <file>.ots`

Required tool: `pip install opentimestamps-client`

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **Owner** | Entity holding constitutional authority via hardware keys |
| **Editorial Board** | Group responsible for content approval |
| **Hardware Key** | Physical security device for cryptographic signing |
| **Threshold (k)** | Minimum signatures required for content approval |
| **Presenting Members (n)** | Board members who cast a vote on a specific article |
| **Quorum** | Minimum attendance required for valid decisions (currently 1) |
| **Manifest** | Cryptographically signed record of board composition |
| **Randomart** | Visual fingerprint of content hash |
| **OpenTimestamp** | Cryptographic proof that data existed at a certain time, anchored to Bitcoin blockchain |
| **Notice Period** | Required waiting time between announcement and governance action |
| **Ratification** | Formal signing and timestamping of bylaws to make them effective |

---

## Revision History

| Version | Date | Changes | Signed By |
|---------|------|---------|-----------|
| 1.0 | [DATE] | Initial ratification | [OWNER] |
