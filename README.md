
# KeePass Password Database Assignment

## Overview

This project involves developing a program to perform a brute force attack on a KeePass 2 database, analyzing the database format, and discussing various aspects of its security and key derivation mechanisms.

## Table of Contents
- [Exercise 1: Breaking a KeePass Password Database](#exercise-1-breaking-a-keepass-password-database)
  - [Part a: Brute Force Attack](#part-a-brute-force-attack)
  - [Part b: Using the Cracked Password](#part-b-using-the-cracked-password)
- [Exercise 2: Discussion of the Database Format](#exercise-2-discussion-of-the-database-format)
  - [Part a: Key Transformation Purpose](#part-a-key-transformation-purpose)
  - [Part b: ECB Mode Security](#part-b-ecb-mode-security)
  - [Part c: Password Testing Performance](#part-c-password-testing-performance)
  - [Part d: Stream Start Bytes Field](#part-d-stream-start-bytes-field)
  - [Part e: Integrity Protection in Older KeePass Versions](#part-e-integrity-protection-in-older-keepass-versions)
  - [Part f: Alternative Key Derivation](#part-f-alternative-key-derivation)
- [Appendix A: KeePass 2 Database Format](#appendix-a-keepass-2-database-format)
  - [Structure](#structure)
  - [Key Derivation](#key-derivation)
  
## Exercise 1: Breaking a KeePass Password Database

### Part a: Brute Force Attack

#### Objective:
Create a program to perform a brute force attack on a KeePass 2 database to determine the user password.

#### Requirements:
- Each student has a separate KeePass database.
- Password is a 4-digit number (0000-9999).
- No key file is used.
- Implement the following in your code:
  - Parsing the database
  - Key derivation
  - Trial decryption

#### Implementation Details:
- Use libraries for SHA-256, AES, etc., but core functionalities should be self-coded.
- Brute force all possible 4-digit combinations.

#### Deliverable:
- Provide the cracked password for at least one group member's database.

### Part b: Using the Cracked Password

#### Task:
- Open the database with the cracked password.
- Extract and provide the login and password stored inside.

## Exercise 2: Discussion of the Database Format

### Part a: Key Transformation Purpose

#### Discussion:
Explain the purpose of key transformation (transformedCredentials) and the impact of the number of transform_rounds.

### Part b: ECB Mode Security

#### Discussion:
Evaluate whether using ECB mode compromises the security of the key transformation.

### Part c: Password Testing Performance

#### Task:
- Measure passwords tested per second by your program.
- Estimate the time to crack the database with expanded key spaces:
  - Lowercase letters
  - Lowercase and uppercase letters
- Consider transform_rounds values of 10,000 and 1,000,000.

### Part d: Stream Start Bytes Field

#### Discussion:
Explain the purpose of the stream start bytes field in the header. Suggest an alternative method to achieve the same functionality.

### Part e: Integrity Protection in Older KeePass Versions

#### Task:
- Demonstrate how to create a second valid file with modified header but same content, decryptable without the new integrity check.
- Include the modified database file in your solution.

### Part f: Alternative Key Derivation

#### Task:
- Implement PBKDF2-HMAC-SHA256 for key derivation.
- Measure the iterations (transform_rounds) required for a 1-second key derivation on your CPU.
- Update estimates from Part c based on this new key derivation method.

## Appendix A: KeePass 2 Database Format

### Structure

- **Signature Fields (4 bytes each):**
  - 0x9AA2D903
  - 0xB54BFB67
  - <Version>

- **Header Fields:**
  - ID (1 byte)
  - Length (2 bytes)
  - Data (<Length> bytes)

- **Relevant Header Fields:**
  - 0: End of header
  - 4: Master seed
  - 5: Transform seed
  - 6: Transform rounds
  - 7: Encryption IV
  - 9: Stream start bytes

- **Encrypted Data Stream:**
  - AES-256 in CBC mode.
  - First 32 bytes are random and copied to stream start bytes header field.
  - Correct password matches stream start bytes upon decryption.

### Key Derivation

- **Process:**
  1. `credentials = SHA-256(SHA-256(password))`
  2. `transformed_credentials = SHA-256(AES-256transform_rounds(transform_seed, credentials))`
  3. `key = SHA-256(master_seed ∥ transformed_credentials)`

Note: AES-256 in ECB mode is applied transform_rounds times to transform_seed.

---

This README provides a comprehensive overview of the tasks and requirements for the KeePass password database assignment. Follow the structure and guidelines to complete the exercises and document your findings.
