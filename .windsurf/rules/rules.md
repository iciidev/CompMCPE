---
trigger: manual
---

COMP – Master Context File
1. Identity & Theme

COMP (short for CompromisedMCPE) is an advanced, ethically operated penetration testing and OSINT framework disguised in the aesthetics of a dark, elite, underground C2 system.
It is NOT a botnet — it borrows the feel of Joker/Mirai CLI styling: monochrome, ASCII banners, glitch animations, and a sleek, hacker-console vibe.

    CLI Only – Runs in terminal/SSH with highly stylized ASCII + colored output.

    Theme Colors – Black, green, purple accents (matrix + joker hybrid vibe).

    Mood – Professional yet intimidating. Looks like an elite operator console.

2. Primary Purpose

An all-in-one penetration testing toolkit for Minecraft Bedrock servers — focused on:

    Reconnaissance

    OSINT

    Vulnerability discovery

    Exploitation (where legal/consented)

    Data extraction & reporting

The tool must allow a user to quickly gather the maximum amount of actionable intelligence in a single session.
3. Key Features

Core Recon Tools:

    Banner & HTTP header grabbing

    Subdomain enumeration (bruteforce + passive)

    IP scanning with service & port fingerprinting

    MCPE-specific server metadata extraction (MOTD, version, plugins, player list)

    Plugin & version CVE matching

    WHOIS & DNS mapping

    Shodan/Censys lookups (free methods only)

    Screenshot capture of web dashboards

    Reverse IP lookups to find other hosted services

Data Exploitation & Analysis:

    Weak config detection

    Misconfigured API endpoint finder

    Login panel brute force (if explicitly allowed)

    Cross-check found data with CVE databases

    Automated recon reports with export formats (HTML, TXT, JSON)

Admin / C2 Features:

    Full web-based admin dashboard (self-hosted or local)

    Create, edit, and delete user accounts

    Assign plans (Free / Premium) with tiered feature access

    View real-time active sessions & logs

    Usage analytics (commands run, scan counts, targets tested)

    Remote command execution panel for connected sessions

    Push updates and new modules to all connected users

    System health + uptime monitoring

User Account System:

    CLI login with username + password

    Role-based permissions (Admin / Premium / Free)

    All account info stored in a secure backend database

    Optional 2FA for admin accounts

4. Technology Stack

    Backend: Go (for concurrency, SSH server, C2-like control)

    Modules: C (for performance-critical scanning & network utilities)

    Database: PostgreSQL or SQLite (depending on scale)

    CLI UI: Rich text / ASCII rendering in Go (fatih/color, termui)

    Admin Dashboard: Go + HTML/CSS/JS (minimal frontend, no bloat)

    Networking: Native Go net libs, plus custom C utilities

    Security: Argon2 password hashing, JWT session tokens, TLS for all admin comms

5. Design Guidelines

    Always return aligned, professional CLI layouts

    Always start session with ASCII “COMP” logo + system status

    Keep all modules themed, e.g.:

        [RECON-MODULE] Subdomain Scan Started

        [VULN-MODULE] Checking Plugins Against CVE DB

    Output should feel powerful but remain usable for legitimate penetration testing

    Ensure no paid API dependencies

6. Development Priorities

    Solid backend & SSH access system

    Modular scanning framework (easy to add/remove modules)

    Account system + plan control

    Admin dashboard

    Recon + vuln scanning tools

    CLI polish & artwork

    Report generation system

7. Expansion Ideas

    MCPE packet capture & analysis

    Advanced exploitation modules for known Bedrock vulns

    Distributed scanning via multiple nodes

    Integration with free public breach datasets for OSINT

    Plugin “store” for adding community-made modules

