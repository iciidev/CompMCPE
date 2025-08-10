# COMP - Advanced Cyber Operations Framework

COMP is a high-speed, SSH-accessible cyber operations framework designed for full-spectrum digital reconnaissance, vulnerability discovery, exploitation, and OSINT harvesting.

## Core Features

- SSH-based access with role-based authentication
- High-performance network reconnaissance and scanning
- Advanced OSINT and intelligence gathering
- Vulnerability discovery and exploitation modules
- Target profiling and persistence management
- Real-time admin monitoring and control

## Plans

1. **CompFree** - Basic access with limited features
2. **CompIX** - Enhanced reconnaissance capabilities
3. **CompX** - Full feature access with advanced modules
4. **CompKingX** - Elite tier with exclusive tools and admin features

## Architecture

- **Go Core**: User management, session control, networking orchestration
- **C Modules**: High-performance scanning, packet crafting, exploit deployment
- **BoltDB**: Local database for user data and audit logs
- **Terminal UI**: Minimalist interface with real-time feedback

## Building

```bash
# Install Go dependencies
go mod download

# Build C modules
cd modules/c
make all

# Build main binary
go build -o comp cmd/comp/main.go
```

## Security

- Role-based access control (Admin, Operator, Observer)
- Full audit logging
- Plan-based feature gating
- Encrypted session management

## License

Proprietary - All rights reserved
