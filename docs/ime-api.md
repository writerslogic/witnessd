# Witnessd IME API Documentation

This document describes the Input Method Engine (IME) API for integrating
witnessd cryptographic authorship witnessing into desktop keyboard input systems.

## Overview

The IME package provides a cross-platform engine for recording keystroke
patterns and generating cryptographic evidence of authorship. The engine
operates in pass-through mode: it observes typing without modifying input.

**Supported Platforms:**
- macOS (Input Method Kit)
- Linux (IBus)
- Windows (Text Services Framework)

## Core Components

### Engine

The `Engine` type is the main entry point for IME integration.

```go
import "witnessd/internal/ime"

// Create a new engine
engine := ime.NewEngine()
```

### Session Management

Sessions track typing activity for a specific document or text field.

```go
// Start a session
err := engine.StartSession(ime.SessionOptions{
    AppID:   "com.example.app",   // Application identifier
    DocID:   "document-123",       // Document/field identifier
    Context: "optional context",   // User-provided context
})

// Check if session is active
if engine.HasActiveSession() {
    info := engine.GetSessionInfo()
    fmt.Printf("Session %s: %d samples\n", info.ID, info.SampleCount)
}

// End session and get evidence
evidence, err := engine.EndSession()
```

### Key Processing

Process keystrokes through the engine to record typing patterns.

```go
// Create a key event (auto-detect zone from character)
key := ime.NewKey('a')

// Or with explicit keycode
key := ime.NewKeyWithCode(0x00, 'a')  // macOS keycode

// Or with explicit zone
key := ime.NewKeyWithZone('a', 0)  // Zone 0 = left pinky

// Process the keystroke
delay, err := engine.OnKeyDown(key)

// Apply jitter delay (optional, for anti-forgery)
time.Sleep(delay)

// Record the committed text
engine.OnTextCommit("a")

// Record deletions
engine.OnTextDelete(1)  // Delete 1 rune
```

### Evidence

The `Evidence` type contains cryptographic proof of typing.

```go
evidence, err := engine.EndSession()

// Access evidence fields
fmt.Printf("Session: %s\n", evidence.SessionID)
fmt.Printf("Duration: %v\n", evidence.EndTime.Sub(evidence.StartTime))
fmt.Printf("Keystrokes: %d\n", evidence.TotalKeystrokes)
fmt.Printf("Typing rate: %.1f KPM\n", evidence.TypingRateKPM)
fmt.Printf("Hand alternation: %.2f\n", evidence.Profile.HandAlternation)

// Export to JSON
jsonStr, err := evidence.ToJSON()

// Access cryptographic samples
for _, sample := range evidence.Samples {
    fmt.Printf("Zone: %d, Hash: %x\n", sample.Zone, sample.DocHash)
}
```

## Platform Integration

### macOS (Input Method Kit)

The macOS implementation uses cgo to export C functions callable from
Objective-C:

```objc
// Initialize
WitnessdInit();

// Start session
WitnessdStartSession(appID, docID);

// Process keydown (returns jitter delay in microseconds)
int64_t delay = WitnessdOnKeyDown(keyCode, charCode);

// Record text
WitnessdOnTextCommit(text);
WitnessdOnTextDelete(count);

// End session (returns JSON evidence, caller must free)
char* evidence = WitnessdEndSession();
WitnessdFreeString(evidence);
```

### Linux (IBus)

The Linux implementation uses D-Bus to communicate with IBus.

```bash
# Install
witnessd-ibus -install
ibus restart

# Enable in IBus preferences
```

### Windows (TSF)

The Windows implementation uses the Text Services Framework.

```batch
:: Build and register DLL
regsvr32 witnessd.dll

:: Enable in Windows Settings > Language
```

## Evidence Storage

The `EvidenceStorage` type handles persistent storage.

```go
storage, err := ime.NewEvidenceStorage("")  // Use default directory

// Save evidence
err = storage.Save(evidence)

// Load by session ID
evidence, err = storage.Load("session-id")

// List sessions
sessions, err := storage.List(since, until)

// Prune old records
pruned, err := storage.Prune(30 * 24 * time.Hour)  // 30 days
```

### Platform defaults

Evidence is stored in platform-specific locations:
- **macOS/Linux**: `~/.witnessd/evidence/`
- **Windows**: `%APPDATA%\witnessd\evidence\`

## Keyboard Zones

The engine uses 8 keyboard zones based on standard touch-typing:

| Zone | Finger       | Keys (QWERTY)              |
|------|--------------|----------------------------|
| 0    | Left pinky   | Q, A, Z                    |
| 1    | Left ring    | W, S, X                    |
| 2    | Left middle  | E, D, C                    |
| 3    | Left index   | R, T, F, G, V, B           |
| 4    | Right index  | Y, U, H, J, N, M           |
| 5    | Right middle | I, K, , (comma)            |
| 6    | Right ring   | O, L, . (period)           |
| 7    | Right pinky  | P, ; (semicolon), / (slash)|

Zone information is used to compute hand alternation patterns, which
form part of the cryptographic evidence.

## Error Handling

All functions that can fail return an error as the last return value.
The engine is designed to fail gracefully - if errors occur during
keystroke processing, the evidence may be incomplete but input is
never blocked.

## Thread Safety

The `Engine` type is safe for concurrent use. All methods are protected
by a mutex. The `MobileEngine` wrapper is also thread-safe.

## Best Practices

1. **Start sessions early**: Begin a session when focus enters a text field.
2. **End sessions on blur**: End sessions when focus leaves to capture complete evidence.
3. **Handle jitter delays**: Apply the returned delay for anti-forgery protection.
4. **Store evidence promptly**: Save evidence to persistent storage after each session.
5. **Prune regularly**: Remove old evidence to manage storage space.
