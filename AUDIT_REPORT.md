# Audit Report: RootkitDetector
**Date:** 2026-04-21T13:43:51.583315 | **Auditor:** v2

## Summary

| Metric | Value |
|--------|-------|
| Files Analyzed | 19 |
| Tests | 0 PASS / 1 FAIL |
| Mutation Score | 83% |
| Security Issues | 13 |
| Logic Bugs | 1 |

## Security (13)

- CRITICAL: Cmd Inj: os.popen() L60
- CRITICAL: Cmd Inj: os.popen() L104
- CRITICAL: Cmd Inj: os.popen() L84
- CRITICAL: Cmd Inj: os.popen() L64
- CRITICAL: Cmd Inj: os.popen() L148
- CRITICAL: Cmd Inj: os.popen() L91
- CRITICAL: Cmd Inj: os.popen() L131
- CRITICAL: Cmd Inj: os.popen() L157
- CRITICAL: Cmd Inj: os.popen() L176
- CRITICAL: Cmd Inj: os.popen() L205
- CRITICAL: Dangerous eval() L64
- CRITICAL: Dangerous eval() L86
- CRITICAL: Dangerous eval() L125

## Logic (1)

- LOW: range(len) L74

*Multi-Test Auditor v2*
