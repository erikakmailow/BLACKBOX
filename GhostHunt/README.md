\# GhostHunt



\*\*GhostHunt\*\* is a modular, read-only Windows security anomaly hunter built with PowerShell.



It analyzes endpoint telemetry and correlates multiple security signals to help identify suspicious processes, execution contexts, signatures, and network activity.



> GhostHunt is part of the BLACKBOX security engineering toolkit.



\## Current Capabilities



\- Process anomaly detection

\- Process parent/child relationship analysis

\- Executable signature analysis

\- Network/process correlation

\- Multi-signal security correlation

\- Explainable risk scoring

\- Severity classification

\- Confidence scoring

\- Read-only endpoint analysis

\- PowerShell 5.1 compatibility



\## Architecture



```text

&#x20;                   GHOSTHUNT

&#x20;                       |

&#x20;         +-------------+-------------+

&#x20;         |             |             |

&#x20;         v             v             v

&#x20;    ProcessHunt   ProcessTree   SignatureHunt

&#x20;         |             |             |

&#x20;         +-------------+-------------+

&#x20;                       |

&#x20;                       v

&#x20;                 NetworkHunt

&#x20;                       |

&#x20;                       v

&#x20;               CorrelationEngine

&#x20;                       |

&#x20;                       v

&#x20;                  RiskEngine

&#x20;                       |

&#x20;                       v

&#x20;               Security Findings

