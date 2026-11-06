# Example settings for Invoke-WebInventory.ps1 -ConfigFile .\WebInventory.example.psd1
# Data only: parsed with Import-PowerShellDataFile (no code runs). Keys are script parameter names.
# Anything given on the command line overrides the value here. Unknown keys stop the run.
@{
    HostFile     = 'D:\WebInventory\scope\dmz-hosts.txt'
    PortFile     = 'D:\WebInventory\scope\ports.txt'
    ExcludeFile  = 'D:\WebInventory\scope\exclude.txt'
    ScopeFile    = 'D:\WebInventory\scope\authorized-ranges.txt'   # fail-closed: anything outside stops the run

    Pace         = 'Polite'          # Polite | Normal | Fast
    MaxPerHost   = 2
    TimeoutMs    = 4000

    IdentifyPaths = $true            # fixed list of public product/version pages
    # VersionPaths = $true          # one GET to a detected product's version URL when the page showed no version
    ProbeSans     = $true            # vhosts from certificate SANs that resolve to the same IP
    ReverseDns    = $true
    # Cname       = $true          # CNAME chain of each hostname target (one DNS query per name to this host's resolvers)
    # TlsFingerprint = $true         # JARM (+10 handshakes per TLS service) and JA4S (see the FoxIO licence note)
    # Smb  = $true                   # TCP 445: dialect, signing, SMBv1, names/domain/build (no login)
    # Rdp  = $true                   # TCP 3389: NLA, security protocol, certificate, names/build (no login)
    # Snmp = $true                   # UDP 161 sysDescr etc.; v3 engine discovery only unless a credential is given
    # Screenshot = $true             # headless Edge after the scan, confined to the scanned origins
    # Proxy = 'http://jump01:3128'   # HTTP CONNECT proxy on a jump host (credentials only on the command line)
    # SnmpCommunity = '...'          # possible here, but then restrict this file's ACL; SNMPv3 and proxy credentials
                                     # (PSCredential / SecureString) can only be passed on the command line

    OutputDir    = 'D:\WebInventory\results'
    BaselineCsv  = 'auto'            # diff against the newest previous run in OutputDir
    Tag          = 'Weekly-DMZ'
    MaxRuntimeMinutes = 360          # stop dispatching after 6 h; resume with -Resume
    NoProgress   = $true             # scheduled task: no progress bar
    Quiet        = $true

    Store        = 'D:\WebInventory\store'   # inventory history: each complete run is archived and added after the scan
    # RetireAfter = 3                # consecutive in-scope runs without a service before it is marked Retired
    # SnapshotEvery = 7              # keep a full inventory snapshot every 7th run (the others keep their change log)
    # AnchorEventLog = $true         # ledger heads to the Application event log (once, as admin: -RegisterEventSource)
}
