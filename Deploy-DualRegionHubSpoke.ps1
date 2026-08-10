<#
=============================================================================
 Deploy-DualRegionHubSpoke.ps1                                  Version 21
 -----------------------------------------------------------------------
 v1  Initial build: dual-region hub-spoke, Azure Firewall deployed by the
     script, manual route tables, standalone baseline NSGs.
 v2  Firewall deployment removed (existing FW private IPs as variables),
     optional existing-hub reference, expanded to 4 spokes x 4 subnets per
     region, route tables replaced by AVNM routing configuration, NSGs
     replaced by AVNM security admin configuration.
 v3  Fixed -UseHubGateway switch usage on
     New-AzNetworkManagerConnectivityGroupItem.
 v4  Added $DeleteExistingConfig teardown switch: uncommits and removes all
     AVNM objects (including the network manager), the membership policies
     and the VNets before redeploying.
 v5  All peering is now AVNM-managed. Manual Add-AzVirtualNetworkPeering
     removed; hubs are peered by a global Mesh connectivity configuration
     over a static hub group. Added $SpokeToSpokeDirect to switch spoke
     traffic between firewall-inspected and directly peered.
 v6  Fixed the global hub mesh: a connectivity group item may only be global
     when its group connectivity is DirectlyConnected. Added -Force to the
     AVNM create cmdlets so re-runs overwrite without prompting.
 v7  Corrected two cmdlet names to their documented form
     (New-AzNetworkManagerSecurityAdminRuleCollection /
     New-AzNetworkManagerSecurityAdminRule) and added a preflight check that
     every required cmdlet exists before anything is created.
 v8  Deploy-AzNetworkManagerCommit takes -Name for the network manager, not
     -NetworkManagerName. Preflight now also validates parameter names.
 v9  Three more AVNM connectivity scenarios (global mesh for IaaS prod, IaaS
     nonprod and infra spokes). Routing reworked so IaaS VM subnets reach each
     other directly instead of hairpinning through the firewall. Added a
     per-region infrastructure NSG associated to every spoke subnet.
 v10 Configurations were being committed while the dynamic groups were still
     empty, so nothing appeared linked to the VNets. The script now triggers a
     policy compliance scan, waits for group membership to materialise, and
     only then commits. Ends with a membership/linkage report.
 v11 The membership wait no longer blocks a full run when membership stays at
     zero: it gives up after $MembershipEarlyExitMinutes, prints what to check,
     and commits anyway. Commits are valid against empty groups - AVNM applies
     configurations to members as they join.
 v12 Route tables are now prestaged in this resource group and associated to
     the spoke subnets directly, so routing works on day one. The AVNM routing
     configuration switches to routeTableUsageMode=UseExisting (API 2025-01-01)
     so it appends its tag-driven routes to those tables instead of building
     its own inside an AVNM-managed resource group.
 v13 Security admin rules are now read back from the service after creation and
     the counts reported, so a configuration that ends up with no rule
     collections fails loudly here instead of looking fine until you open the
     portal. Rule creation is also counted as it goes.
 v14 Added AVNM IPAM: a root pool per region with child pools per workload
     tier, and spoke VNets/subnets allocated from those pools instead of from
     hardcoded CIDRs. Static CIDRs reserve the hub ranges. $UseIpamAllocation
     falls back to the fixed address plan when false.
 v15 Fixed the IPAM address plan: a child pool sat outside its root, and the
     two IaaS spokes in each region shared a /16 pool that could only satisfy
     one of them. Now one child pool per spoke, all verified inside their root
     and non-overlapping by a preflight check. Route/security CIDR lists are
     derived from the pool plan when IPAM is on, instead of from $Base.
 v16 IPAM is now per-spoke rather than global. Hubs, shared services and the
     infra/PaaS spokes keep fixed addressing; IaaS spokes and three new
     workload spokes (DevOps, EnterpriseAnalytics, Finance) allocate from
     pools. IPAM roots moved to 10.32/10.40 so they cannot collide with the
     fixed ranges.
 v17 Re-planned addressing: one /16 per region, /20 hubs, /22 workload spokes
     with /24 subnets. Address maths is now computed from real CIDR helpers
     rather than two-octet string prefixes, so subnet layout follows from the
     VNet size instead of being hardcoded.
 v18 IPAM pool creation is now idempotent. A pool's address prefix cannot be
     changed after creation - the update returns BadRequest - so the script
     compares the existing prefix with the plan and recreates the pool
     (children first) when they differ, instead of blindly overwriting.
 v19 Pool reconciliation now reads the service's own view over REST instead of
     relying on PowerShell object properties, and enumerates every pool that
     exists rather than only the ones this version would create - older script
     versions used different child names, and those orphans were blocking the
     root deletions. Deletion retries leaves-first until nothing remains.
 v20 Removed a stale duplicate of Convert-CidrToRange left inside the address
     plan validation. It shadowed the helper version, returned no Prefix
     property, and so every carved subnet came out as /2. Helper self-test
     added so the CIDR maths is checked before any resource is created.
 v21 The security admin verification read $rc.AppliesToGroup, which does not
     exist on the returned object, so a correctly targeted rule collection was
     reported as targeting nothing. It now reads properties.appliesToGroups
     over REST, which is the authoritative field.
 -----------------------------------------------------------------------
 Dual-region (South Central US / North Central US) hub-spoke deployment

 - Uses EXISTING Azure Firewalls (private IPs supplied as variables)
 - Hub VNets (create new, or reference existing) + global hub-to-hub peering
 - 4 spokes per region, each with 4 subnets:
       iaas-prod, iaas-nonprod, paas-prod, infra-prod
 - AVNM with tag-driven dynamic network groups
 - AVNM Connectivity configuration (hub & spoke per region)
 - AVNM Routing configuration (UDR management) -> next hop = regional firewall
 - AVNM Security Admin configuration -> baseline infrastructure rules
   (AD, DNS, security tooling, backup, monitoring) + guardrail denies

 Run in Azure Cloud Shell (PowerShell 7).
 Requires: Network Contributor + Resource Policy Contributor on the scope,
           and a recent Az.Network module (UDR management is newer).
=============================================================================
#>

$ErrorActionPreference = 'Stop'

#region --------------------------- Helpers ---------------------------------
# Runs an action, reporting failure without halting. $ErrorActionPreference is
# 'Stop', so without this a missing resource would abort the whole run.
function Invoke-Safely {
    param([string]$What, [scriptblock]$Action)
    try   { & $Action; Write-Host "   ok: $What" }
    catch { Write-Host "   skipped: $What -> $($_.Exception.Message)" -ForegroundColor DarkYellow }
}

# ---- CIDR arithmetic ----
# The address plan is built from these rather than string concatenation, so
# subnet layout follows from the VNet size and stays correct if sizes change.
function ConvertTo-UInt32Ip {
    param([string]$Ip)
    $b = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    [array]::Reverse($b)
    return [System.BitConverter]::ToUInt32($b, 0)
}

function ConvertFrom-UInt32Ip {
    param([uint32]$Value)
    $b = [System.BitConverter]::GetBytes($Value)
    [array]::Reverse($b)
    return ([System.Net.IPAddress]::new($b)).ToString()
}

function Convert-CidrToRange {
    param([string]$Cidr)
    $parts = $Cidr -split '/'
    $base  = ConvertTo-UInt32Ip $parts[0]
    $size  = [uint32][math]::Pow(2, 32 - [int]$parts[1])
    [pscustomobject]@{ Start = $base; End = $base + $size - 1; Size = $size; Prefix = [int]$parts[1] }
}

# A CIDR at a host offset from the start of a base CIDR, e.g. hub + 64 as a /26
function Get-CidrAtOffset {
    param([string]$BaseCidr, [uint32]$Offset, [int]$PrefixLength)
    $base = (Convert-CidrToRange $BaseCidr).Start
    return "$(ConvertFrom-UInt32Ip ($base + $Offset))/$PrefixLength"
}

# Divide a CIDR into $Count equal subnets, e.g. a /22 into four /24s
function Get-CidrSubnets {
    param([string]$Cidr, [int]$Count)
    $r     = Convert-CidrToRange $Cidr
    $bits  = [int][math]::Ceiling([math]::Log($Count, 2))
    $newPl = $r.Prefix + $bits
    if ($newPl -gt 29) { throw "Cannot split $Cidr into $Count subnets - /$newPl is too small." }
    $step  = [uint32][math]::Pow(2, 32 - $newPl)
    return @(0..($Count - 1) | ForEach-Object {
        "$(ConvertFrom-UInt32Ip ($r.Start + ($_ * $step)))/$newPl"
    })
}
#endregion

#region ---------------------- CIDR helper self-test ------------------------
# These helpers generate every prefix in the deployment, so a silent fault
# (a shadowed function, a null property) shows up as an invalid subnet only
# once Azure rejects it. Check them against known answers up front instead.
$cidrTests = @(
    @{ What = 'range prefix';   Got = (Convert-CidrToRange '10.10.16.0/22').Prefix;              Want = 22 }
    @{ What = 'range size';     Got = (Convert-CidrToRange '10.10.16.0/22').Size;                Want = 1024 }
    @{ What = 'offset /26';     Got = (Get-CidrAtOffset -BaseCidr '10.10.0.0/20' -Offset 64 -PrefixLength 26); Want = '10.10.0.64/26' }
    @{ What = 'offset /24';     Got = (Get-CidrAtOffset -BaseCidr '10.10.0.0/20' -Offset 256 -PrefixLength 24); Want = '10.10.1.0/24' }
    @{ What = 'split /22 x4';   Got = ((Get-CidrSubnets -Cidr '10.10.16.0/22' -Count 4) -join ' '); Want = '10.10.16.0/24 10.10.17.0/24 10.10.18.0/24 10.10.19.0/24' }
    @{ What = 'split /24 x4';   Got = ((Get-CidrSubnets -Cidr '10.10.16.0/24' -Count 4) -join ' '); Want = '10.10.16.0/26 10.10.16.64/26 10.10.16.128/26 10.10.16.192/26' }
)

$cidrFailures = @($cidrTests | Where-Object { "$($_.Got)" -ne "$($_.Want)" })
if ($cidrFailures) {
    Write-Host 'CIDR helper self-test failed:' -ForegroundColor Red
    $cidrFailures | ForEach-Object {
        Write-Host ("   {0,-14} got '{1}'  expected '{2}'" -f $_.What, $_.Got, $_.Want) -ForegroundColor Red
    }
    throw 'CIDR helpers are not behaving correctly - check for a shadowed function definition.'
}
Write-Host ">> CIDR helpers OK ($($cidrTests.Count) checks)" -ForegroundColor DarkGray
#endregion

#region --------------------------- Preflight -------------------------------
# Fail before anything is created if the loaded Az.Network module is missing a
# cmdlet this script depends on, rather than half-deploying and stopping.
$requiredCmdlets = @(
    'New-AzNetworkManager'
    'New-AzNetworkManagerScope'
    'New-AzNetworkManagerGroup'
    'New-AzNetworkManagerStaticMember'
    'New-AzNetworkManagerHub'
    'New-AzNetworkManagerConnectivityGroupItem'
    'New-AzNetworkManagerConnectivityConfiguration'
    'New-AzNetworkManagerSecurityAdminConfiguration'
    'New-AzNetworkManagerSecurityAdminRuleCollection'
    'New-AzNetworkManagerSecurityAdminRule'
    'New-AzNetworkManagerSecurityGroupItem'
    'New-AzNetworkManagerAddressPrefixItem'
    'Deploy-AzNetworkManagerCommit'
    'New-AzNetworkManagerIpamPool'
    'Get-AzNetworkManagerIpamPool'
    'Remove-AzNetworkManagerIpamPool'
    'Get-AzNetworkManagerSecurityAdminRuleCollection'
    'Get-AzNetworkManagerSecurityAdminRule'
    'Remove-AzNetworkManager'
    'Remove-AzNetworkManagerGroup'
    'Remove-AzNetworkManagerConnectivityConfiguration'
    'Remove-AzNetworkManagerSecurityAdminConfiguration'
)

$missing = $requiredCmdlets | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) }
if ($missing) {
    Write-Host 'Missing cmdlets in the loaded Az.Network module:' -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
    throw "Update Az.Network (Update-Module Az.Network) and re-run. Installed: $((Get-Module Az.Network -ListAvailable | Select-Object -First 1).Version)"
}

# Parameter names drift between Az.Network versions, and a mismatch otherwise
# only surfaces once execution reaches that line - mid-deployment. Check the
# ones this script depends on up front.
$requiredParams = @{
    'Deploy-AzNetworkManagerCommit'                  = @('Name','ResourceGroupName','TargetLocation','ConfigurationId','CommitType')
    'New-AzNetworkManager'                           = @('Name','ResourceGroupName','Location','NetworkManagerScope','NetworkManagerScopeAccess')
    'New-AzNetworkManagerGroup'                      = @('Name','ResourceGroupName','NetworkManagerName')
    'New-AzNetworkManagerStaticMember'               = @('Name','ResourceGroupName','NetworkManagerName','NetworkGroupName','ResourceId')
    'New-AzNetworkManagerConnectivityGroupItem'      = @('NetworkGroupId','GroupConnectivity','IsGlobal')
    'New-AzNetworkManagerConnectivityConfiguration'  = @('Name','ResourceGroupName','NetworkManagerName','ConnectivityTopology','AppliesToGroup','IsGlobal','DeleteExistingPeering')
    'New-AzNetworkManagerSecurityAdminConfiguration' = @('Name','ResourceGroupName','NetworkManagerName')
    'New-AzNetworkManagerSecurityAdminRuleCollection'= @('Name','ResourceGroupName','NetworkManagerName','SecurityAdminConfigurationName','AppliesToGroup')
    'New-AzNetworkManagerSecurityAdminRule'          = @('Name','ResourceGroupName','NetworkManagerName','SecurityAdminConfigurationName','RuleCollectionName','Protocol','Direction','Access','Priority')
    'New-AzNetworkManagerAddressPrefixItem'          = @('AddressPrefix','AddressPrefixType')
    'New-AzNetworkManagerIpamPool'                   = @('Name','ResourceGroupName','NetworkManagerName','AddressPrefix','ParentPoolName')
    'New-AzVirtualNetwork'                           = @('IpamPoolPrefixAllocation')
    'New-AzVirtualNetworkSubnetConfig'               = @('IpamPoolPrefixAllocation')
}

$paramProblems = @()
foreach ($c in $requiredParams.Keys) {
    $available = (Get-Command $c).Parameters.Keys
    foreach ($prm in $requiredParams[$c]) {
        if ($prm -notin $available) { $paramProblems += "$c has no -$prm" }
    }
}
if ($paramProblems) {
    Write-Host 'Parameter mismatches in the loaded Az.Network module:' -ForegroundColor Red
    $paramProblems | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
    throw 'Update Az.Network (Update-Module Az.Network) and re-run.'
}

Write-Host ">> Preflight OK - Az.Network $((Get-Module Az.Network -ListAvailable | Select-Object -First 1).Version)" -ForegroundColor DarkGray
#endregion

#region ---------------------------- Variables ------------------------------

$subId     = (Get-AzContext).Subscription.Id
$rgName    = 'rg-network-core'

$loc1      = 'southcentralus';  $loc1Short = 'scus'
$loc2      = 'northcentralus';  $loc2Short = 'ncus'

# ---- EXISTING firewall private IPs (fill these in) ----
# Azure Firewall takes the 4th address of AzureFirewallSubnet, which is the
# first host address Azure makes available. Override if yours differs.
$fwIp = @{
    $loc1Short = '10.10.0.4'      # SCUS hub Azure Firewall private IP
    $loc2Short = '10.20.0.4'      # NCUS hub Azure Firewall private IP
}

# ---- Hubs: set $CreateHubs = $false to reference hubs that already exist ----
$CreateHubs = $true
$hubName = @{
    $loc1Short = "vnet-hub-$loc1Short"
    $loc2Short = "vnet-hub-$loc2Short"
}
$hubRg   = @{                      # RG holding existing hubs, if different
    $loc1Short = $rgName
    $loc2Short = $rgName
}
# ---- Regional address plan ----
# Each region owns a single /16. Inside it:
#   x.x.0.0/20    hub (firewall, gateway, bastion, shared services)
#   x.x.16.0/20   fixed-address workload spokes, /22 each
#   x.x.128.0/17  IPAM root, /22 child pools
$regionCidr = @{
    $loc1Short = '10.10.0.0/16'
    $loc2Short = '10.20.0.0/16'
}

# Hub is the first /20 of the region
$hubCidr = @{
    $loc1Short = Get-CidrAtOffset -BaseCidr $regionCidr[$loc1Short] -Offset 0 -PrefixLength 20
    $loc2Short = Get-CidrAtOffset -BaseCidr $regionCidr[$loc2Short] -Offset 0 -PrefixLength 20
}

# Hub subnet layout, as host offsets from the hub base
$hubSubnetPlan = @(
    @{ Name = 'AzureFirewallSubnet';           Offset = 0;   Prefix = 26 }
    @{ Name = 'AzureFirewallManagementSubnet'; Offset = 64;  Prefix = 26 }
    @{ Name = 'GatewaySubnet';                 Offset = 128; Prefix = 27 }
    @{ Name = 'AzureBastionSubnet';            Offset = 192; Prefix = 26 }
    @{ Name = 'snet-sharedservices';           Offset = 256; Prefix = 24 }
)

# Spoke sizing: /22 VNets split into four /24 subnets. Set to 24 for small
# spokes and the subnets become /26 automatically.
$spokePrefixLength = 22

# Shared / infrastructure service ranges (where DCs, DNS, tooling, backup live)
# Shared services is a subnet of the hub, so derive it from the hub plan
$sharedSvcPlan = $hubSubnetPlan | Where-Object { $_.Name -eq 'snet-sharedservices' }
$sharedSvcCidr = @{
    $loc1Short = Get-CidrAtOffset -BaseCidr $hubCidr[$loc1Short] -Offset $sharedSvcPlan.Offset -PrefixLength $sharedSvcPlan.Prefix
    $loc2Short = Get-CidrAtOffset -BaseCidr $hubCidr[$loc2Short] -Offset $sharedSvcPlan.Offset -PrefixLength $sharedSvcPlan.Prefix
}
$sharedSvcAll = @($sharedSvcCidr.Values)


$commonTags = @{
    costCenter = 'network'
    owner      = 'netops'
}

# ---- Teardown ----
# $true  = delete the existing deployment (AVNM node included) before rebuilding
# $false = deploy only
$DeleteExistingConfig      = $false
$SkipDeleteConfirmation    = $false   # $true to skip the interactive prompt

# ---- Dynamic group membership ----
# Configurations attach to network GROUPS, not to VNets. A group populated by
# Azure Policy is empty until policy evaluates, so committing immediately makes
# every configuration look unlinked. Wait for membership first.
$SkipMembershipWait        = $false
$MembershipWaitMinutes     = 25
# If nothing at all has joined after this long, something is wrong that more
# waiting won't fix - stop polling, report, and carry on to the commits.
$MembershipEarlyExitMinutes = 6

# ---- Spoke-to-spoke behaviour ----
# $false = spokes peer to the hub only; spoke-to-spoke traffic is hairpinned
#          through the regional firewall by the routing configuration.
# $true  = AVNM also peers spokes directly to each other within a region.
#          Faster and cheaper, but those flows bypass the firewall: a peering
#          system route for a spoke /16 is more specific than the 10.0.0.0/8
#          UDR, so longest-prefix match sends the traffic direct.
$SpokeToSpokeDirect = $false

# ---- AVNM object names (hoisted so teardown can find them) ----
$avnmName     = 'avnm-core'
$meshCfgName  = 'cc-hubmesh'
$meshIaasProd = 'cc-mesh-iaas-prod'
$meshIaasNonP = 'cc-mesh-iaas-nonprod'
$meshInfra    = 'cc-mesh-infra'
$allMeshCfgs  = @($meshCfgName, $meshIaasProd, $meshIaasNonP, $meshInfra)
$nsgName      = @{
    $loc1Short = "nsg-infra-$loc1Short"
    $loc2Short = "nsg-infra-$loc2Short"
}
$rtName       = @{
    $loc1Short = "rt-spokes-$loc1Short"
    $loc2Short = "rt-spokes-$loc2Short"
}

# ---- IP address management (IPAM) ----
# $true  = spoke VNets and subnets draw non-overlapping CIDRs from IPAM pools.
#          The $Base values below then describe pool sizing rather than fixed
#          addresses, and the actual prefixes are assigned by Azure.
# $false = use the hardcoded $Base CIDRs exactly as before.
$UseIpamAllocation = $true

# An existing pool's address prefix is immutable. When the plan no longer
# matches what is deployed:
#   $true  = delete the mismatched pools (children first) and recreate them
#   $false = stop with an explanatory error and change nothing
$RecreateIpamPoolsOnMismatch = $true

# Root pool per region. Sized to cover every spoke tier in that region with
# room to grow; hub ranges are reserved as static CIDRs so IPAM never hands
# them out.
$ipamRootName   = @{
    $loc1Short = "ipam-root-$loc1Short"
    $loc2Short = "ipam-root-$loc2Short"
}
# Roots deliberately sit well clear of the fixed 10.10-10.24 ranges used by the
# hubs, shared services and the infra/PaaS spokes, so an IPAM allocation can
# never land on an address something else already depends on.
$ipamRootCidr   = @{
    $loc1Short = Get-CidrAtOffset -BaseCidr $regionCidr[$loc1Short] -Offset (128 * 256) -PrefixLength 17
    $loc2Short = Get-CidrAtOffset -BaseCidr $regionCidr[$loc2Short] -Offset (128 * 256) -PrefixLength 17
}

# Addresses requested per allocation. A /16 spoke is 65536; each /24 subnet 256.
$ipamVnetAddresses   = [int][math]::Pow(2, 32 - $spokePrefixLength)          # /22 -> 1024
$ipamSubnetAddresses = [int]($ipamVnetAddresses / 4)                        # four subnets per spoke

# ---- Prestaged route tables ----
# AVNM defaults to building its own route tables inside a network-manager-managed
# resource group, which is why nothing appears alongside your other resources.
# Prestaging here keeps the tables in $rgName under your naming and tags, and
# UseExisting mode makes AVNM append to them rather than create its own.
$PrestageRouteTables = $true
# $true  = write every firewall route into the prestaged table up front
# $false = prestage only the 0.0.0.0/0 safety net and let AVNM add the rest,
#          which is the point of having AVNM manage routing by tag
$PrestageAllRoutes   = $false
$routeCfgName = 'rc-spoke-egress'
$sacName      = 'sac-baseline'
$apiVersion   = '2024-05-01'
# routeTableUsageMode = UseExisting requires 2025-01-01 or later
$routingApi   = '2025-01-01'
$avnmBase     = "/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Network/networkManagers/$avnmName"

$ngNames      = @{
    $loc1Short = "ng-spokes-$loc1Short"
    $loc2Short = "ng-spokes-$loc2Short"
    nonprod    = 'ng-spokes-nonprod'
    hubs       = 'ng-hubs'
    iaasProd   = 'ng-iaas-prod'
    iaasNonP   = 'ng-iaas-nonprod'
    infra      = 'ng-infra-prod'
}
$policyNames  = @{
    $loc1Short = "avnm-ng-spokes-$loc1Short"
    $loc2Short = "avnm-ng-spokes-$loc2Short"
    nonprod    = 'avnm-ng-spokes-nonprod'
    iaasProd   = 'avnm-ng-iaas-prod'
    iaasNonP   = 'avnm-ng-iaas-nonprod'
    infra      = 'avnm-ng-infra-prod'
}

# ---- Spoke definitions: 4 per region ----
# Subnet prefixes are generated as <Base>.<n>.0/24
$subnetTemplate = @{
    iaas      = @('snet-web','snet-app','snet-data','snet-mgmt')
    paas      = @('snet-privatelink','snet-appsvc-integration','snet-functions','snet-data')
    infra     = @('snet-adds','snet-mgmt','snet-security','snet-backup')
    devops    = @('snet-build-agents','snet-artifacts','snet-privatelink','snet-mgmt')
    analytics = @('snet-ingest','snet-compute','snet-storage','snet-privatelink')
    finance   = @('snet-app','snet-data','snet-privatelink','snet-mgmt')
}

# Ipam = $true  -> address space allocated from an IPAM pool
# Ipam = $false -> fixed $Base CIDR, unchanged from the original plan.
# Hubs, shared services and the infra/PaaS spokes stay fixed deliberately:
# they hold DCs, DNS, firewalls and private endpoints that other systems and
# on-premises routing reference by address, so they should not float.
# Fixed-address spokes occupy the second /20 of the region, /22 apart.
# IPAM spokes have no fixed CIDR - Azure assigns from their pool.
$fixedSpokeSlot = @{ paas = 0; infra = 1 }   # slot index within x.x.16.0/20

function Get-FixedSpokeCidr {
    param([string]$Region, [string]$Workload)
    $blockBase = Get-CidrAtOffset -BaseCidr $regionCidr[$Region] -Offset (16 * 256) -PrefixLength 20
    $step      = [uint32][math]::Pow(2, 32 - $spokePrefixLength)
    return Get-CidrAtOffset -BaseCidr $blockBase -Offset ($fixedSpokeSlot[$Workload] * $step) `
                            -PrefixLength $spokePrefixLength
}

$spokeDefs = @(
    # ---- South Central US ----
    @{ Loc=$loc1; Rg=$loc1Short; Workload='paas';      Env='prod';    Ipam=$false }
    @{ Loc=$loc1; Rg=$loc1Short; Workload='infra';     Env='prod';    Ipam=$false }
    @{ Loc=$loc1; Rg=$loc1Short; Workload='iaas';      Env='prod';    Ipam=$true  }
    @{ Loc=$loc1; Rg=$loc1Short; Workload='iaas';      Env='nonprod'; Ipam=$true  }
    @{ Loc=$loc1; Rg=$loc1Short; Workload='devops';    Env='prod';    Ipam=$true  }
    @{ Loc=$loc1; Rg=$loc1Short; Workload='analytics'; Env='prod';    Ipam=$true  }
    @{ Loc=$loc1; Rg=$loc1Short; Workload='finance';   Env='prod';    Ipam=$true  }
    # ---- North Central US ----
    @{ Loc=$loc2; Rg=$loc2Short; Workload='paas';      Env='prod';    Ipam=$false }
    @{ Loc=$loc2; Rg=$loc2Short; Workload='infra';     Env='prod';    Ipam=$false }
    @{ Loc=$loc2; Rg=$loc2Short; Workload='iaas';      Env='prod';    Ipam=$true  }
    @{ Loc=$loc2; Rg=$loc2Short; Workload='iaas';      Env='nonprod'; Ipam=$true  }
    @{ Loc=$loc2; Rg=$loc2Short; Workload='devops';    Env='prod';    Ipam=$true  }
    @{ Loc=$loc2; Rg=$loc2Short; Workload='analytics'; Env='prod';    Ipam=$true  }
    @{ Loc=$loc2; Rg=$loc2Short; Workload='finance';   Env='prod';    Ipam=$true  }
)

# One child pool per IPAM-managed spoke, /22 each, laid out in order within the
# region's IPAM root. Built after $spokeDefs so the two can't drift apart.
$ipamChildCidr = @{}
foreach ($r in @($loc1Short, $loc2Short)) {
    $step = [uint32][math]::Pow(2, 32 - $spokePrefixLength)
    $i    = 0
    foreach ($sp in ($spokeDefs | Where-Object { $_.Rg -eq $r -and $_.Ipam })) {
        $ipamChildCidr["$r-$($sp.Workload)-$($sp.Env)"] =
            Get-CidrAtOffset -BaseCidr $ipamRootCidr[$r] -Offset ($i * $step) -PrefixLength $spokePrefixLength
        $i++
    }
}

# Resolves a spoke's address space: from the IPAM pool plan when IPAM is on,
# otherwise from the fixed $Base value.
function Test-SpokeUsesIpam {
    param($Spoke)
    return ($UseIpamAllocation -and $Spoke.Ipam)
}

function Get-SpokeCidr {
    param($Spoke)
    if (Test-SpokeUsesIpam $Spoke) { $ipamChildCidr["$($Spoke.Rg)-$($Spoke.Workload)-$($Spoke.Env)"] }
    else                           { Get-FixedSpokeCidr -Region $Spoke.Rg -Workload $Spoke.Workload }
}

# Prod address space (used by the nonprod isolation rule collection)
$prodCidrs = @($spokeDefs | Where-Object { $_.Env -eq 'prod' } | ForEach-Object { Get-SpokeCidr $_ }) `
             + @($hubCidr.Values)

# ---- Which destinations are firewall-inspected, and which go direct ----
# "Route directly" cannot be expressed as a UDR next hop - Azure picks routes by
# longest prefix match, so a destination goes direct precisely when no route
# table entry covers it and a connectivity path (peering / connected group)
# exists. IaaS spoke ranges are therefore deliberately LEFT OUT of the inspected
# list below, and reachability comes from the IaaS mesh configurations instead.
# With IPAM on, Azure assigns the actual prefixes, so these lists must come
# from the pool plan rather than $Base - otherwise the routing rules and the
# nonprod-to-prod deny would reference addresses nothing actually holds.
# IaaS spokes are excluded from inspection so their mesh path stays direct.
# DevOps, analytics and finance are business workloads, so their traffic is
# pulled to the firewall like PaaS and infra.
$iaasCidrs      = @($spokeDefs | Where-Object { $_.Workload -eq 'iaas' } | ForEach-Object { Get-SpokeCidr $_ })
$nonIaasCidrs   = @($spokeDefs | Where-Object { $_.Workload -ne 'iaas' } | ForEach-Object { Get-SpokeCidr $_ })

# Everything here is forced to the regional firewall. 0.0.0.0/0 is added
# separately, so anything not listed and not directly connected still egresses
# via the firewall by default.
$inspectedRanges = @($hubCidr.Values) + $nonIaasCidrs + @('172.16.0.0/12','192.168.0.0/16')

#endregion

#region --------------------------- Teardown --------------------------------
# Deletes the previous deployment in dependency order. AVNM will not release
# configurations that are still deployed, so every commit must be removed
# first, and the membership policies must go before their network groups.
if ($DeleteExistingConfig) {

    Write-Host ''
    Write-Host '!! TEARDOWN REQUESTED' -ForegroundColor Red
    Write-Host "   Subscription : $subId"
    Write-Host "   Resource grp : $rgName"
    Write-Host "   This deletes the AVNM node '$avnmName', its configurations," -ForegroundColor Red
    Write-Host '   the membership policies, all 8 spoke VNets' -ForegroundColor Red
    if ($CreateHubs) { Write-Host '   AND both hub VNets.' -ForegroundColor Red }
    else             { Write-Host '   (existing hubs are left in place).' -ForegroundColor Red }

    if (-not $SkipDeleteConfirmation) {
        $answer = Read-Host "   Type DELETE to continue"
        if ($answer -cne 'DELETE') { throw 'Teardown not confirmed - aborting.' }
    }

    $nm = Get-AzNetworkManager -Name $avnmName -ResourceGroupName $rgName -ErrorAction SilentlyContinue

    if ($nm) {
        # 1. Remove every deployment (empty configuration list per type/region)
        Write-Host '>> Uncommitting AVNM deployments' -ForegroundColor Cyan
        foreach ($location in @($loc1, $loc2)) {
            foreach ($ct in @('Connectivity','Routing','SecurityAdmin')) {
                Invoke-Safely "commit $ct @ $location" {
                    Deploy-AzNetworkManagerCommit -ResourceGroupName $rgName -Name $avnmName `
                        -TargetLocation @($location) -ConfigurationId @() -CommitType $ct | Out-Null
                }
            }
        }
        Write-Host '   Waiting 60s for deployments to drain...' -ForegroundColor Yellow
        Start-Sleep -Seconds 60

        # 2. Configurations
        Write-Host '>> Removing AVNM configurations' -ForegroundColor Cyan
        Invoke-Safely "routing configuration $routeCfgName" {
            $r = Invoke-AzRestMethod -Method DELETE `
                -Path "$avnmBase/routingConfigurations/$routeCfgName`?api-version=$apiVersion&force=true"
            if ($r.StatusCode -ge 400) { throw $r.Content }
        }
        Invoke-Safely "security admin configuration $sacName" {
            Remove-AzNetworkManagerSecurityAdminConfiguration -Name $sacName `
                -ResourceGroupName $rgName -NetworkManagerName $avnmName -Force
        }
        foreach ($r in @($loc1Short, $loc2Short)) {
            Invoke-Safely "connectivity configuration cc-hubspoke-$r" {
                Remove-AzNetworkManagerConnectivityConfiguration -Name "cc-hubspoke-$r" `
                    -ResourceGroupName $rgName -NetworkManagerName $avnmName -Force
            }
        }
        foreach ($m in $allMeshCfgs) {
            Invoke-Safely "connectivity configuration $m" {
                Remove-AzNetworkManagerConnectivityConfiguration -Name $m `
                    -ResourceGroupName $rgName -NetworkManagerName $avnmName -Force
            }
        }

        # 3. Membership policies (assignment first, then definition)
        Write-Host '>> Removing dynamic membership policies' -ForegroundColor Cyan
        foreach ($p in $policyNames.Values) {
            Invoke-Safely "policy assignment $p" {
                Remove-AzPolicyAssignment -Name $p -Scope "/subscriptions/$subId"
            }
            Invoke-Safely "policy definition $p" {
                Remove-AzPolicyDefinition -Name $p -Force
            }
        }

        # 4. Network groups
        Write-Host '>> Removing network groups' -ForegroundColor Cyan
        foreach ($g in $ngNames.Values) {
            Invoke-Safely "network group $g" {
                Remove-AzNetworkManagerGroup -Name $g -ResourceGroupName $rgName `
                    -NetworkManagerName $avnmName -Force
            }
        }

        # 5. The network manager itself
        Write-Host '>> Removing network manager' -ForegroundColor Cyan
        Invoke-Safely "network manager $avnmName" {
            Remove-AzNetworkManager -Name $avnmName -ResourceGroupName $rgName -Force
        }
    }
    else {
        Write-Host "   No network manager named '$avnmName' found - skipping AVNM teardown."
    }

    # 6. Spoke VNets
    Write-Host '>> Removing spoke VNets' -ForegroundColor Cyan
    foreach ($s in $spokeDefs) {
        $vnetName = "vnet-spoke-$($s.Workload)-$($s.Env)-$($s.Rg)"
        Invoke-Safely "spoke $vnetName" {
            Remove-AzVirtualNetwork -Name $vnetName -ResourceGroupName $rgName -Force
        }
    }

    # 7. Hubs - only the ones this script owns
    if ($CreateHubs) {
        Write-Host '>> Removing hub VNets' -ForegroundColor Cyan
        foreach ($r in @($loc1Short, $loc2Short)) {
            Invoke-Safely "hub $($hubName[$r])" {
                Remove-AzVirtualNetwork -Name $hubName[$r] -ResourceGroupName $rgName -Force
            }
        }
    }
    else {
        # Existing hubs stay. AVNM removes its own peerings when the mesh
        # configuration is uncommitted; this only clears manual peerings left
        # behind by script versions before v5.
        Write-Host '>> Clearing legacy manual hub peerings (hubs retained)' -ForegroundColor Cyan
        Invoke-Safely "peering peer-$loc1Short-to-$loc2Short" {
            Remove-AzVirtualNetworkPeering -Name "peer-$loc1Short-to-$loc2Short" `
                -VirtualNetworkName $hubName[$loc1Short] -ResourceGroupName $hubRg[$loc1Short] -Force
        }
        Invoke-Safely "peering peer-$loc2Short-to-$loc1Short" {
            Remove-AzVirtualNetworkPeering -Name "peer-$loc2Short-to-$loc1Short" `
                -VirtualNetworkName $hubName[$loc2Short] -ResourceGroupName $hubRg[$loc2Short] -Force
        }
    }

    # Route tables and NSGs last - neither deletes while a subnet references it.
    # Note AVNM never deletes a customer-created route table, even if it has
    # appended routes to it, so this is the only thing that removes them.
    # IPAM pools release their CIDRs when the allocated resources are deleted,
    # so pools must come down after the VNets. Children before parents.
    if ($UseIpamAllocation) {
        Write-Host '>> Removing IPAM pools' -ForegroundColor Cyan
        foreach ($r in @($loc1Short, $loc2Short)) {
            foreach ($sp in ($spokeDefs | Where-Object { $_.Rg -eq $r -and (Test-SpokeUsesIpam $_) })) {
                $childName = "ipam-$($sp.Workload)-$($sp.Env)-$r"
                Invoke-Safely "IPAM child pool $childName" {
                    Remove-AzNetworkManagerIpamPool -Name $childName `
                        -ResourceGroupName $rgName -NetworkManagerName $avnmName -Force
                }
            }
            Invoke-Safely "IPAM root pool $($ipamRootName[$r])" {
                Remove-AzNetworkManagerIpamPool -Name $ipamRootName[$r] `
                    -ResourceGroupName $rgName -NetworkManagerName $avnmName -Force
            }
        }
    }

    Write-Host '>> Removing prestaged route tables' -ForegroundColor Cyan
    foreach ($r in @($loc1Short, $loc2Short)) {
        Invoke-Safely "route table $($rtName[$r])" {
            Remove-AzRouteTable -Name $rtName[$r] -ResourceGroupName $rgName -Force
        }
    }

    Write-Host '>> Removing infrastructure NSGs' -ForegroundColor Cyan
    foreach ($r in @($loc1Short, $loc2Short)) {
        Invoke-Safely "NSG $($nsgName[$r])" {
            Remove-AzNetworkSecurityGroup -Name $nsgName[$r] -ResourceGroupName $rgName -Force
        }
    }

    Write-Host '>> Teardown complete' -ForegroundColor Green
    Write-Host ''
}
#endregion

#region ------------------- Validate the IPAM address plan ------------------
# Azure rejects a child pool that is not contained by its parent, and a pool
# shared by two full-size allocations silently runs out. Both are arithmetic,
# so check them here rather than discovering it as a BadRequest mid-deployment.
if ($UseIpamAllocation) {
    Write-Host '>> Validating IPAM address plan' -ForegroundColor Cyan

    # Convert-CidrToRange comes from the Helpers region - do not redefine it
    # here; a local copy would shadow it and drop the Prefix property.

    $planErrors = @()

    foreach ($r in @($loc1Short, $loc2Short)) {
        $root = Convert-CidrToRange $ipamRootCidr[$r]
        $used = @()

        # Only IPAM-managed spokes draw from the root
        $entries = @{}
        foreach ($sp in ($spokeDefs | Where-Object { $_.Rg -eq $r -and (Test-SpokeUsesIpam $_) })) {
            $key = "$r-$($sp.Workload)-$($sp.Env)"
            if (-not $ipamChildCidr.ContainsKey($key)) {
                $planErrors += "no pool CIDR defined for $key"
                continue
            }
            $entries[$key] = $ipamChildCidr[$key]
        }

        foreach ($k in $entries.Keys) {
            $c = Convert-CidrToRange $entries[$k]

            if ($c.Start -lt $root.Start -or $c.End -gt $root.End) {
                $planErrors += "$k ($($entries[$k])) is outside root $($ipamRootCidr[$r])"
            }
            foreach ($u in $used) {
                if ($c.Start -le $u.Range.End -and $c.End -ge $u.Range.Start) {
                    $planErrors += "$k ($($entries[$k])) overlaps $($u.Name) ($($u.Cidr))"
                }
            }
            # each spoke draws $ipamVnetAddresses from its own pool
            if ($c.Size -lt $ipamVnetAddresses) {
                $planErrors += "$k ($($entries[$k])) holds $($c.Size) addresses but the spoke requests $ipamVnetAddresses"
            }
            $used += [pscustomobject]@{ Name = $k; Cidr = $entries[$k]; Range = $c }
        }
        # The fixed estate must stay clear of the IPAM roots
        $rootRange = $root
        $fixedHere = @{ "hub-$r" = $hubCidr[$r] }
        foreach ($sp in ($spokeDefs | Where-Object { $_.Rg -eq $r -and -not (Test-SpokeUsesIpam $_) })) {
            $fixedHere["$($sp.Workload)-$($sp.Env)-$r"] = Get-SpokeCidr $sp
        }
        foreach ($k in $fixedHere.Keys) {
            $f = Convert-CidrToRange $fixedHere[$k]
            if ($f.Start -le $rootRange.End -and $f.End -ge $rootRange.Start) {
                $planErrors += "fixed range $k ($($fixedHere[$k])) overlaps IPAM root $($ipamRootCidr[$r])"
            }
        }

        Write-Host "   $r root $($ipamRootCidr[$r]): $($entries.Count) pooled, $($fixedHere.Count) fixed"
    }

    if ($planErrors) {
        Write-Host 'IPAM address plan is invalid:' -ForegroundColor Red
        $planErrors | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
        throw 'Fix $ipamRootCidr / $ipamChildCidr before deploying.'
    }
    Write-Host '   Address plan OK.' -ForegroundColor Green
}
#endregion

#region ------------------------- Resource Group ----------------------------
Write-Host ">> Resource group $rgName" -ForegroundColor Cyan
New-AzResourceGroup -Name $rgName -Location $loc1 -Tag $commonTags -Force | Out-Null
#endregion

#region ------------------- Azure Virtual Network Manager -------------------
# Created before any VNet, because IPAM pools hang off the network manager and
# the VNets below allocate their address space from those pools.
Write-Host '>> Creating Azure Virtual Network Manager' -ForegroundColor Cyan

$scope = New-AzNetworkManagerScope -Subscription @("/subscriptions/$subId")
$avnm  = New-AzNetworkManager -Name $avnmName -ResourceGroupName $rgName -Location $loc1 `
    -NetworkManagerScope $scope `
    -NetworkManagerScopeAccess @('Connectivity','SecurityAdmin','Routing') `
    -Tag $commonTags -Force
#endregion

#region --------------------------- IPAM pools ------------------------------
# Root pool per region, child pool per workload tier. A VNet may only allocate
# from a pool in its own region, hence one hierarchy per region rather than a
# single global root.
$ipamPool  = @{}
$ipamChild = @{}

# Pool state is read over REST rather than through the PowerShell object model:
# the cmdlet's property names have shifted between Az.Network versions, and a
# property that reads as empty makes every pool look mismatched. The service's
# own JSON is the authoritative view.
function Get-AllIpamPools {
    $r = Invoke-AzRestMethod -Method GET -Path "$avnmBase/ipamPools`?api-version=$apiVersion"
    if ($r.StatusCode -ge 400) { throw "Listing IPAM pools failed ($($r.StatusCode)): $($r.Content)" }
    $v = ($r.Content | ConvertFrom-Json).value
    return @($v | ForEach-Object {
        [pscustomobject]@{
            Name     = $_.name
            Prefixes = @($_.properties.addressPrefixes)
            Parent   = $_.properties.parentPoolName
        }
    })
}

function Remove-IpamPoolByName {
    param([string]$Name)
    $r = Invoke-AzRestMethod -Method DELETE -Path "$avnmBase/ipamPools/$Name`?api-version=$apiVersion"
    if ($r.StatusCode -ge 400) { throw "$($r.StatusCode): $($r.Content)" }
}

if ($UseIpamAllocation) {
    Write-Host '>> Reconciling IPAM pools' -ForegroundColor Cyan

    # What the plan wants: pool name -> address prefix
    $desired = @{}
    foreach ($r in @($loc1Short, $loc2Short)) {
        $desired[$ipamRootName[$r]] = $ipamRootCidr[$r]
        foreach ($sp in ($spokeDefs | Where-Object { $_.Rg -eq $r -and (Test-SpokeUsesIpam $_) })) {
            $desired["ipam-$($sp.Workload)-$($sp.Env)-$r"] = $ipamChildCidr["$r-$($sp.Workload)-$($sp.Env)"]
        }
    }

    $existing = Get-AllIpamPools
    if ($existing.Count) {
        Write-Host "   $($existing.Count) pool(s) currently deployed:"
        $existing | ForEach-Object {
            $want = if ($desired.ContainsKey($_.Name)) { $desired[$_.Name] } else { '(not in plan)' }
            $have = if ($_.Prefixes) { $_.Prefixes -join ', ' } else { '(none)' }
            $verdict = if ($desired.ContainsKey($_.Name) -and $have -eq $want) { 'matches' } else { 'differs' }
            Write-Host ("     {0,-30} has {1,-18} plan {2,-18} {3}" -f $_.Name, $have, $want, $verdict)
        }
    }

    # Anything that is not an exact match must go, including pools left behind
    # by earlier script versions under names this version never generates.
    $toRemove = @($existing | Where-Object {
        -not $desired.ContainsKey($_.Name) -or
        ($_.Prefixes -join ',') -ne $desired[$_.Name]
    })

    if ($toRemove.Count) {
        if (-not $RecreateIpamPoolsOnMismatch) {
            throw ("$($toRemove.Count) IPAM pool(s) differ from the plan and pool prefixes are immutable. " +
                   "Set `$RecreateIpamPoolsOnMismatch = `$true or remove them manually.")
        }

        Write-Host "   Removing $($toRemove.Count) pool(s) that do not match the plan" -ForegroundColor Yellow

        # A root cannot be deleted while it has children, and the parent chain
        # can be several layers deep, so delete leaves repeatedly until either
        # nothing is left or a pass makes no progress.
        $remaining = $toRemove
        for ($pass = 1; $pass -le 8 -and $remaining.Count; $pass++) {
            $live     = Get-AllIpamPools
            $parents  = @($live | Where-Object { $_.Parent } | ForEach-Object { $_.Parent } | Select-Object -Unique)
            $leaves   = @($remaining | Where-Object { $_.Name -notin $parents })
            $progress = $false

            # If nothing looks like a leaf, try everything - the parent field
            # may be absent in this API version.
            if (-not $leaves.Count) { $leaves = $remaining }

            foreach ($pool in $leaves) {
                try {
                    Remove-IpamPoolByName -Name $pool.Name
                    Write-Host "     deleted $($pool.Name)"
                    $progress = $true
                }
                catch {
                    Write-Host "     pass ${pass}: $($pool.Name) not yet deletable" -ForegroundColor DarkYellow
                }
            }

            Start-Sleep -Seconds 5
            $stillThere = @(Get-AllIpamPools | ForEach-Object { $_.Name })
            $remaining  = @($remaining | Where-Object { $_.Name -in $stillThere })

            if (-not $progress -and $remaining.Count) {
                Write-Host '   Cannot delete the remaining pools:' -ForegroundColor Red
                $remaining | ForEach-Object { Write-Host "     $($_.Name)" -ForegroundColor Red }
                Write-Host '   Usually a VNet is still allocated from one of them.' -ForegroundColor Red
                Write-Host '   Run Diagnose-IpamPools.ps1 to see the allocations.' -ForegroundColor Red
                throw 'IPAM pool cleanup could not complete.'
            }
        }
    }

    # ---- Create what is missing; reuse exact matches ----
    $current = @{}
    Get-AllIpamPools | ForEach-Object { $current[$_.Name] = $_ }

    foreach ($r in @($loc1Short, $loc2Short)) {
        $location = if ($r -eq $loc1Short) { $loc1 } else { $loc2 }

        if ($current.ContainsKey($ipamRootName[$r])) {
            $ipamPool[$r] = Get-AzNetworkManagerIpamPool -Name $ipamRootName[$r] `
                -ResourceGroupName $rgName -NetworkManagerName $avnm.Name
            Write-Host "   reused  $($ipamRootName[$r])  $($ipamRootCidr[$r])"
        }
        else {
            $ipamPool[$r] = New-AzNetworkManagerIpamPool -Name $ipamRootName[$r] `
                -ResourceGroupName $rgName -NetworkManagerName $avnm.Name -Location $location `
                -AddressPrefix @($ipamRootCidr[$r]) `
                -DisplayName "Root pool - $r" `
                -Description "Pooled spoke address space for $r" -Force
            Write-Host "   created $($ipamRootName[$r])  $($ipamRootCidr[$r])"
        }

        foreach ($sp in ($spokeDefs | Where-Object { $_.Rg -eq $r -and (Test-SpokeUsesIpam $_) })) {
            $key       = "$r-$($sp.Workload)-$($sp.Env)"
            $childName = "ipam-$($sp.Workload)-$($sp.Env)-$r"

            if ($current.ContainsKey($childName)) {
                $ipamChild[$key] = Get-AzNetworkManagerIpamPool -Name $childName `
                    -ResourceGroupName $rgName -NetworkManagerName $avnm.Name
                Write-Host "   reused  $childName  $($ipamChildCidr[$key])"
            }
            else {
                $ipamChild[$key] = New-AzNetworkManagerIpamPool -Name $childName `
                    -ResourceGroupName $rgName -NetworkManagerName $avnm.Name -Location $location `
                    -AddressPrefix @($ipamChildCidr[$key]) `
                    -ParentPoolName $ipamRootName[$r] `
                    -DisplayName "$($sp.Workload) $($sp.Env) - $r" `
                    -Description "Allocation pool for the $($sp.Workload)/$($sp.Env) spoke in $r" -Force
                Write-Host "   created $childName  $($ipamChildCidr[$key])"
            }
        }
    }
}
else {
    Write-Host '>> IPAM allocation disabled - using the fixed address plan' -ForegroundColor Yellow
}
#endregion

#region ----------------------------- Hub VNets -----------------------------
$hub = @{}

foreach ($r in @($loc1Short, $loc2Short)) {
    $location = if ($r -eq $loc1Short) { $loc1 } else { $loc2 }

    if ($CreateHubs) {
        Write-Host ">> Creating hub VNet $($hubName[$r])" -ForegroundColor Cyan
        $hubSubnets = @(
            foreach ($sn in $hubSubnetPlan) {
                $prefix = Get-CidrAtOffset -BaseCidr $hubCidr[$r] -Offset $sn.Offset -PrefixLength $sn.Prefix
                Write-Host "     $($sn.Name)  $prefix"
                New-AzVirtualNetworkSubnetConfig -Name $sn.Name -AddressPrefix $prefix
            }
        )
        $hub[$r] = New-AzVirtualNetwork -Name $hubName[$r] -ResourceGroupName $rgName `
            -Location $location -AddressPrefix $hubCidr[$r] -Subnet $hubSubnets `
            -Tag ($commonTags + @{ networkRole = 'hub'; region = $r; environment = 'shared' })
    }
    else {
        Write-Host ">> Using existing hub VNet $($hubName[$r])" -ForegroundColor Cyan
        $hub[$r] = Get-AzVirtualNetwork -Name $hubName[$r] -ResourceGroupName $hubRg[$r]
    }
}
#endregion

#region ----------------------- Hub-to-hub peering --------------------------
# Hub peering is created by the AVNM Mesh connectivity configuration further
# down (see "Connectivity"), not by Add-AzVirtualNetworkPeering. Any manual
# peering left over from an earlier run is removed by -DeleteExistingPeering
# when that configuration is committed.
#endregion

#region ---------------------------- Spoke VNets ----------------------------
Write-Host ">> Creating spoke VNets" -ForegroundColor Cyan

foreach ($s in $spokeDefs) {
    $vnetName = "vnet-spoke-$($s.Workload)-$($s.Env)-$($s.Rg)"
    $names    = $subnetTemplate[$s.Workload]
    $subnets  = @()
    $useIpam  = Test-SpokeUsesIpam $s

    # With IPAM on, both the VNet and its subnets reference a pool and Azure
    # picks non-overlapping prefixes. The allocation object is a plain
    # PSCustomObject of the pool ID plus how many addresses to draw.
    $vnetAlloc = $null
    if ($useIpam) {
        $poolId    = $ipamChild["$($s.Rg)-$($s.Workload)-$($s.Env)"].Id
        $vnetAlloc = [PSCustomObject]@{ Id = $poolId; NumberOfIpAddresses = $ipamVnetAddresses }
        $snAlloc   = [PSCustomObject]@{ Id = $poolId; NumberOfIpAddresses = $ipamSubnetAddresses }
    }

    # Subnet prefixes are carved from the spoke's own CIDR, so a /22 spoke gets
    # four /24s and a /24 spoke gets four /26s with no other changes.
    $snPrefixes = if ($useIpam) { @($null) * $names.Count }
                  else          { Get-CidrSubnets -Cidr (Get-SpokeCidr $s) -Count $names.Count }

    for ($i = 0; $i -lt $names.Count; $i++) {
        $prefix     = $snPrefixes[$i]
        $subnetName = $names[$i]

        $snParams = @{ Name = $subnetName }
        if ($useIpam) { $snParams['IpamPoolPrefixAllocation'] = @($snAlloc) }
        else          { $snParams['AddressPrefix']            = $prefix }

        if ($subnetName -eq 'snet-appsvc-integration') {
            $snParams['Delegation'] = New-AzDelegation -Name 'delegation-appservice' `
                -ServiceName 'Microsoft.Web/serverFarms'
        }
        $subnets += New-AzVirtualNetworkSubnetConfig @snParams
    }

    $vnetParams = @{
        Name              = $vnetName
        ResourceGroupName = $rgName
        Location          = $s.Loc
        Subnet            = $subnets
        Force             = $true
        Tag               = ($commonTags + @{
            networkRole  = 'spoke'
            region       = $s.Rg
            workloadType = $s.Workload
            environment  = $s.Env
        })
    }
    if ($useIpam) { $vnetParams['IpamPoolPrefixAllocation'] = @($vnetAlloc) }
    else          { $vnetParams['AddressPrefix']            = @(Get-SpokeCidr $s) }

    $created = New-AzVirtualNetwork @vnetParams

    $actual = if ($created.AddressSpace.AddressPrefixes) { $created.AddressSpace.AddressPrefixes -join ', ' }
              else { 'pending IPAM allocation' }
    $src = if ($useIpam) { 'IPAM' } else { 'fixed' }
    Write-Host "   $vnetName  $actual  ($src)  [$($names -join ', ')]"
}
#endregion

#region ------------------- AVNM network groups -----------------------------
# ---- Network groups (membership is tag-driven via Azure Policy below) ----
$ng = @{}
$ng[$loc1Short] = New-AzNetworkManagerGroup -Name $ngNames[$loc1Short] -ResourceGroupName $rgName `
    -NetworkManagerName $avnm.Name -Description 'SCUS spokes (dynamic)' -Force
$ng[$loc2Short] = New-AzNetworkManagerGroup -Name $ngNames[$loc2Short] -ResourceGroupName $rgName `
    -NetworkManagerName $avnm.Name -Description 'NCUS spokes (dynamic)' -Force
$ngNonProd = New-AzNetworkManagerGroup -Name $ngNames['nonprod'] -ResourceGroupName $rgName `
    -NetworkManagerName $avnm.Name -Description 'All non-production spokes (dynamic)' -Force

# ---- Workload groups behind the additional mesh scenarios ----
$ngIaasProd = New-AzNetworkManagerGroup -Name $ngNames['iaasProd'] -ResourceGroupName $rgName `
    -NetworkManagerName $avnm.Name -Description 'IaaS production spokes, both regions (dynamic)' -Force
$ngIaasNonP = New-AzNetworkManagerGroup -Name $ngNames['iaasNonP'] -ResourceGroupName $rgName `
    -NetworkManagerName $avnm.Name -Description 'IaaS non-production spokes, both regions (dynamic)' -Force
$ngInfra    = New-AzNetworkManagerGroup -Name $ngNames['infra'] -ResourceGroupName $rgName `
    -NetworkManagerName $avnm.Name -Description 'Infrastructure spokes, both regions (dynamic)' -Force

# ---- Hub group: static membership, since there are exactly two hubs ----
$ngHubs = New-AzNetworkManagerGroup -Name $ngNames['hubs'] -ResourceGroupName $rgName `
    -NetworkManagerName $avnm.Name -Description 'Regional hubs (static)' -Force

foreach ($r in @($loc1Short, $loc2Short)) {
    New-AzNetworkManagerStaticMember -Name "sm-hub-$r" -ResourceGroupName $rgName `
        -NetworkManagerName $avnm.Name -NetworkGroupName $ngHubs.Name `
        -ResourceId $hub[$r].Id -Force | Out-Null
}
#endregion

#region ---------------- Dynamic membership via Azure Policy ----------------
# Dynamic AVNM groups are populated by policies in "Microsoft.Network.Data"
# mode using the "addToNetworkGroup" effect.
Write-Host ">> Creating tag-based dynamic membership policies" -ForegroundColor Cyan

function New-AvnmDynamicGroupPolicy {
    param(
        [string]$PolicyName,
        [string]$DisplayName,
        [string]$NetworkGroupId,
        [hashtable]$TagMatch      # e.g. @{ region = 'scus'; workloadType = 'iaas' }
    )

    # Every group is scoped to spokes, plus whatever tag conditions are passed in
    $conditions = @('      { "field": "type", "equals": "Microsoft.Network/virtualNetworks" }',
                    '      { "field": "tags[''networkRole'']", "equals": "spoke" }')
    foreach ($k in $TagMatch.Keys) {
        $conditions += "      { ""field"": ""tags['$k']"", ""equals"": ""$($TagMatch[$k])"" }"
    }
    $conditionBlock = $conditions -join ",`n"

    $rule = @"
{
  "if": {
    "allOf": [
$conditionBlock
    ]
  },
  "then": {
    "effect": "addToNetworkGroup",
    "details": { "networkGroupId": "$NetworkGroupId" }
  }
}
"@

    $def = New-AzPolicyDefinition -Name $PolicyName -DisplayName $DisplayName `
        -Mode 'Microsoft.Network.Data' -Policy $rule
    New-AzPolicyAssignment -Name $PolicyName -DisplayName $DisplayName `
        -Scope "/subscriptions/$subId" -PolicyDefinition $def | Out-Null
}

New-AvnmDynamicGroupPolicy -PolicyName $policyNames[$loc1Short] `
    -DisplayName 'AVNM group - SCUS spokes' -NetworkGroupId $ng[$loc1Short].Id `
    -TagMatch @{ region = $loc1Short }

New-AvnmDynamicGroupPolicy -PolicyName $policyNames[$loc2Short] `
    -DisplayName 'AVNM group - NCUS spokes' -NetworkGroupId $ng[$loc2Short].Id `
    -TagMatch @{ region = $loc2Short }

New-AvnmDynamicGroupPolicy -PolicyName $policyNames['nonprod'] `
    -DisplayName 'AVNM group - non-production spokes' -NetworkGroupId $ngNonProd.Id `
    -TagMatch @{ environment = 'nonprod' }

# Groups behind the new mesh scenarios. These span both regions on purpose -
# the meshes are global.
New-AvnmDynamicGroupPolicy -PolicyName $policyNames['iaasProd'] `
    -DisplayName 'AVNM group - IaaS production spokes' -NetworkGroupId $ngIaasProd.Id `
    -TagMatch @{ workloadType = 'iaas'; environment = 'prod' }

New-AvnmDynamicGroupPolicy -PolicyName $policyNames['iaasNonP'] `
    -DisplayName 'AVNM group - IaaS non-production spokes' -NetworkGroupId $ngIaasNonP.Id `
    -TagMatch @{ workloadType = 'iaas'; environment = 'nonprod' }

New-AvnmDynamicGroupPolicy -PolicyName $policyNames['infra'] `
    -DisplayName 'AVNM group - infrastructure spokes' -NetworkGroupId $ngInfra.Id `
    -TagMatch @{ workloadType = 'infra' }

Write-Host '   Policy evaluation typically takes 15-30 min before groups populate.' -ForegroundColor Yellow
#endregion

#region ---------------------- Connectivity (peering) -----------------------
# All peering in this design is created and maintained by AVNM:
#   * spoke -> hub   : one HubAndSpoke configuration per region
#   * spoke <-> spoke: same configuration, when $SpokeToSpokeDirect is on
#   * hub  <-> hub   : one global Mesh configuration over the static hub group
# AVNM re-evaluates membership continuously, so a new spoke carrying the right
# tags is peered automatically - no peering objects are managed by this script.
Write-Host '>> Creating connectivity configurations' -ForegroundColor Cyan

$groupConnectivity = if ($SpokeToSpokeDirect) { 'DirectlyConnected' } else { 'None' }
Write-Host "   Spoke group connectivity: $groupConnectivity"

$conn = @{}
foreach ($r in @($loc1Short, $loc2Short)) {
    $hubItem = New-AzNetworkManagerHub -ResourceId $hub[$r].Id -ResourceType 'Microsoft.Network/virtualNetworks'

    # -UseHubGateway and -IsGlobal are switches: omit them to leave them off.
    # (Add -UseHubGateway if spokes should use an ExpressRoute/VPN gateway in the hub.)
    $grpItem = New-AzNetworkManagerConnectivityGroupItem -NetworkGroupId $ng[$r].Id `
        -GroupConnectivity $groupConnectivity

    $conn[$r] = New-AzNetworkManagerConnectivityConfiguration -Name "cc-hubspoke-$r" `
        -ResourceGroupName $rgName -NetworkManagerName $avnm.Name `
        -ConnectivityTopology 'HubAndSpoke' -Hub $hubItem -AppliesToGroup @($grpItem) `
        -DeleteExistingPeering -Force
}

# ---- Hub-to-hub: global mesh over the static hub group ----
# -IsGlobal is required on both the group item and the configuration for a mesh
# that crosses regions, and the API only accepts a global group item when its
# group connectivity is DirectlyConnected - which is what a mesh wants anyway.
$hubGrpItem = New-AzNetworkManagerConnectivityGroupItem -NetworkGroupId $ngHubs.Id `
    -GroupConnectivity 'DirectlyConnected' -IsGlobal

$connMesh = New-AzNetworkManagerConnectivityConfiguration -Name $meshCfgName `
    -ResourceGroupName $rgName -NetworkManagerName $avnm.Name `
    -ConnectivityTopology 'Mesh' -AppliesToGroup @($hubGrpItem) `
    -IsGlobal -DeleteExistingPeering -Force `
    -Description 'Global mesh peering between the regional hubs'

# ---- Additional scenarios: workload meshes ----
# Each mesh is a separate configuration over a separate group, which is what
# keeps prod and non-prod from becoming mutually reachable: membership of one
# mesh confers no connectivity to members of another.
function New-GlobalMesh {
    param([string]$Name, $NetworkGroup, [string]$Description)

    $item = New-AzNetworkManagerConnectivityGroupItem -NetworkGroupId $NetworkGroup.Id `
        -GroupConnectivity 'DirectlyConnected' -IsGlobal

    New-AzNetworkManagerConnectivityConfiguration -Name $Name `
        -ResourceGroupName $rgName -NetworkManagerName $avnm.Name `
        -ConnectivityTopology 'Mesh' -AppliesToGroup @($item) `
        -IsGlobal -DeleteExistingPeering -Force -Description $Description
}

# IaaS production: this is what lets the VM subnets reach each other directly.
$connIaasProd = New-GlobalMesh -Name $meshIaasProd -NetworkGroup $ngIaasProd `
    -Description 'Global mesh across IaaS production spokes (VM-to-VM direct)'

# IaaS non-production: same behaviour, isolated from prod.
$connIaasNonP = New-GlobalMesh -Name $meshIaasNonP -NetworkGroup $ngIaasNonP `
    -Description 'Global mesh across IaaS non-production spokes'

# Infrastructure: cross-region DC replication without hairpinning the firewall.
$connInfra = New-GlobalMesh -Name $meshInfra -NetworkGroup $ngInfra `
    -Description 'Global mesh across infrastructure spokes'
#endregion

#region ------------------ Routing configuration (UDR mgmt) -----------------
# Rule collections are applied to a tag-driven network group, and AVNM writes
# the resulting routes into the prestaged tables rather than its own, because
# routeTableUsageMode is UseExisting. Driven through the ARM API here because
# cmdlet coverage for UDR management varies by Az version.
Write-Host ">> Creating AVNM routing configuration" -ForegroundColor Cyan

# $apiVersion / $avnmBase / $routeCfgName are defined in the variables region.

function Invoke-AvnmPut {
    param([string]$Path, [hashtable]$Body, [string]$ApiVersion = $routingApi)
    $resp = Invoke-AzRestMethod -Method PUT -Path "$Path`?api-version=$ApiVersion" `
        -Payload ($Body | ConvertTo-Json -Depth 12)
    if ($resp.StatusCode -ge 400) { throw "PUT $Path failed ($($resp.StatusCode)): $($resp.Content)" }
    return ($resp.Content | ConvertFrom-Json)
}

# Routing configuration container.
#   ManagedOnly (default) - AVNM builds its own route tables in a managed
#                           resource group, which is why none appeared here.
#   UseExisting           - AVNM appends to the route table already associated
#                           with the subnet, preserving its name, tags and RG.
$routeTableMode = if ($PrestageRouteTables) { 'UseExisting' } else { 'ManagedOnly' }
Write-Host "   routeTableUsageMode: $routeTableMode"

Invoke-AvnmPut -Path "$avnmBase/routingConfigurations/$routeCfgName" -Body @{
    properties = @{
        description         = 'Force spoke egress through the regional firewall'
        routeTableUsageMode = $routeTableMode
    }
} | Out-Null

foreach ($r in @($loc1Short, $loc2Short)) {
    $rcName = "rules-$r"

    # Rule collection scoped to that region's spoke group, BGP propagation off
    Invoke-AvnmPut -Path "$avnmBase/routingConfigurations/$routeCfgName/ruleCollections/$rcName" -Body @{
        properties = @{
            description                = "Spoke routing for $r"
            disableBgpRoutePropagation = 'True'
            appliesTo                  = @(@{ networkGroupId = $ng[$r].Id })
        }
    } | Out-Null

    # Default route -> regional firewall
    Invoke-AvnmPut -Path "$avnmBase/routingConfigurations/$routeCfgName/ruleCollections/$rcName/rules/default-to-fw" -Body @{
        properties = @{
            description = 'All internet-bound traffic via firewall'
            destination = @{ type = 'AddressPrefix'; destinationAddress = '0.0.0.0/0' }
            nextHop     = @{ nextHopType = 'VirtualAppliance'; nextHopAddress = $fwIp[$r] }
        }
    } | Out-Null

    # Explicitly inspected ranges -> regional firewall. IaaS spoke CIDRs are
    # absent from this list, so IaaS-to-IaaS traffic has no route table entry
    # and follows the mesh connectivity directly. Everything else private is
    # still pulled to the firewall, and 0.0.0.0/0 above catches the remainder.
    $n = 0
    foreach ($p in $inspectedRanges) {
        $n++
        Invoke-AvnmPut -Path "$avnmBase/routingConfigurations/$routeCfgName/ruleCollections/$rcName/rules/private-$n-to-fw" -Body @{
            properties = @{
                description = "Inspected range $p via firewall"
                destination = @{ type = 'AddressPrefix'; destinationAddress = $p }
                nextHop     = @{ nextHopType = 'VirtualAppliance'; nextHopAddress = $fwIp[$r] }
            }
        } | Out-Null
    }
}
#endregion

#region --------------- Security admin configuration (NSG enforcement) ------
# Security admin rules are evaluated BEFORE subnet/NIC NSGs.
#   Access = 'Allow'       -> permitted here, still subject to NSG evaluation
#   Access = 'AlwaysAllow' -> bypasses NSGs entirely
#   Access = 'Deny'        -> dropped, cannot be overridden by an NSG
Write-Host ">> Creating security admin configuration" -ForegroundColor Cyan

$sac = New-AzNetworkManagerSecurityAdminConfiguration -Name $sacName `
    -ResourceGroupName $rgName -NetworkManagerName $avnm.Name `
    -Description 'Baseline infrastructure services + guardrails' `
    -ApplyOnNetworkIntentPolicyBasedService @('AllowRulesOnly') -Force

# Reusable address prefix items
$apVnet     = New-AzNetworkManagerAddressPrefixItem -AddressPrefix 'VirtualNetwork' -AddressPrefixType 'ServiceTag'
$apInternet = New-AzNetworkManagerAddressPrefixItem -AddressPrefix 'Internet'       -AddressPrefixType 'ServiceTag'
$apMonitor  = New-AzNetworkManagerAddressPrefixItem -AddressPrefix 'AzureMonitor'   -AddressPrefixType 'ServiceTag'
$apAny      = New-AzNetworkManagerAddressPrefixItem -AddressPrefix '0.0.0.0/0'      -AddressPrefixType 'IPPrefix'
$apShared   = @($sharedSvcAll | ForEach-Object { New-AzNetworkManagerAddressPrefixItem -AddressPrefix $_ -AddressPrefixType 'IPPrefix' })
$apProd     = @($prodCidrs    | ForEach-Object { New-AzNetworkManagerAddressPrefixItem -AddressPrefix $_ -AddressPrefixType 'IPPrefix' })

# ---------- Collection 1: infrastructure services, all spokes ----------
$appliesAll = @(
    New-AzNetworkManagerSecurityGroupItem -NetworkGroupId $ng[$loc1Short].Id
    New-AzNetworkManagerSecurityGroupItem -NetworkGroupId $ng[$loc2Short].Id
)

$rcInfra = New-AzNetworkManagerSecurityAdminRuleCollection -Name 'rc-infrastructure' `
    -ResourceGroupName $rgName -NetworkManagerName $avnm.Name `
    -SecurityAdminConfigurationName $sac.Name -AppliesToGroup $appliesAll -Force `
    -Description 'AD / DNS / security tooling / backup / monitoring'

# Sanity-check what the service actually handed back before building on it.
if (-not $sac.Name)     { throw "Security admin configuration returned no name - creation failed silently." }
if (-not $rcInfra.Name) { throw "Rule collection rc-infrastructure returned no name - creation failed silently." }
Write-Host "   config '$($sac.Name)' / collection '$($rcInfra.Name)' created"

$rule = @{
    ResourceGroupName              = $rgName
    NetworkManagerName             = $avnm.Name
    SecurityAdminConfigurationName = $sac.Name
    RuleCollectionName             = $rcInfra.Name
}

# Active Directory - TCP (Kerberos, RPC EPM, LDAP, SMB, kpasswd, LDAPS, GC, dynamic RPC)
New-AzNetworkManagerSecurityAdminRule @rule -Name 'Allow-AD-TCP' -Priority 100 `
    -Direction Outbound -Access Allow -Protocol Tcp `
    -SourceAddressPrefix @($apVnet) -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix $apShared `
    -DestinationPortRange @('88','135','389','445','464','636','3268','3269','49152-65535') -Force | Out-Null

# Active Directory - UDP (Kerberos, NTP, LDAP ping, kpasswd)
New-AzNetworkManagerSecurityAdminRule @rule -Name 'Allow-AD-UDP' -Priority 110 `
    -Direction Outbound -Access Allow -Protocol Udp `
    -SourceAddressPrefix @($apVnet) -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix $apShared -DestinationPortRange @('88','123','389','464') -Force | Out-Null

# DNS
New-AzNetworkManagerSecurityAdminRule @rule -Name 'Allow-DNS-TCP' -Priority 120 `
    -Direction Outbound -Access Allow -Protocol Tcp `
    -SourceAddressPrefix @($apVnet) -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix $apShared -DestinationPortRange @('53') -Force | Out-Null

New-AzNetworkManagerSecurityAdminRule @rule -Name 'Allow-DNS-UDP' -Priority 130 `
    -Direction Outbound -Access Allow -Protocol Udp `
    -SourceAddressPrefix @($apVnet) -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix $apShared -DestinationPortRange @('53') -Force | Out-Null

# Security tooling (EDR / vulnerability management agents outbound)
New-AzNetworkManagerSecurityAdminRule @rule -Name 'Allow-SecurityTools-Out' -Priority 140 `
    -Direction Outbound -Access Allow -Protocol Tcp `
    -SourceAddressPrefix @($apVnet) -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix $apShared -DestinationPortRange @('443','8443') -Force | Out-Null

# Authenticated scanning inbound from the shared services subnets
New-AzNetworkManagerSecurityAdminRule @rule -Name 'Allow-SecurityScanners-In' -Priority 150 `
    -Direction Inbound -Access Allow -Protocol Tcp `
    -SourceAddressPrefix $apShared -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix @($apVnet) -DestinationPortRange @('22','443','3389','5985','5986') -Force | Out-Null

# Backup agents (adjust the range to your backup product)
New-AzNetworkManagerSecurityAdminRule @rule -Name 'Allow-Backup-Out' -Priority 160 `
    -Direction Outbound -Access Allow -Protocol Tcp `
    -SourceAddressPrefix @($apVnet) -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix $apShared -DestinationPortRange @('443','10101-10199') -Force | Out-Null

# Azure Monitor / Log Analytics
New-AzNetworkManagerSecurityAdminRule @rule -Name 'Allow-AzureMonitor-Out' -Priority 170 `
    -Direction Outbound -Access Allow -Protocol Tcp `
    -SourceAddressPrefix @($apVnet) -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix @($apMonitor) -DestinationPortRange @('443') -Force | Out-Null

# ---- Guardrail denies (cannot be overridden by a workload team's NSG) ----
New-AzNetworkManagerSecurityAdminRule @rule -Name 'Deny-Internet-Inbound-Mgmt' -Priority 4000 `
    -Direction Inbound -Access Deny -Protocol Tcp `
    -SourceAddressPrefix @($apInternet) -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix @($apAny) -DestinationPortRange @('22','3389','5985','5986') -Force | Out-Null

New-AzNetworkManagerSecurityAdminRule @rule -Name 'Deny-Internet-Inbound-SMB-RPC' -Priority 4010 `
    -Direction Inbound -Access Deny -Protocol Tcp `
    -SourceAddressPrefix @($apInternet) -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix @($apAny) -DestinationPortRange @('135','139','445') -Force | Out-Null

New-AzNetworkManagerSecurityAdminRule @rule -Name 'Deny-Internet-Inbound-DB' -Priority 4020 `
    -Direction Inbound -Access Deny -Protocol Tcp `
    -SourceAddressPrefix @($apInternet) -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix @($apAny) -DestinationPortRange @('1433','3306','5432','27017') -Force | Out-Null

# ---------- Collection 2: non-production isolation ----------
$rcNonProd = New-AzNetworkManagerSecurityAdminRuleCollection -Name 'rc-nonprod-isolation' `
    -ResourceGroupName $rgName -NetworkManagerName $avnm.Name `
    -SecurityAdminConfigurationName $sac.Name `
    -AppliesToGroup @(New-AzNetworkManagerSecurityGroupItem -NetworkGroupId $ngNonProd.Id) -Force `
    -Description 'Block non-production spokes from reaching production'

New-AzNetworkManagerSecurityAdminRule -ResourceGroupName $rgName -NetworkManagerName $avnm.Name `
    -SecurityAdminConfigurationName $sac.Name -RuleCollectionName $rcNonProd.Name `
    -Name 'Deny-NonProd-To-Prod' -Priority 200 `
    -Direction Outbound -Access Deny -Protocol Any `
    -SourceAddressPrefix @($apVnet) -SourcePortRange @('0-65535') `
    -DestinationAddressPrefix $apProd -DestinationPortRange @('0-65535') -Force | Out-Null
#endregion

#region --------------- Verify the security admin configuration -------------
# Read back what the service holds, rather than trusting that the create calls
# worked. This distinguishes three very different situations:
#   no rule collections        -> creation silently no-opped
#   collections but no rules   -> rules were rejected
#   rules but no group members -> configuration is fine, membership is not
Write-Host '>> Verifying security admin configuration contents' -ForegroundColor Cyan

# Read collections over REST: the ARM field is properties.appliesToGroups, and
# the PowerShell object does not expose it under that name on every Az version.
$rcUri  = "$avnmBase/securityAdminConfigurations/$sacName/ruleCollections`?api-version=$apiVersion"
$rcResp = Invoke-AzRestMethod -Method GET -Path $rcUri
if ($rcResp.StatusCode -ge 400) {
    throw "Could not read rule collections ($($rcResp.StatusCode)): $($rcResp.Content)"
}
$rcList = @(($rcResp.Content | ConvertFrom-Json).value)

if (-not $rcList.Count) {
    Write-Host "   '$sacName' contains NO rule collections." -ForegroundColor Red
    Write-Host '   The create calls returned without error but nothing persisted.' -ForegroundColor Red
    Write-Host '   Check write access on the network manager and any resource locks.' -ForegroundColor Red
    throw "Security admin configuration '$sacName' has no rule collections."
}

$totalRules = 0
foreach ($rc in $rcList) {
    $rules = Get-AzNetworkManagerSecurityAdminRule `
        -RuleCollectionName $rc.name -SecurityAdminConfigurationName $sacName `
        -NetworkManagerName $avnm.Name -ResourceGroupName $rgName -ErrorAction SilentlyContinue

    $count       = @($rules).Count
    $totalRules += $count
    $groups      = @($rc.properties.appliesToGroups)

    $colour = if ($count -gt 0 -and $groups.Count -gt 0) { 'Green' } else { 'Red' }
    Write-Host ("   {0,-24} {1,2} rule(s), applied to {2} group(s)" -f $rc.name, $count, $groups.Count) -ForegroundColor $colour

    foreach ($g in $groups) {
        Write-Host "     -> $(($g.networkGroupId -split '/')[-1])"
    }

    if ($groups.Count -eq 0) {
        throw "Rule collection '$($rc.name)' targets no network group - it can never apply."
    }
}

if ($totalRules -eq 0) {
    throw "Rule collections exist under '$sacName' but contain no rules."
}
Write-Host "   $totalRules rule(s) across $($rcList.Count) collection(s), all targeted." -ForegroundColor Green
#endregion

#region ---------------------- Prestaged route tables ------------------------
# Created here, in your resource group, with your naming and tags. AVNM will
# append to these rather than build its own once UseExisting mode is committed.
Write-Host '>> Creating prestaged route tables' -ForegroundColor Cyan

$rt = @{}
foreach ($r in @($loc1Short, $loc2Short)) {
    $location = if ($r -eq $loc1Short) { $loc1 } else { $loc2 }

    $routes = @(
        # Safety net. Present from the moment the table is associated, so spoke
        # egress is inspected even before AVNM has evaluated anything.
        New-AzRouteConfig -Name 'default-to-fw' -AddressPrefix '0.0.0.0/0' `
            -NextHopType 'VirtualAppliance' -NextHopIpAddress $fwIp[$r]
    )

    if ($PrestageAllRoutes) {
        $i = 0
        foreach ($p in $inspectedRanges) {
            $i++
            $routes += New-AzRouteConfig -Name "inspected-$i-to-fw" -AddressPrefix $p `
                -NextHopType 'VirtualAppliance' -NextHopIpAddress $fwIp[$r]
        }
    }

    $rt[$r] = New-AzRouteTable -Name $rtName[$r] -ResourceGroupName $rgName -Location $location `
        -DisableBgpRoutePropagation -Route $routes -Force `
        -Tag ($commonTags + @{
            networkRole    = 'spoke'
            region         = $r
            routingProfile = 'spoke-via-firewall'
            managedBy      = 'avnm'
        })

    Write-Host "   $($rtName[$r]) with $($routes.Count) prestaged route(s), BGP propagation off"
}
#endregion

#region ------------------- Infrastructure NSGs (subnet level) ---------------
# These sit underneath the AVNM security admin rules. Order of evaluation is:
#   security admin Deny  -> dropped outright
#   security admin Allow -> passed down here for the NSG to decide
#   security admin AlwaysAllow -> skips the NSG entirely
# So an infrastructure flow needs BOTH an admin Allow and an NSG Allow. The
# admin rules are the guardrail a workload team cannot remove; these are the
# per-subnet baseline they can extend.
Write-Host '>> Creating infrastructure NSGs' -ForegroundColor Cyan

function New-InfraNsg {
    param([string]$Name, [string]$Location)

    $rules = @()

    # ---- Inbound ----
    # Scanning / patching / remote management from the shared services subnets
    $rules += New-AzNetworkSecurityRuleConfig -Name 'Allow-Mgmt-In-From-SharedSvc' -Priority 100 `
        -Direction Inbound -Access Allow -Protocol Tcp `
        -SourceAddressPrefix $sharedSvcAll -SourcePortRange '*' `
        -DestinationAddressPrefix 'VirtualNetwork' -DestinationPortRange @('22','443','3389','5985','5986')

    # AD / DNS answers and general intra-VNet + connected-group traffic. This
    # also covers the direct IaaS-to-IaaS path, since the VirtualNetwork tag
    # includes peered and connected address space.
    $rules += New-AzNetworkSecurityRuleConfig -Name 'Allow-VNet-In' -Priority 200 `
        -Direction Inbound -Access Allow -Protocol '*' `
        -SourceAddressPrefix 'VirtualNetwork' -SourcePortRange '*' `
        -DestinationAddressPrefix 'VirtualNetwork' -DestinationPortRange '*'

    $rules += New-AzNetworkSecurityRuleConfig -Name 'Allow-AzureLB-In' -Priority 300 `
        -Direction Inbound -Access Allow -Protocol '*' `
        -SourceAddressPrefix 'AzureLoadBalancer' -SourcePortRange '*' `
        -DestinationAddressPrefix '*' -DestinationPortRange '*'

    $rules += New-AzNetworkSecurityRuleConfig -Name 'Deny-Internet-In' -Priority 4000 `
        -Direction Inbound -Access Deny -Protocol '*' `
        -SourceAddressPrefix 'Internet' -SourcePortRange '*' `
        -DestinationAddressPrefix '*' -DestinationPortRange '*'

    # ---- Outbound ----
    # Active Directory
    $rules += New-AzNetworkSecurityRuleConfig -Name 'Allow-AD-TCP-Out' -Priority 100 `
        -Direction Outbound -Access Allow -Protocol Tcp `
        -SourceAddressPrefix 'VirtualNetwork' -SourcePortRange '*' `
        -DestinationAddressPrefix $sharedSvcAll `
        -DestinationPortRange @('88','135','389','445','464','636','3268','3269','49152-65535')

    $rules += New-AzNetworkSecurityRuleConfig -Name 'Allow-AD-UDP-Out' -Priority 110 `
        -Direction Outbound -Access Allow -Protocol Udp `
        -SourceAddressPrefix 'VirtualNetwork' -SourcePortRange '*' `
        -DestinationAddressPrefix $sharedSvcAll -DestinationPortRange @('88','123','389','464')

    # DNS
    $rules += New-AzNetworkSecurityRuleConfig -Name 'Allow-DNS-Out' -Priority 120 `
        -Direction Outbound -Access Allow -Protocol '*' `
        -SourceAddressPrefix 'VirtualNetwork' -SourcePortRange '*' `
        -DestinationAddressPrefix $sharedSvcAll -DestinationPortRange '53'

    # Security tooling and backup agents
    $rules += New-AzNetworkSecurityRuleConfig -Name 'Allow-SecTools-Backup-Out' -Priority 130 `
        -Direction Outbound -Access Allow -Protocol Tcp `
        -SourceAddressPrefix 'VirtualNetwork' -SourcePortRange '*' `
        -DestinationAddressPrefix $sharedSvcAll -DestinationPortRange @('443','8443','10101-10199')

    # Azure Monitor / Log Analytics
    $rules += New-AzNetworkSecurityRuleConfig -Name 'Allow-AzureMonitor-Out' -Priority 140 `
        -Direction Outbound -Access Allow -Protocol Tcp `
        -SourceAddressPrefix 'VirtualNetwork' -SourcePortRange '*' `
        -DestinationAddressPrefix 'AzureMonitor' -DestinationPortRange '443'

    # Intra-VNet, peered and connected-group traffic (keeps IaaS mesh working)
    $rules += New-AzNetworkSecurityRuleConfig -Name 'Allow-VNet-Out' -Priority 200 `
        -Direction Outbound -Access Allow -Protocol '*' `
        -SourceAddressPrefix 'VirtualNetwork' -SourcePortRange '*' `
        -DestinationAddressPrefix 'VirtualNetwork' -DestinationPortRange '*'

    # NOTE: no blanket outbound Internet deny. Spoke egress is routed to the
    # firewall by the routing configuration, but the destination is still an
    # internet address at the NIC, so a deny here would break firewall egress
    # as well as direct egress. Control it in firewall policy instead.

    New-AzNetworkSecurityGroup -Name $Name -ResourceGroupName $rgName -Location $Location `
        -SecurityRules $rules -Tag $commonTags -Force
}

$nsg = @{}
foreach ($r in @($loc1Short, $loc2Short)) {
    $location = if ($r -eq $loc1Short) { $loc1 } else { $loc2 }
    $nsg[$r]  = New-InfraNsg -Name $nsgName[$r] -Location $location
}

# ---- Associate NSG and route table with every spoke subnet ----
# Mutating the subnet objects in place preserves delegations and any other
# subnet properties; re-running Set-AzVirtualNetworkSubnetConfig would drop them.
# Both associations happen in one pass so each VNet is written once.
Write-Host '>> Associating NSGs and route tables with spoke subnets' -ForegroundColor Cyan
foreach ($s in $spokeDefs) {
    $vnetName = "vnet-spoke-$($s.Workload)-$($s.Env)-$($s.Rg)"
    $vnet     = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $rgName

    foreach ($sn in $vnet.Subnets) {
        $sn.NetworkSecurityGroup = $nsg[$s.Rg]
        if ($PrestageRouteTables) { $sn.RouteTable = $rt[$s.Rg] }
    }
    $vnet | Set-AzVirtualNetwork | Out-Null
    Write-Host "   $vnetName -> $($nsgName[$s.Rg]) + $($rtName[$s.Rg]) on $($vnet.Subnets.Count) subnets"
}
#endregion

#region ------------- Wait for dynamic group membership ---------------------
# Membership is written by Azure Policy and recorded in Azure Resource Graph
# under Microsoft.Network/networkGroupMemberships. Until a VNet appears there,
# no configuration that applies to that group affects it - which is exactly the
# "security admin configuration isn't linked to my VNets" symptom.
Write-Host '>> Waiting for dynamic group membership' -ForegroundColor Cyan

$dynamicGroupIds = @{
    $ngNames[$loc1Short] = $ng[$loc1Short].Id
    $ngNames[$loc2Short] = $ng[$loc2Short].Id
    $ngNames['nonprod']  = $ngNonProd.Id
    $ngNames['iaasProd'] = $ngIaasProd.Id
    $ngNames['iaasNonP'] = $ngIaasNonP.Id
    $ngNames['infra']    = $ngInfra.Id
}

function Get-GroupMemberCount {
    param([hashtable]$GroupIds)

    $query = @"
networkresources
| where type == "microsoft.network/networkgroupmemberships"
| mv-expand membership = properties.GroupMemberships
| project groupId = tolower(tostring(membership.NetworkGroupId))
| summarize count() by groupId
"@
    $rows   = Search-AzGraph -Query $query -Subscription $subId -ErrorAction Stop
    $counts = @{}
    foreach ($g in $GroupIds.Keys) {
        $match = $rows | Where-Object { $_.groupId -eq $GroupIds[$g].ToLower() }
        $counts[$g] = if ($match) { [int]$match.count_ } else { 0 }
    }
    return $counts
}

if ($SkipMembershipWait) {
    Write-Host '   Skipped by configuration - configurations may show as unlinked until policy evaluates.' -ForegroundColor Yellow
}
elseif (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
    Write-Host '   Az.ResourceGraph not available; cannot poll membership.' -ForegroundColor Yellow
    Write-Host "   Sleeping $MembershipWaitMinutes minutes instead. Install-Module Az.ResourceGraph for the polling path." -ForegroundColor Yellow
    Start-Sleep -Seconds ($MembershipWaitMinutes * 60)
}
else {
    # Nudge Azure Policy rather than waiting for the standard evaluation cycle
    Invoke-Safely 'triggered policy compliance scan' {
        Start-AzPolicyComplianceScan -AsJob | Out-Null
    }

    $start     = Get-Date
    $deadline  = $start.AddMinutes($MembershipWaitMinutes)
    $earlyExit = $start.AddMinutes($MembershipEarlyExitMinutes)
    $expected  = $spokeDefs.Count         # every spoke belongs to a regional group
    $regional  = 0

    do {
        Start-Sleep -Seconds 45
        try   { $counts = Get-GroupMemberCount -GroupIds $dynamicGroupIds }
        catch { Write-Host "   graph query failed: $($_.Exception.Message)" -ForegroundColor DarkYellow; continue }

        $regional = $counts[$ngNames[$loc1Short]] + $counts[$ngNames[$loc2Short]]
        $remain   = [int]($deadline - (Get-Date)).TotalMinutes
        Write-Host "   regional groups hold $regional/$expected spokes (${remain}m left)"

        # Partial membership means policy is working and just needs more time.
        # Flat zero past the early-exit mark means it isn't going to happen.
        if ($regional -eq 0 -and (Get-Date) -gt $earlyExit) {
            Write-Host ''
            Write-Host "   Still zero after $MembershipEarlyExitMinutes minutes - not waiting further." -ForegroundColor Yellow
            Write-Host '   Either policy is not producing membership, or this query is not seeing it.' -ForegroundColor Yellow
            Write-Host '   Run Diagnose-AvnmMembership.ps1 to tell those apart. Common causes:' -ForegroundColor Yellow
            Write-Host '     - assignment lacks permission to join the network group (Classic Admin does not count)'
            Write-Host '     - tag values differ in case from the policy conditions'
            Write-Host '     - Az.ResourceGraph missing or querying a different subscription'
            break
        }
    }
    while ($regional -lt $expected -and (Get-Date) -lt $deadline)

    if ($regional -ge $expected) {
        Write-Host '   All spokes are group members.' -ForegroundColor Green
    }
    else {
        Write-Host '   Continuing to commit. Configurations attach to groups, not VNets, so a' -ForegroundColor Yellow
        Write-Host '   commit against an empty group is valid and starts applying as members join.' -ForegroundColor Yellow
    }
}
#endregion

#region -------------------------- Commit / deploy --------------------------
Write-Host ">> Committing AVNM configurations" -ForegroundColor Cyan

foreach ($r in @($loc1Short, $loc2Short)) {
    $location = if ($r -eq $loc1Short) { $loc1 } else { $loc2 }

    Deploy-AzNetworkManagerCommit -ResourceGroupName $rgName -Name $avnm.Name `
        -TargetLocation @($location) `
        -ConfigurationId @($conn[$r].Id, $connMesh.Id, $connIaasProd.Id,
                           $connIaasNonP.Id, $connInfra.Id) -CommitType 'Connectivity'

    Deploy-AzNetworkManagerCommit -ResourceGroupName $rgName -Name $avnm.Name `
        -TargetLocation @($location) `
        -ConfigurationId @("$avnmBase/routingConfigurations/$routeCfgName") -CommitType 'Routing'

    Deploy-AzNetworkManagerCommit -ResourceGroupName $rgName -Name $avnm.Name `
        -TargetLocation @($location) -ConfigurationId @($sac.Id) -CommitType 'SecurityAdmin'
}
#endregion

#region ---------------------- Linkage verification -------------------------
Write-Host ''
Write-Host '>> Verifying what is linked' -ForegroundColor Cyan

if (Get-Command Search-AzGraph -ErrorAction SilentlyContinue) {
    try {
        $counts = Get-GroupMemberCount -GroupIds $dynamicGroupIds
        Write-Host '   Network group membership:'
        foreach ($g in ($counts.Keys | Sort-Object)) {
            $colour = if ($counts[$g] -gt 0) { 'Green' } else { 'Yellow' }
            Write-Host ("     {0,-22} {1} VNet(s)" -f $g, $counts[$g]) -ForegroundColor $colour
        }
        if (($counts.Values | Measure-Object -Sum).Sum -eq 0) {
            Write-Host '   Every group is empty - configurations will not apply yet.' -ForegroundColor Yellow
            Write-Host '   Check the membership policies and re-run a compliance scan.' -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "   graph query failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

# Per-VNet view of the security admin rules actually in effect. This is the
# authoritative answer to "is the security admin configuration linked?".
$sampleSpoke = "vnet-spoke-$($spokeDefs[0].Workload)-$($spokeDefs[0].Env)-$($spokeDefs[0].Rg)"
Invoke-Safely "effective security admin rules on $sampleSpoke" {
    $vnet    = Get-AzVirtualNetwork -Name $sampleSpoke -ResourceGroupName $rgName
    $effUri  = "$($vnet.Id)/listNetworkManagerEffectiveSecurityAdminRules`?api-version=$apiVersion"
    $resp    = Invoke-AzRestMethod -Method POST -Path $effUri
    if ($resp.StatusCode -ge 400) { throw $resp.Content }

    $rules = ($resp.Content | ConvertFrom-Json).value
    if ($rules) {
        Write-Host "   $sampleSpoke has $($rules.Count) effective admin rule(s)" -ForegroundColor Green
    }
    else {
        Write-Host "   $sampleSpoke has NO effective admin rules - not yet a group member," -ForegroundColor Yellow
        Write-Host '   or the SecurityAdmin commit has not finished.' -ForegroundColor Yellow
    }
}
#endregion

Write-Host ''
Write-Host '>> Address allocation summary' -ForegroundColor Cyan
foreach ($r in @($loc1Short, $loc2Short)) {
    Write-Host "   $r"
    Write-Host "     hub (fixed)          $($hubCidr[$r])"
    foreach ($sp in ($spokeDefs | Where-Object { $_.Rg -eq $r } | Sort-Object Workload, Env)) {
        $label = "$($sp.Workload)-$($sp.Env)"
        $src   = if (Test-SpokeUsesIpam $sp) { 'IPAM ' } else { 'fixed' }
        Write-Host ("     {0,-20} {1} {2}" -f $label, $src, (Get-SpokeCidr $sp))
    }
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor Green
Write-Host ' Deployment complete' -ForegroundColor Green
Write-Host "  SCUS firewall next hop : $($fwIp[$loc1Short])"
Write-Host "  NCUS firewall next hop : $($fwIp[$loc2Short])"
Write-Host '  Spokes join their groups once Azure Policy evaluates the tags'
Write-Host '  (~15-30 min, or trigger a compliance scan to speed it up).'
Write-Host '  Connectivity / routing / security admin configs are committed'
Write-Host '  and apply automatically as group membership settles.'
Write-Host '============================================================' -ForegroundColor Green