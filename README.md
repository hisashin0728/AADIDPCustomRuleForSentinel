# AADIDPCustomRuleForSentinel
As of September 30, 2022, alerts coming from the Azure Active Directory Identity Protection connector no longer contain the following fields:

- CompromisedEntity
- ExtendedProperties["User Account"]
- ExtendedProperties["User Name”]

https://learn.microsoft.com/en-us/azure/sentinel/whats-new#account-enrichment-fields-removed-from-azure-ad-identity-protection-connector

Customer wants to generate User Account and User Name entities from Azure AD Identity Protection Alerts, so this custom package will provide these entities by scheduled analytics query on Microsoft Sentinel.

<img width="933" alt="image" src="https://user-images.githubusercontent.com/55295601/207201392-2485c56b-8799-4c29-9ca2-2826eb7dd80e.png">

# Requirements
Customer needs to prepare following requirements:

- If you haven't already, enable the UEBA solution to sync the IdentityInfo table with your Azure AD logs.

# Not Supported
- Due to schedule rule, incidents will be generated as only "Medium" Severity.
    - Default AAD IDP Connector and "Microsoft Security" rule supports each severities (High/Medium/Low) from AAD IDP Alerts, but this schedule rule can support Medium Severity.

# How to Deploy
Download json file as Resouce Manager Templates, and import this from Microsoft Sentinel.

https://github.com/hisashin0728/AADIDPCustomRuleForSentinel/blob/main/Create%20incidents%20based%20on%20AAD%20Identity%20Protection%20Customized.json

# Current KQL

```
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Active Directory Identity Protection"
| mv-expand Entity = todynamic(Entities)
| where Entity.Type == "account"
| extend AadTenantId = tostring(Entity.AadTenantId)
| extend AadUserId = tostring(Entity.AadUserId)
| join kind=inner (
    IdentityInfo
    | where TimeGenerated > ago(14d)
    | distinct AccountTenantId, AccountObjectId, AccountUPN, AccountDisplayName
    | extend UserAccount = AccountUPN
    | extend UserName = AccountDisplayName
    | where isnotempty(AccountDisplayName) and isnotempty(UserAccount)
    | project AccountTenantId, AccountObjectId, UserAccount, UserName
    )
    on
    $left.AadTenantId == $right.AccountTenantId,
    $left.AadUserId == $right.AccountObjectId
| extend CompromisedEntity = iff(CompromisedEntity == "N/A" or isempty(CompromisedEntity), UserAccount, CompromisedEntity)
| project-away AadTenantId, AccountTenantId, AccountObjectId
```
