# AADIDPCustomRuleForSentinel
As of September 30, 2022, alerts coming from the Azure Active Directory Identity Protection connector no longer contain the following fields:

- CompromisedEntity
- ExtendedProperties["User Account"]
- ExtendedProperties["User Name”]

https://learn.microsoft.com/en-us/azure/sentinel/whats-new#account-enrichment-fields-removed-from-azure-ad-identity-protection-connector

Customer wants to generate User Account and User Name entities from Azure AD Identity Protection Alerts, so this custom package will provide these entities by scheduled analytics query on Microsoft Sentinel.

# How to Deploy


# Current KQL

```
SecurityAlert
| where ProductName == "Azure Active Directory Identity Protection"
| mv-expand Entity = todynamic(Entities)
| where Entity.Type == "account"
| extend AadTenantId = tostring(Entity.AadTenantId)
| extend AadUserId = tostring(Entity.AadUserId)
| join kind=inner (
    IdentityInfo
    | where TimeGenerated > ago(7d)
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
