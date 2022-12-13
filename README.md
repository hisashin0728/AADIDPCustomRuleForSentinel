# AADIDPCustomRuleForSentinel



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
