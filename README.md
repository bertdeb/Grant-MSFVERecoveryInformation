# Grant-MSFVERecoveryInformation
Grant MSFVE Recovery Information To Security Groups By OU In Bulk

Delegating BitLocker read permissions in Active Directory can be a tricky business, especially when it is important to maintain the concept of least-privilege.

This PowerShell script allows you to grant read permission on OUs to security groups based on input from a CSV file.

It was designed for the use case of a large enterprise environment with multiple help desks.

This article describes the rationale of this approach:
https://www.experts-exchange.com/articles/33769/Delegation-of-access-to-Bitlocker-Recovery-Passwords-this-way-please.html
