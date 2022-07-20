[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $true)][string]$keyvault,
    [Parameter(Mandatory = $true)][string]$resourceGroup,
    [Parameter(Mandatory = $true)][string]$subscriptionId,
    [Parameter(Mandatory = $false)][bool]$rbacConfirm = $true
    
)

Function Set-Permission {
    Param (
        [Parameter (Mandatory = $false)]
        [String] $roleDef,

        [Parameter (Mandatory = $false)]
        [String] $objectId 
    )

    $roleName = $roleDef
    $scope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.KeyVault/vaults/$keyvault"
    $miObjectId = $objectId

    $roleAssignment = Get-AzRoleAssignment -Scope $scope -RoleDefinitionName $roleName -ObjectId $miObjectId
    If (-not $roleAssignment) {
        Write-Host "Assigning role '$roleName' on Keyvault AAD with ObjectID '$miObjectId' on scope '$scope'"
        New-AzRoleAssignment -Scope $scope -RoleDefinitionName $roleName -ObjectId $miObjectId
    }
    else {
        Write-Host "Role Assigment '$roleName' on Keyvault AAD with ObjectID '$miObjectId' on scope '$scope' is already existing"
    }

}



$kvPolicies = (Get-AzKeyVault -VaultName $keyvault -ResourceGroupName $resourceGroup ).AccessPolicies

$kvPolicies | % {


    if ($_.DisplayName.contains("admin")) {

        Write-Host $_.DisplayName
        Set-Permission -objectId $_.ObjectId -roleDef "Key Vault Administrator"

    }
    else {

        Write-Host $_.DisplayName    
        write-host "Keeys"
        Write-Host $_.PermissionsToKeysStr
        write-host "Secretss"
        Write-Host $_.PermissionsToSecretsStr
        write-host "Certtt"
        Write-Host $_.PermissionsToCertificatesstr


        $objId = $_.ObjectId

        switch -wildcard ($_.PermissionsToSecretsStr) {
            "*set*" { Set-Permission -objectId $objId -roleDef "Key Vault Secrets Officer"; break }
            "*get*" { Set-Permission -objectId $objId -roleDef "Key Vault Secrets User"  ; break }
            "*list*" { Set-Permission -objectId $objId -roleDef "Key Vault Reader" } 
        }

        switch -wildcard ($_.PermissionsToKeysStr) {
            "*set*" { Set-Permission -objectId $objId -roleDef "Key Vault Crypto Officer"; break }
            "*get*" { Set-Permission -objectId $objId -roleDef "Key Vault Crypto Service Encryption User"; break }
            "*list*" { Set-Permission -objectId $objId -roleDef "Key Vault Reader" } 
        }
   
        switch -wildcard ($_.PermissionsToCertificatesstr) {
            "*set*" { Set-Permission -objectId $objId -roleDef "Key Vault Certificates Officer"; break }
            "*get*" { Set-Permission -objectId $objId -roleDef "Key Vault Certificates Officer"; break }
            "*list*" { Set-Permission -objectId $objId -roleDef "Key Vault Reader" } 
        }

    
    }


}

Update-AzKeyVault -VaultName $keyvault -ResourceGroupName $resourceGroup -EnableRbacAuthorization $rbacConfirm









