#Run Connect-MsolService and login with Global Admin account.
#Run Set-MsolDirSyncFeature -Feature EnforceCloudPasswordPolicyForPasswordSyncedUsers -Enable $true to Enforce cloud password policy for Password Synced Users
#Set the password validity period and notification days by using below cmdlet:
#
# Set-MsolPasswordPolicy -ValidityPeriod 60 -NotificationDays 14

#This command updates the tenant so that all users passwords expire after 60 days. The users receive notification 14 days prior to that expiry.


# Install-Module -Force Microsoft.Graph -Scope AllUsers

# Get-InstalledModule Microsoft.Graph


# Using Delegated Access 
Connect-MgGraph -Scopes 'User.Read.All', 'Mail.Send', 'Domain.Read.All' 
Connect-Graph -scopes "Policy.Read.All"

# Use App-only access with a client secret credential. This method requires additional safeguards to avoid exposing the secret key. 
#Connect-MgGraph -TenantId "c4689893-958d-4304-858a-0a43f660a43d" -ClientSecretCredential "D2S8Q~NrbCkX96_t0PmoZZTO4ky3mf4fCLXFcbXW"

$clientId = "d8466531-70a4-4d96-800c-d62e494f2c65"
$clientSecret = "ID Chave do client criado app registrations"
$tenantId = "ID Tenant"
$credential = New-Object System.Management.Automation.PSCredential($clientId, (ConvertTo-SecureString -String $clientSecret -AsPlainText -Force))

Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential


# Use App-only access with a certificate 
Connect-MgGraph -ClientId "d8466531-70a4-4d96-800c-d62e494f2c65" -TenantId "ID Tenant" -CertificateThumbprint "F5670C760FD952064147F8EEC1A86B6847788298"
Connect-MgGraph -ClientId "d8466531-70a4-4d96-800c-d62e494f2c65" -TenantId "ID Tenant" -Certificate (Get-Item CERT:\CurrentUser\My\F5670C760FD952064147F8EEC1A86B6847788298)

#Get-MgContext

$domains = Get-MgDomain | Where-Object { $_.PasswordValidityPeriodInDays -ne 2147483647 } | Select-Object Id, PasswordValidityPeriodInDays 
$domains | ForEach-Object { if (!$_.PasswordValidityPeriodInDays) { $_.PasswordValidityPeriodInDays = 180 } } 
$domains

$properties = @("UserPrincipalName", "Mail", "DisplayName", "PasswordPolicies", "LastPasswordChangeDateTime", "CreatedDateTime")

############Actual Script################

# [START EDIT] UPDATE THESE VALUES
# Specify which days remaining will trigger notifications.
$PasswordNotificationWindowInDays = @(180,90,60,30,10) # Remove 60 and 0 as they are only for testing
# Specify the sender email address.
$SenderEmailAddress = 'mailsend@gcb.com.br' # Try with a shared email box as it's free and eliminates the requirement of an SMTP Relay agent
# Specify the group name to which you want to restrict notifications.
$TargetGroupName = "teste_expiracaosenhas_365"
$TargetGroupId = "e2c4e0a3-321d-4839-9790-f26dca189c09"
# [END EDIT]

# Check if TargetGroupId is provided, otherwise get it from TargetGroupName
    if (-not $TargetGroupId) {
        $group = Get-MgGroup -Filter "displayName eq '$TargetGroupName'"
        if ($group) {
            $TargetGroupId = $group.Id
        } else {
            throw "Group with name '$TargetGroupName' not found."
        }
    }

    # Obter os membros do grupo
    $groupMembers = Get-MgGroupMember -GroupId $TargetGroupId

    # Exibir os membros do grupo
    $groupMembers

    # Get group members based on the group ID
    foreach ($member in $groupMembers) {
    # Obter os detalhes do usuário com base no ID do membro
    $user = Get-MgUser -UserId $member.Id

    # Verificar se o usuário é do tipo 'member' e se a conta está habilitada
    if ($user.userType -eq 'member' -and $user.accountEnabled) {
        # Verificar se as políticas de senha não são 'DisablePasswordExpiration'
        if ($user.PasswordPolicies -ne 'DisablePasswordExpiration') {
            # Verificar se o domínio do usuário está na lista de domínios com política de senha
            if ($domains.id -contains $user.userPrincipalName.Split('@')[1]) {
                # Adicionar o usuário à lista de usuários filtrados
                $filteredUsers += $user
            }
        }
    }
}


    
    try {
    Write-Host "Script executed successfully."
} catch {
    Write-Host "An error occurred: $_"
}


# Get the current datetime for calculation
$timeNow = Get-Date

foreach ($user in $users) {
    # Get the user's domain
    $userDomain = ($user.userPrincipalName).Split('@')[1]

    # Get the maximum password age based on the domain password policy.
    $maxPasswordAge = ($domains | Where-Object { $_.id -eq $userDomain }).PasswordValidityPeriodInDays

    # Skip the user if the PasswordValidityPeriodInDays is 2147483647, which means no expiration.
    if ($maxPasswordAge -eq 2147483647) {
        continue;
    }

    # Check if LastPasswordChangeDateTime is null
    if ($null -eq $user.LastPasswordChangeDateTime) {
        Write-Host "LastPasswordChangeDateTime is null for user $($user.userPrincipalName). Skipping."
        continue
    }

    # Check if LastPasswordChangeDateTime is a valid DateTime object
    if (-not ($user.LastPasswordChangeDateTime -is [DateTime])) {
        Write-Host "Invalid LastPasswordChangeDateTime for user $($user.userPrincipalName). Skipping."
        continue
    }

    $passwordAge = (New-TimeSpan -Start $user.LastPasswordChangeDateTime -End $timeNow).Days

    # Check if expiresOn is a valid DateTime object
    if ($null -eq $expiresOn) {
        Write-Host "ExpiresOn is null for user $($user.userPrincipalName). Skipping."
        continue
    }

    # Check if expiresOn is a valid DateTime object
    if (-not ($expiresOn -is [DateTime])) {
        Write-Host "Invalid ExpiresOn for user $($user.userPrincipalName). Skipping."
        continue
    }

    $expiresOn = (Get-Date $user.LastPasswordChangeDateTime).AddDays($maxPasswordAge)

    $user.Domain = $userDomain
    $user.MaxPasswordAge = $maxPasswordAge
    $user.PasswordAge = $passwordAge
    $user.ExpiresOn = $expiresOn

    $user.DaysRemaining = $( 
        # If the remaining days is negative, show 0 instead.
        if (($daysRemaining = (New-TimeSpan -Start $timeNow -End $expiresOn).Days) -lt 1) { 0 }
        else { $daysRemaining }
    )
}

# Obter o endereço de e-mail da caixa compartilhada mailsend
$mailSendAddress = "mailsend@gcb.com.br"

# Definindo o endereço do servidor SMTP Relay
$smtpServer = "smtp.sendgrid.net"

# Definir as propriedades desejadas em um array
$properties = "UserPrincipalName", "Mail", "DisplayName", "PasswordPolicies", "LastPasswordChangeDateTime", "CreatedDateTime"

# Configurações de envio de email
$smtpServer = "smtp.sendgrid.net"
$fromEmail = "notificacao.teste@gcb.com.br"
$subject = "Notificação de Expiração de Senha"
$body = "Prezado usuário,\n\nSua senha está prestes a expirar. Por favor, atualize sua senha o mais rápido possível.\n\nAtenciosamente,\nEquipe de Suporte"

# Nome do grupo do qual você deseja listar os usuários
$groupName = "teste_expiracaosenhas_365"

# Obter o ID do grupo
$group = Get-MgGroup -Filter "DisplayName eq '$groupName'"

if ($group) {
    # Obter os membros do grupo
    $groupMembers = Get-MgGroupMember -GroupId $group.Id

    foreach ($member in $groupMembers) {
        # Obter os detalhes do usuário com base no ID do membro
        $user = Get-MgUser -UserId $member.Id

        # Verificar se a conta do usuário está habilitada
        if ($user.accountEnabled) {
            # Exibir informações do usuário
            Write-Host "Sending expiration notification email to $($user.DisplayName) - $($user.UserPrincipalName)"

            # Enviar email de notificação de expiração de senha
            $emailParams = @{
                From       = $fromEmail
                To         = $user.Mail
                Subject    = $subject
                Body       = $body
                SmtpServer = $smtpServer
            }

            Send-MailMessage @emailParams
        }
    }
} else {
    Write-Host "Grupo '$groupName' não encontrado."
}
