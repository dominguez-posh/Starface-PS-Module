# Starface Powershell Module
A Set of Cmdlets calling the Starface API with Powershell


## Requirements

The Scripts is written on a Windows 10 20H2 machine with latest version of Powershell.
The functionality ist also tested on an Up2Date Windows 10 Machine.

The script does NOT work on Server 2012R2 with factory installed Powershell ( I think 3.0 ?)

## Installation and initialization

To Import the Scripts, you need to download the starface-api.psm1 file and run 

```powershell

import-module <pathtofile>\starface-api.psm1

```

## Connect to Starface-Instance

to connect to a Starface Instance you need to create a login-session. The session has a retention time of 4 hours.

 
```PowerShell
#to start a new session run 

Start-InitStarfaceAPI -login

# Saving Creds can be done with

Start-InitStarfaceAPI -login -SaveCreds

#Login Silently with

Start-InitStarfaceAPI -login -StarfaceFQDN <starface.contoso.com> -Creds <PS-Cred-Obj> 

#When session is retent, you can use the command to generate a new 4h session

Start-InitStarfaceAPI

#To Log out the session use

start-initstarfaceAPI -logout


```
  
## Generic API-Call
  
Not every function ist coded in a CMDlet, so you can use the generic API-Call CMDlet
  
```powershell

Start-StarfaceAPICall -type <type> -call <call> -body <(json)body>

```
 
You can Use all API-Calls wich are documented in the Starface-Doku
https://knowledge.starface.de/download/attachments/46568050/STARFACE%20Rest%20V6_6_0_X.yaml?version=1&modificationDate=1589441304946&api=v2
  
The calls are implemented in the intellisense, so you can tab out the Calls.
  
## Implemented Commands

```powershell
#If you give a userID you'll get a specific User.
Get-StarfaceUser -userID <UserID>


#if you dont give a userID you will get all Configured Starface User
Get-StarfaceUser 

```

You can pipe the Command to the other ones

```powershell
Set-StarfaceUser (userID) ((login),(firstName),(familyName) etc.)

#You can change one or more properties of a specific user.
#For example you want to change the FAX-Header of all users run

Get-StarfaceUser | Set-Starfaceuser -FaxHeader "Contosoo Inc."
```

```powershell
Add-StarfaceUser (FamilyName),(Firstname),(email) ((FaxHeader),etc,)
#Adds a new User with given information
```



```powershell
Remove-StarfaceUser (UserID)

#Removes a User. Can be piped like:
Get-StarfaceUser | ? -familyName -eq "Smith"| Remove-StarfaceUser

```  


```powershell
### Get-StarfaceUserPermission ((UserID))
``` 

Get the permissions of a specific User.
Can be piped.
```powershell
Set-StarfaceUserPermission -userID ((SetAdmin),(SetDefault))
# You can set the permission of a specific user to default or grant a admin-user like

StarfaceUserPermission -userID 1001 -SetDefault
```




  
