# Starface Powershell API
A Set of Cmdlets calling the Starface API with Powershell


## Requirements

The Scripts is written on a Windows 10 20H2 machine with latest version of Powershell.
The functionality ist also tested on an Up2Date Windows 10 Machine.

The script does NOT work on Server 2012R2 with factory installed Powershell ( I think 3.0 ?)

## Installation and initialization

To Import the Scripts, you need to download the starface-api.psm1 file and run import-module <pathtofile>\starface-api.psm1

## Connect to Starface-Instance

to connect to a Starface Instance you need to create a login-session. The session has a retention time of 4 hours.

to start the session run 
 ### Start-InitStarfaceAPI -login
you will be asked for a Starface FQDN and User Creds.
  Use -StarfaceFQDN and -Creds to start initialing silently
Saving creds is possible with -SaveCreds

When the session is retend, re-connect with Start-InitStarfaceAPI
  
To log out and delete any saved creds run start-initstarfaceAPI -logout
  
## Generic API-Call
  
Not every function ist coded in a CMDlet, so you can use the generic API-Call CMDlet
  
### Start-StarfaceAPICall -type <type> -call <call> -body <body(JSON)>
 
You can Use all API-Calls wich are documented in the Starface-Doku
https://knowledge.starface.de/download/attachments/46568050/STARFACE%20Rest%20V6_6_0_X.yaml?version=1&modificationDate=1589441304946&api=v2
  
The calls are implemented in the intellisense, so you can tab out the Calls.
  
## Implemented Commands
  
### Get-StarfaceUser (<userID>)
if you dont give a userID you will get all Configured Starface User
If you give a userID you'll get a specific User.

You can pipe the Command to the other ones
  
### Set-StarfaceUser <userID> (<login>,<firstName>,<familyName> etc.)
You can change one or more properties of a specific user.
For example you want to change the FAX-Header of all users run
  
Get-StarfaceUser | Set-Starfaceuser -FaxHeader "Contosoo Inc."

### Add-StarfaceUser <FamilyName>,<Firstname>,<email> (<FaxHeader>,etc,)
Adds a new User with given information

  
### Remove-StarfaceUser <UserID>
Removes a User. Can be piped like:
Get-StarfaceUser | ? -familyName -eq "Smith"| Remove-StarfaceUser
 
### Get-StarfaceUserPermission (<UserID>)
Get the permissions of a specific User.
Can be piped.
 
### Set-StarfaceUserPermission -userID (<SetAdmin>,<SetDefault>)
You can set the permission of a specific user to default or grant a admin-user
for example:
StarfaceUserPermission -userID 1001 -SetDefault

  
