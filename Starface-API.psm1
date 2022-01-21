function ConvertTo-SHA512
{
Param
  (
    [parameter(Mandatory=$true)]
    [String] $Inputstring
  )
$mystream = [IO.MemoryStream]::new([byte[]][char[]]$Inputstring)
$Hash = (Get-FileHash -InputStream $mystream -Algorithm SHA512).hash

return $Hash.ToLower()

}

Function Get-RandomPassword
{
param (
[Parameter(Mandatory=$false)][int]$PasswordLenght = 10
)
    Add-Type -AssemblyName System.Web
    $PassComplexCheck = $false
    do {
    $newPassword=[System.Web.Security.Membership]::GeneratePassword($PasswordLenght,1)
    If ( ($newPassword -cmatch "[A-Z\p{Lu}\s]") `
    -and ($newPassword -cmatch "[a-z\p{Ll}\s]") `
    -and ($newPassword -match "[\d]") `
    -and ($newPassword -match "[^\w]")
    )
    {
        $PassComplexCheck=$True
    }
    } While ($PassComplexCheck -eq $false)
    return $newPassword
}

function Start-StarfaceAPICall
{
   
    Param (    
           
            [parameter(Position=0)][ValidateSet(
            "Get", 
            "Put", 
            "Post",
            "Delete"
            )] 
            $Type,
            [System.Management.Automation.PSCredential][parameter(Mandatory=$false)]$Credential,
            [Switch]$Login,
            $UserID,
            $permissionId,
            $voicemailboxid,
            $redirectId,
            $contactId,
            $groupid,
            $conferenceId,
            $phoneId,
            $fkSetId,
            $fmcId,
            $tagId,
            $serviceId,
            $phoneNumberId,
            $Body
           )

     DynamicParam
    {
 
        $Type = $PSBoundParameters.Type
        $Login = $PSBoundParameters.login
 
        if($Type){        

        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
 
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
 
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.ValueFromPipeline = $true
        $ParameterAttribute.ValueFromPipelineByPropertyName = $true
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 1
 
        $AttributeCollection.Add($ParameterAttribute)

        $arrSet = (($APIObj.paths.psobject.members | ? Value -like "*$Type*").name)
         

        $APIObj = try{Import-Clixml "$ENV:temp\SWAGGER\APIOBJ.TMP"}catch{"No Login possible please Initiate !"}
        if($APIObj){
        $ArrSet = ($APIObj.paths.psobject.members | ? Value -like "*$Type*").name}
        else{
        $ArrSet = @("Please First Initialize!")}
        
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)
 
        $AttributeCollection.Add($ValidateSetAttribute)
 
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter("Call", [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add("Call", $RuntimeParameter)

       
        return $RuntimeParameterDictionary
        }


    }
    begin{

    try {$APIObj = Import-Clixml "$ENV:temp\SWAGGER\APIOBJ.TMP" -ErrorAction SilentlyContinue}catch{""}

    

    if($Login){
        
            
            $StarfaceFQDN = $APIObj.InstanceName

            if($StarfaceFQDN -eq $Null){return "No FQDN Chosen, retry"}
            

            $StarfaceURL = ("https://"+$StarfaceFQDN+"/rest/login")
            $SFLogin = try{Invoke-RestMethod -Method get -uri $StarfaceURL}
            catch
            {
                write-host "Connection with given Hostname ist not Possible :( "
                Remove-Item -Path "$ENV:temp\SWAGGER" -Recurse -Force -ErrorAction Ignore
                New-Item -Path "$ENV:temp" -Name "SWAGGER" -ItemType Directory -Force
                return $Null
            }

            try{Invoke-RestMethod -Method get -uri $StarfaceURL} catch{"login with given URI not Possible! :("; return Start-InitStarfaceAPI -logout}
            
            
            if($Credential -eq $Null){
                
                $Credential = try{((Import-Clixml "$ENV:temp\SWAGGER\APIOBJ.TMP").Credentials)}catch{return "No Creds Given :("}
                if($Credential -eq $Null){
                    $Credential = Get-Credential -Message "Enter Creds Please !"
                }
            }
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            ##
            $PasswordHashed = ConvertTo-SHA512 $Password

            $HashString = ConvertTo-SHA512 ($Credential.UserName + $SFLogin.nonce + $PasswordHashed)

            $HashString = $Credential.UserName + ":" + $HashString


            $BodyLogin = @{
            "loginType"="Internal";
            "nonce"=$SFLogin.nonce;
            "secret"=$HashString
            } | ConvertTo-Json

            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add('Content-Type','application/json')
            $headers.Add('X-Version','2')



            $logintoken = (Invoke-RestMethod -Uri $StarfaceURL -Body $BodyLogin -Headers $headers -Method Post).token

            $APIObj.logintoken = $LoginToken
            $APIObj.Retention = (Get-Date).AddHours(3.5)
            $APIObj | Export-Clixml "$ENV:temp\SWAGGER\APIOBJ.TMP" 


            return $APIObj


        }

    
    }
   Process {
        if($APIObj.Retention -le (Get-Date)){Return "Session retent, please Login Again with Start-InitStarfaceAPI "}
        if($Type){
           $APIURL = "https://"+$APIObj.Instancename+"/rest"+$PSBoundParameters.Call.replace("{userId}",$UserID).replace("{permissionId}",$permissionId).replace("{voicemailboxid}",$voicemailboxid).replace("{redirectId}",$redirectId).replace("{contactId}",$contactId).replace("{groupid}",$groupid).replace("{conferenceId}",$conferenceId).replace("{phoneId}",$phoneId).replace('{fkSetId}',$fkSetId).replace('{fmcId}',$fmcId).replace('{tagId}',$tagId).replace('{serviceId}',$serviceId).replace('{phoneNumberId}',$phoneNumberId)
           
           $header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
           $header.Add('Content-Type','application/json')
           $header.Add('X-Version','2')
           $header.Add('authToken',$APIObj.logintoken)

           if($Type -like "Get"){

            return Invoke-RestMethod -Method Get -Headers $header -uri $APIURL
           }
           if($Type -like "Put"){
            write-host $Body
            return Invoke-RestMethod -Method Put -Headers $header -Body $Body -uri $APIURL
           }
           if($Type -like "Post"){

            return Invoke-RestMethod -Method Post -Headers $header -Body $Body -uri $APIURL
           }
           if($Type -like "Delete"){

            return Invoke-RestMethod -Method Delete -Headers $header -uri $APIURL
           }



           
           write-host $APIURL
        }
        

    {


    }
    }

}

function Get-StarfaceUser
{
    param(
    [parameter(Mandatory=$false)][String]$UserID
    )
    process{

        if($UserID){

            $output = (Start-StarfaceAPICall -Type get -call '/users/{userId}' -UserID $UserID)[0]
            return $output
        
        }

        else
        {
             $Output = Start-StarfaceAPICall -Type get -call '/users'
             return $Output
        }
    }




}

function Add-StarfaceUser
{
    param(
        [parameter(Mandatory=$true)][String]$firstName,
        [parameter(Mandatory=$true)][String]$familyName,
        [parameter(Mandatory=$true)][String]$login,
        [parameter(Mandatory=$true)][String]$email,
        [parameter(Mandatory=$false)][String]$faxCallerId,
        [parameter(Mandatory=$false)][Bool]$faxEmailJournal = $False,
        [parameter(Mandatory=$false)][String]$faxHeader,
        [parameter(Mandatory=$false)][Bool]$faxCoverPage = $False,
        [parameter(Mandatory=$false)][String]$language  = "default",
        [parameter(Mandatory=$false)][String]$password = (Get-RandomPassword),
        [parameter(Mandatory=$false)][Bool]$missedCallReport = $False

    )
    begin{
  


      $Body = @{
      "email"= $email;
      "familyName"= $familyName;
      "faxCallerId"= $faxCallerId;
      "faxCoverPage"= $faxCoverPage;
      "faxEmailJournal"= $faxEmailJournal;
      "faxHeader"= $faxHeader;
      "firstName"= $firstName;
      #"id"= 0;
      "language"= $language;
      "login"= $login;
      "missedCallReport"= $missedCallReport;
      "namespace"= $Null;
      "personId"= $Null
      }

      if($password){$Body.add("password",$Password)}

      $Body = $Body | ConvertTo-Json

    }

    process{

    Start-StarfaceAPICall -Type Post -call /users -Body $Body
    return $Body

    }



}

function Set-StarfaceUser 
{
    param(
        
        [parameter(Mandatory=$false)][String]$firstName,
        [parameter(Mandatory=$false)][String]$familyName,
        [parameter(Mandatory=$false)][String]$login,
        [parameter(Mandatory=$false)][String]$email,
        [parameter(Mandatory=$false)][String]$faxCallerId,
        [parameter(Mandatory=$false)][Bool]$faxEmailJournal,
        [parameter(Mandatory=$false)][String]$faxHeader,
        [parameter(Mandatory=$false)][Bool]$faxCoverPage,
        [parameter(Mandatory=$false)][String]$language,
        [parameter(Mandatory=$false)][String]$password ,
        [parameter(Mandatory=$false)][Bool]$missedCallReport,
        [parameter(Mandatory=$false)][String]$UserID,
        [Parameter(ValueFromPipeline)]$DATA


    )
    begin{
 



    }

    process{
    if($UserID){
    
    $DATA = Get-StarfaceUser -UserID $UserID

    }

     $Body = $DATA
     if($firstName){$Body.firstName= $firstName}
      if($familyName){$Body.familyName= $familyName}
      if($login){$Body.login= $login}
      if($email){$Body.email= $email}
      if($faxCallerId){$Body.faxCallerId= $faxCallerId}
      if($faxEmailJournal){$Body.faxEmailJournal= $faxEmailJournal}
      if($faxHeader){$Body.faxHeader= $faxHeader}
      if($faxCoverPage){$Body.faxCoverPage= $faxCoverPage}
      if($language){$Body.language= $language}
      if($password){$Body.password= $password}
      if($missedCallReport){$Body.missedCallReport= $missedCallReport }

      $Body = $Body | ConvertTo-Json

    return Start-StarfaceAPICall -Type Put -call '/users/{userId}' -UserID $DATA.id -Body $Body

    }



}

function Remove-StarfaceUser
{
    param(
        [parameter(Mandatory=$true)][String]$UserID,
        [Parameter(ValueFromPipeline)]$DATA

    )
    begin{
  

    }

    process{

    if($DATA){return Start-StarfaceAPICall -Type Delete -call '/users/{userId}' -UserID $DATA.id}
    else{return Start-StarfaceAPICall -Type Delete -call '/users/{userId}' -UserID $UserID}
    
    

    }



}

function Start-InitStarfaceAPI
{
[CmdletBinding()]
param(

    [Parameter(Mandatory=$false)][Switch] $SaveCreds,
    [Parameter(Mandatory=$false)][Switch] $logout,
    [Parameter(Mandatory=$false)][Switch] $login

)

DynamicParam {

    if ($login) {
        
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $true

        $paramAttributesCollect = New-Object -Type `
            System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        
        $dynParam1 = New-Object -Type `
        System.Management.Automation.RuntimeDefinedParameter("Credentials", [System.Management.Automation.PSCredential],
            $paramAttributesCollect)
        $dynParam2 = New-Object -Type `
        System.Management.Automation.RuntimeDefinedParameter("StarfaceFQDN", [String],
            $paramAttributesCollect)

        $paramDictionary = New-Object `
            -Type System.Management.Automation.RuntimeDefinedParameterDictionary
        $paramDictionary.Add("StarfaceFQDN", $dynParam2) 
        $paramDictionary.Add("Credentials", $dynParam1)
             
    }

    return $paramDictionary
}


begin{

$JsonData = '{
  "swagger": "2.0",
  "info": {
    "version": "0.9.3",
    "title": "STARFACE Rest Api",
    "description": "A Rest API for STARFACE",
    "termsOfService": "https://www.starface.com/agb/",
    "license": {
      "name": "STARFACE proprietary license",
      "url": "http://www.starface.com"
    }
  },
  "consumes": [
    "application/json"
  ],
  "produces": [
    "application/json"
  ],
  "schemes": [
    "https",
    "http"
  ],
  "paths": {
    "/conferenceConfiguration/defaults": {
      "get": {
        "operationId": "getDefaultTexts",
        "summary": "Fetch the texts for conference emails",
        "description": "Fetch the texts for conference emails",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "locale",
            "in": "query",
            "description": "locale for default text",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "ConferenceConfigurationTexts with default text in given locale",
            "schema": {
              "$ref": "#/definitions/ConferenceConfigurationTexts"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/groups": {
      "post": {
        "operationId": "createGroup",
        "summary": "Create a new group",
        "description": "Create a STARFACE group.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "group",
            "in": "body",
            "description": "Group to save.",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Group"
            }
          }
        ],
        "responses": {
          "204": {
            "description": "OK. Group created."
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "get": {
        "operationId": "getGroups",
        "summary": "Retrieve a list of groups",
        "description": "Retrieve a list of STARFACE groups.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "searchTerm",
            "in": "query",
            "description": "The searchTerm to query groups.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. A list of accessable groups",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/GroupListItem"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "saveGroup",
        "summary": "Save a group",
        "description": "Save a STARFACE group.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "group",
            "in": "body",
            "description": "Group to save.",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Group"
            }
          }
        ],
        "responses": {
          "204": {
            "description": "OK. Group saved."
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/phonenumberconfig/phonenumbers/{phoneNumberId}": {
      "get": {
        "operationId": "getPhoneNumberAssignment",
        "summary": "Fetches the PhoneNumberAssignment",
        "description": "Fetches the PhoneNumberAssignment for the corresponding {phoneNumberId} of the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          },
          {
            "name": "phoneNumberId",
            "in": "path",
            "description": "Id of the PhoneNumber thats is assigned to the User with the given {userId}",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "Ok. Returning the PhoneNumberAssignment for the corresponding {phoneNumberId} of the User with the given {userId}",
            "schema": {
              "$ref": "#/definitions/PhoneNumberAssignment"
            }
          },
          "400": {
            "description": "Unexpected error",
            "schema": {
              "$ref": "#/definitions/PhoneNumberAssignment"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "delete": {
        "operationId": "deletePhoneNumberAssignment",
        "summary": "Deletes the PhoneNumberAssignment",
        "description": "Deletes the PhoneNumberAssignment from the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          },
          {
            "name": "phoneNumberId",
            "in": "path",
            "description": "Id of the PhoneNumber that gets unassigned from the User with the given {userId}",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "204": {
            "description": "No Content. The PhoneNumber with the given {phoneNumberId} has successfully been unassigned from the User"
          },
          "400": {
            "description": "Unexpected error"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/login": {
      "post": {
        "operationId": "login",
        "summary": "Login to the Rest-Service",
        "description": "This endpoint is used to login to the STARFACE Rest-Service. By providing a template Login-Object from this endpoints GET-Request with the users secret. If the loginType is INTERNAL the secret can be calculated with <login>:SHA512(<loginId><nonce>SHA512(<password>)). For loginType ACTIVE_DIRECTORY the secret will be BASE64(loginId+nonce+password). For security reasons it<s recommended to use HTTPS over HTTP for the login. The returned token must then be used in a HTTP header paramether named \"authToken\" in order to use this login.",
        "parameters": [
          {
            "name": "login",
            "in": "body",
            "description": "Login-Object with the users secret.",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Login"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "login was successful, returning the users authToken",
            "schema": {
              "$ref": "#/definitions/AuthToken"
            }
          },
          "400": {
            "description": "invalid login",
            "schema": {
              "$ref": "#/definitions/AuthToken"
            }
          },
          "500": {
            "description": "Unexpected error",
            "schema": {
              "$ref": "#/definitions/AuthToken"
            }
          }
        }
      },
      "get": {
        "operationId": "getLogin",
        "summary": "Get a template Login-Object filled with loginType and nonce",
        "description": "This endpoint returns a template of an Login-Object that proviedes the loginType required by the Server and a nonce. The template Login-Object can then be used to authorize a user by sending a POST-Request to this endpoint providing the users secret. See the description of this endpoind<s POST-Request on how to derive the secret from a users loginId and password.",
        "responses": {
          "200": {
            "description": "A template Login-Object",
            "schema": {
              "$ref": "#/definitions/Login"
            }
          },
          "500": {
            "description": "Unexpected error",
            "schema": {
              "$ref": "#/definitions/Login"
            }
          }
        }
      },
      "delete": {
        "operationId": "logout",
        "summary": "invalidate the provided authToken.",
        "description": "User for the given authToken will be logged out. The authToken will be invalidated",
        "parameters": [
          {
            "name": "authToken",
            "in": "header",
            "description": "the authToken to check",
            "required": true,
            "type": "string"
          }
        ],
        "responses": {
          "204": {
            "description": "If a valid authToken was provided it has just been invalidated"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      }
    },
    "/phonenumbers": {
      "get": {
        "operationId": "getPhoneNumbers",
        "summary": "Retrive a list of all configured PhoneNumbers",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "type",
            "in": "query",
            "description": "filter for the type of the PhoneNumber",
            "required": false,
            "type": "string"
          },
          {
            "name": "assigned",
            "in": "query",
            "description": "filter for only assigned or unassigned PhoneNumbers",
            "required": false,
            "type": "boolean"
          }
        ],
        "responses": {
          "200": {
            "description": "A list of available PhoneNumbers",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PhoneNumber"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/phoneconfig": {
      "get": {
        "operationId": "getPhoneConfig",
        "summary": "Fetch the PhoneConfig",
        "description": "Fetch the PhoneConfig of the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "Ok. Returning the PhoneConfig of the User with the given {userId}",
            "schema": {
              "$ref": "#/definitions/PhoneConfig"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "putPhoneConfig",
        "summary": "Update the PhoneConfig",
        "description": "Update the PhoneConfig of the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "Unexpected error"
          },
          "204": {
            "description": "No Content. The PhoneConfig has been successfully been updated"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/callservices/{serviceId}": {
      "get": {
        "operationId": "getCallService",
        "summary": "Fetch a CallService",
        "description": "Fetch the CallService with the given {serviceId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "serviceId",
            "in": "path",
            "description": "Id of the CallService that will be fetched",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. Returning the CallService object with the given {serviceId}",
            "schema": {
              "$ref": "#/definitions/CallService"
            }
          },
          "404": {
            "description": "Not Found. A CallService with the given {serviceId} was not found",
            "schema": {
              "$ref": "#/definitions/CallService"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/permissions": {
      "get": {
        "operationId": "getPermissions",
        "summary": "Retrieve a list of permissions",
        "description": "Retrieve a list of all existing STARFACE permissions.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "responses": {
          "200": {
            "description": "OK. A list of permissions",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PermissionInfo"
              }
            }
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      }
    },
    "/fmcPhones": {
      "post": {
        "operationId": "postFmcPhone",
        "summary": "Create a new FmcPhone",
        "description": "Create a new FmcPhone",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fmcPhone",
            "in": "body",
            "description": "FmcPhone object to add",
            "required": true,
            "schema": {
              "$ref": "#/definitions/FmcPhone"
            }
          },
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "201": {
            "description": "The FmcPhone has successfully been created"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "get": {
        "operationId": "getFmcPhones",
        "summary": "Retrieve a list of FmcPhones",
        "description": "Retrieve a list of STARFACE IFMC phones for the current user.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "A list of available FmcPhones",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/FmcPhone"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/contacts/tags/{tagId}": {
      "get": {
        "operationId": "getTag",
        "summary": "Fetch a tag",
        "description": "Fetch the tag with the given {tagId} from the addressbook",
        "parameters": [
          {
            "name": "tagId",
            "in": "path",
            "description": "id of the Tag",
            "required": true,
            "type": "string"
          },
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/Tag"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "delete": {
        "operationId": "deleteTag",
        "summary": "Delete a tag",
        "description": "Delete the tag with the given {tagId} from the addressbook",
        "parameters": [
          {
            "name": "tagId",
            "in": "path",
            "description": "id of the Tag",
            "required": true,
            "type": "string"
          }
        ],
        "responses": {
          "204": {
            "description": "tag successfully deleted response"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "putTag",
        "summary": "Update a tag",
        "description": "Updates the tag with the given {tagId} from the addressbook",
        "parameters": [
          {
            "name": "tagId",
            "in": "path",
            "description": "id of the Tag",
            "required": true,
            "type": "string"
          },
          {
            "name": "tag",
            "in": "body",
            "description": "updated tag",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Tag"
            }
          },
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "204": {
            "description": "OK"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/phoneconfig/phones": {
      "post": {
        "operationId": "assignPhone",
        "summary": "Assignes a phone to the User",
        "description": "Assignes a phone to the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "Unexpected error"
          },
          "201": {
            "description": "Created. The phone has successfully been assigned to the User with the given {userId}"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "get": {
        "operationId": "listAssignedPhones",
        "summary": "Fetches a list of assigned phones",
        "description": "Fetches a list of assigned phones for the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "Ok. Returning a list of assigned phones for the User with the given {userId}",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PhoneAssignment"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/avatar": {
      "get": {
        "operationId": "getAvatar",
        "summary": "Fetch the Avatar",
        "description": "Fetch the Avatar of the user with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "image/png",
          "image/jpeg",
          "image/gif"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User thats avatar will be fetched",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. Returning the Avatar of the User with the given {userId}",
            "schema": {
              "type": "string",
              "format": "binary"
            }
          },
          "404": {
            "description": "Not Found. An User with the given {userId} was not found"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "delete": {
        "operationId": "deleteAvatar",
        "summary": "Delete the Avatar",
        "description": "Delete the Avatar of the user with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User thats avatar will be updated",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "204": {
            "description": "No Content. The Avatar of the User with the given {userId} has successfully been deleted"
          },
          "404": {
            "description": "Not Found. An User with the given {userId} was not found"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "putAvatar",
        "summary": "Set the Avatar",
        "description": "Set the Avatar of the user with the given {userId}",
        "consumes": [
          "image/png",
          "image/jpeg",
          "image/gif"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "image",
            "in": "body",
            "description": "Image png",
            "required": true,
            "schema": {
              "type": "string",
              "format": "binary"
            }
          },
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User thats avatar will be updated",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "204": {
            "description": "No Content. The Avatar of the User with the given {userId} has successfully been set"
          },
          "404": {
            "description": "Not Found. An User with the given {userId} was not found"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/phonenumbers/{phoneNumberId}": {
      "get": {
        "operationId": "getPhoneNumber",
        "summary": "Fetch a PhoneNumber",
        "description": "Fetch the PhoneNumber with the given {phoneNumberId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "phoneNumberId",
            "in": "path",
            "description": "Id of the PhoneNumber that will be fetched",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. Returning the PhoneNumber object with the given {phoneNumberId}",
            "schema": {
              "$ref": "#/definitions/PhoneNumber"
            }
          },
          "404": {
            "description": "Not Found. A PhoneNumber with the given {phoneNumberId} was not found",
            "schema": {
              "$ref": "#/definitions/PhoneNumber"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/fmcPhones/{fmcId}": {
      "get": {
        "operationId": "getFmcPhone",
        "summary": "Fetch a FmcPhone",
        "description": "Fetch the FmcPhone with the given {fmcId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fmcId",
            "in": "path",
            "description": "Id of the FmcPhone that will be fetched",
            "required": true,
            "type": "string"
          },
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. Returning the FmcPhone object with the given {fmcId}",
            "schema": {
              "$ref": "#/definitions/FmcPhone"
            }
          },
          "404": {
            "description": "Not Found. A FmcPhone with the given {fmcId} was not found",
            "schema": {
              "$ref": "#/definitions/FmcPhone"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "delete": {
        "operationId": "deleteFmcPhone",
        "summary": "Delete a FmcPhone",
        "description": "Delete the FmcPhone with the given {fmcId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fmcId",
            "in": "path",
            "description": "Id of the FmcPhone that will be deleted",
            "required": true,
            "type": "string"
          },
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "204": {
            "description": "OK. The FmcPhone with the given {fmcId} has successfully been deleted"
          },
          "404": {
            "description": "Not Found. A FmcPhone with the given {fmcId} was not found"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "putFmcPhone",
        "summary": "Update a FmcPhone",
        "description": "Update the FmcPhone with the given {fmcId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fmcId",
            "in": "path",
            "description": "Id of the FmcPhone that will be updated",
            "required": true,
            "type": "string"
          },
          {
            "name": "fmcPhone",
            "in": "body",
            "description": "FmcPhone-Object with updated values that should be applied",
            "required": true,
            "schema": {
              "$ref": "#/definitions/FmcPhone"
            }
          },
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "204": {
            "description": "OK. The FmcPhone with the given {fmcId} has successfully been updated"
          },
          "404": {
            "description": "Not Found. A FmcPhone with the given {fmcId} was not found",
            "schema": {
              "$ref": "#/definitions/FmcPhone"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/contacts/tags": {
      "post": {
        "operationId": "postTag",
        "summary": "Create a new tag",
        "description": "Create a new tag",
        "parameters": [
          {
            "name": "tag",
            "in": "body",
            "description": "tag to add to the system",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Tag"
            }
          },
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "201": {
            "description": "the created tag",
            "schema": {
              "$ref": "#/definitions/Tag"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "get": {
        "operationId": "getTagList",
        "summary": "Retrieve a list of tags",
        "description": "Retrieve a list of tags this user can access.",
        "parameters": [
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          },
          {
            "name": "page",
            "in": "query",
            "description": "The page number for this request",
            "required": false,
            "type": "integer"
          },
          {
            "name": "pagesize",
            "in": "query",
            "description": "The page size to use. Default is 20",
            "required": false,
            "type": "integer"
          },
          {
            "name": "sort",
            "in": "query",
            "description": "The fieldname to sort for",
            "required": false,
            "type": "string"
          },
          {
            "name": "sortdirection",
            "in": "query",
            "description": "The fieldname to order for",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/Tag"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/callservices": {
      "get": {
        "operationId": "getCallServices",
        "summary": "Retrive a list of all available call services",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "type",
            "in": "query",
            "description": "filter for a call service type. If none or an invalid type is provided the type filter will default to FOR_USER_ACCOUNTS",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "A list of available CallServices",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/CallService"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/functionkeysets/{fkSetId}/phone": {
      "put": {
        "operationId": "putFunctionKeySetOnPhone",
        "description": "Provisions a phone with the given function key set",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fkSetId",
            "in": "path",
            "description": "The Id of the FunctionKeySet",
            "required": true,
            "type": "string"
          },
          {
            "name": "phone",
            "in": "query",
            "description": "The phone",
            "required": true,
            "type": "string"
          },
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "Provisions a phone with the given function key set"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/me": {
      "get": {
        "operationId": "usersMeGet",
        "summary": "Get own user",
        "description": "endpoint alias for /users/{userId} of the user that is corrently logged in",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "responses": {
          "200": {
            "description": "OK. Returning the User object of the user that is corrently logged in",
            "schema": {
              "$ref": "#/definitions/User"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/redirects": {
      "get": {
        "operationId": "getRedirects",
        "summary": "Retrieve a list of redirects",
        "description": "Retrieve a list of redirects for the current user.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "A list of available redirects",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/Redirection"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}": {
      "get": {
        "operationId": "getUser",
        "summary": "Fetch a user",
        "description": "Fetch the STARFACE user with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User that will be fetched",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. Returning the User object with the given {userId}",
            "schema": {
              "$ref": "#/definitions/User"
            }
          },
          "404": {
            "description": "Not Found. A User with the given {userId} was not found",
            "schema": {
              "$ref": "#/definitions/User"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "delete": {
        "operationId": "deleteUser",
        "summary": "Delete a user",
        "description": "Delete the STARFACE user with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User that will be deleted",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "204": {
            "description": "No Content. The User with the given {userId} has successfully been deleted"
          },
          "404": {
            "description": "Not Found. An User with the given {userId} was not found"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "putUser",
        "summary": "Update a user",
        "description": "Update the STARFACE user with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User that will be updated",
            "required": true,
            "type": "integer"
          },
          {
            "name": "user",
            "in": "body",
            "description": "User-Object with updated values that should be applied",
            "required": true,
            "schema": {
              "$ref": "#/definitions/User"
            }
          }
        ],
        "responses": {
          "204": {
            "description": "No Content. The User with the given {userId} has successfully been updated"
          },
          "404": {
            "description": "Not Found. An User with the given {userId} was not found"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/phoneconfig/phones/{phoneId}": {
      "get": {
        "operationId": "getPhoneAssignment",
        "summary": "Fetches the PhoneAssignment",
        "description": "Fetches the PhoneAssignment for the corresponding {phoneId} of the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          },
          {
            "name": "phoneId",
            "in": "path",
            "description": "Id of a phone",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "Ok. Returning the PhoneAssignment for the corresponding {phoneId} of the User with the given {userId}"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "delete": {
        "operationId": "deletePhoneAssignment",
        "summary": "Deletes the PhoneAssignment",
        "description": "Deletes the PhoneAssignment from the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          },
          {
            "name": "phoneId",
            "in": "path",
            "description": "Id of a phone",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "Unexpected error"
          },
          "204": {
            "description": "No Content. The phone with the given {phoneId} has successfully been unassigned from the User"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/conferenceConfiguration": {
      "get": {
        "operationId": "getConferenceConfiguration",
        "summary": "Fetch default values for new managed conferences",
        "description": "Fetch the ConferenceConfiguration",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "responses": {
          "200": {
            "description": "The current setting of conference configuration",
            "schema": {
              "$ref": "#/definitions/ConferenceConfiguration"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "putConferenceConfiguration",
        "summary": "Update the Conference Configuration",
        "description": "Update the given conference configuration by the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "query",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          },
          {
            "name": "conferenceConfiguration",
            "in": "body",
            "description": "conferenceConfiguration",
            "required": true,
            "schema": {
              "$ref": "#/definitions/ConferenceConfiguration"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "OK. The conference configuration has successfully been updated"
          },
          "400": {
            "description": "Validation error"
          },
          "401": {
            "description": "The user with the given account id {userId} does not have Administrator permission"
          },
          "404": {
            "description": "An user with the given account id {userId} could not be found"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      }
    },
    "/functionkeysets/{fkSetId}/phones": {
      "get": {
        "operationId": "getPhonesForFunctionKeySet",
        "description": "Fetch the phones for functionkeyset with the given {fkSetId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fkSetId",
            "in": "path",
            "description": "The Id of the FunctionKeySet",
            "required": true,
            "type": "string"
          },
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "Returning the FunctionKey object with the given {keyId}",
            "schema": {
              "type": "array",
              "items": {
                "type": "string"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/managedConferences/{conferenceId}/start": {
      "put": {
        "operationId": "startManagedConference",
        "summary": "Start ManagedConference",
        "description": "Start the ManagedConference of the User with the given {userId} and {conferenceId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the user",
            "required": true,
            "type": "integer"
          },
          {
            "name": "conferenceId",
            "in": "path",
            "description": "Id of the conference",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "204": {
            "description": "OK. The managed conference with the given conferenceId {conferenceId} has successfully been started"
          },
          "400": {
            "description": "The managed conference with the given conferenceId {conferenceId} is already finished"
          },
          "404": {
            "description": "No managed conference with the given conferenceId {conferenceId} could be found"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      }
    },
    "/functionkeysets/edit/defaults": {
      "get": {
        "operationId": "getEditFunctionKeyDefaults",
        "description": "Returns edit possible edit informations",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "responses": {
          "200": {
            "description": "Returning the EditFunctionKey of all possible keys",
            "schema": {
              "$ref": "#/definitions/EditFunctionKey"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users": {
      "post": {
        "operationId": "postUser",
        "summary": "Create a new user",
        "description": "Create a new STARFACE user",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "user",
            "in": "body",
            "description": "User object to add",
            "required": true,
            "schema": {
              "$ref": "#/definitions/User"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Unexpected error"
          },
          "201": {
            "description": "Created.  User has successfully been created"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "get": {
        "operationId": "getUsers",
        "summary": "Retrieve a list of users",
        "description": "Retrieve a list of STARFACE users the current user can access.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "searchTerm",
            "in": "query",
            "description": "The searchTerm to query users.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. A list of accessable User",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/User"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/functionkeysets/{fkSetId}/": {
      "post": {
        "operationId": "createFunctionKey",
        "description": "Creates a new FunctionKey and appends it to the end of the FunctionKeySet if no position is provided. Otherwise the Functionkey will shift other keys aside.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fkSetId",
            "in": "path",
            "description": "The Id of the FunctionKeySet",
            "required": true,
            "type": "string"
          },
          {
            "name": "functionKey",
            "in": "body",
            "description": "The new functionKey to create",
            "required": true,
            "schema": {
              "$ref": "#/definitions/FunctionKey"
            }
          },
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "201": {
            "description": "The FunctionKey has successfully been created",
            "schema": {
              "$ref": "#/definitions/FunctionKey"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "get": {
        "operationId": "getFunctionKeys",
        "description": "Retrieve the list of FunctionKeys contained in the given FunctionKeySet.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fkSetId",
            "in": "path",
            "description": "The Id of the FunctionKeySet",
            "required": true,
            "type": "string"
          },
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "The list of contained FunctionKeys",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/FunctionKey"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "updateFunctionKeySet",
        "description": "Update the FunctionKeySet with the given {fkSetId}. This operation can be used to reorder the FunctionKeys contained in this set. NOTE keys on phones must be refreshed (GET /{fkSetId}/phones and PUT /{fkSetId}/phone).",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fkSetId",
            "in": "path",
            "description": "The Id of the FunctionKeySet",
            "required": true,
            "type": "string"
          },
          {
            "name": "functionKeys",
            "in": "body",
            "description": "The updated FunctionKeySet to reorder FunctionKeys",
            "required": true,
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/FunctionKey"
              }
            }
          },
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "204": {
            "description": "The FunctionKeySet with the given {fkSetId} has successfully been updated"
          },
          "400": {
            "description": "The FunctionKeySet with the given {fkSetId} has not successfully been updated. Returns the positions of the bad functionkeys in the array",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/FunctionKeySetError"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/phonenumberconfig": {
      "get": {
        "operationId": "getPhoneNumberConfig",
        "summary": "Fetch the PhoneNumberConfig",
        "description": "Fetch the PhoneNumberConfig of the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "Ok. Returning the PhoneNumberConfig of the User with the given {userId}",
            "schema": {
              "$ref": "#/definitions/PhoneNumberConfig"
            }
          },
          "500": {
            "description": "Unexpected error",
            "schema": {
              "$ref": "#/definitions/PhoneNumberConfig"
            }
          }
        }
      },
      "put": {
        "operationId": "putPhoneNumberConfig",
        "summary": "Update the PhoneNumberConfig",
        "description": "Update the PhoneNumberConfig of the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User thats PhoneNumberConfig will be updated",
            "required": true,
            "type": "integer"
          },
          {
            "name": "phoneNumberConfig",
            "in": "body",
            "description": "PhoneNumberConfig-Object with updated values that should be applied",
            "required": true,
            "schema": {
              "$ref": "#/definitions/PhoneNumberConfig"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Ok. Returning the PhoneNumberConfig of the User with the given {userId}",
            "schema": {
              "$ref": "#/definitions/PhoneNumberConfig"
            }
          },
          "500": {
            "description": "Unexpected error",
            "schema": {
              "type": "string"
            }
          }
        }
      }
    },
    "/contacts/scheme": {
      "get": {
        "operationId": "getScheme",
        "summary": "Get the Contact-Scheme",
        "description": "Get the Contact-Scheme",
        "parameters": [
          {
            "name": "lang",
            "in": "query",
            "description": "Language identifiers as specified by RFC 3066 for i18nDisplayName",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/ContactsScheme"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/managedConferences/{conferenceId}": {
      "get": {
        "operationId": "getManagedConference",
        "summary": "Fetch ManagedConference",
        "description": "Fetch the ManagedConference of the User with the given {userId} and {conferenceId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the user",
            "required": true,
            "type": "integer"
          },
          {
            "name": "conferenceId",
            "in": "path",
            "description": "Id of the conference",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "A configured managed conference",
            "schema": {
              "$ref": "#/definitions/ManagedConference"
            }
          },
          "404": {
            "description": "No managed conference with the given conferenceId {conferenceId} could be found"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      },
      "delete": {
        "operationId": "deleteManagedConference",
        "summary": "Delete a managed conference",
        "description": "Delete the managed conference with the given {conferenceId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the user",
            "required": true,
            "type": "integer"
          },
          {
            "name": "conferenceId",
            "in": "path",
            "description": "Id of the conference",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "204": {
            "description": "OK. The managed conference with the given conferenceId {conferenceId} has successfully been deleted"
          },
          "403": {
            "description": "User not allowed to make this change"
          },
          "404": {
            "description": "No managed conference with the given conferenceId {conferenceId} could be found"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      },
      "put": {
        "operationId": "putManagedConference",
        "summary": "Update ManagedConference",
        "description": "Update the ManagedConference of the User with the given {userId} and {conferenceId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the user",
            "required": true,
            "type": "integer"
          },
          {
            "name": "conferenceId",
            "in": "path",
            "description": "Id of the conference",
            "required": true,
            "type": "integer"
          },
          {
            "name": "conference",
            "in": "body",
            "description": "ManagedConference-Object with updated values that should be applied",
            "required": true,
            "schema": {
              "$ref": "#/definitions/ManagedConference"
            }
          }
        ],
        "responses": {
          "204": {
            "description": "OK. The managed conference with the given {conferenceId} has successfully been updated"
          },
          "400": {
            "description": "Validation error"
          },
          "404": {
            "description": "Cannot update. No managed conference with the given conferenceId {conferenceId} could be found"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      }
    },
    "/groups/{groupid}": {
      "get": {
        "operationId": "getGroup",
        "summary": "Retrieve a group with id",
        "description": "Retrieve a STARFACE group.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "groupid",
            "in": "path",
            "description": "Id of the group.",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. A group with id.",
            "schema": {
              "$ref": "#/definitions/Group"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "delete": {
        "operationId": "deleteGroup",
        "summary": "Delete a group with id",
        "description": "Delete a STARFACE group.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "groupid",
            "in": "path",
            "description": "Id of the group.",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "204": {
            "description": "OK. Group deleted"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/contacts/{contactId}": {
      "get": {
        "operationId": "getContact",
        "summary": "Fetch a contact",
        "description": "Fetch the contact with the given {contactId} from the addressbook",
        "parameters": [
          {
            "name": "contactId",
            "in": "path",
            "description": "id of the contact",
            "required": true,
            "type": "string"
          },
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/Contact"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "delete": {
        "operationId": "deleteContact",
        "summary": "Delete a contact",
        "description": "Delete the contact with the given {contactId} from the addressbook",
        "parameters": [
          {
            "name": "contactId",
            "in": "path",
            "description": "id of the contact",
            "required": true,
            "type": "string"
          }
        ],
        "responses": {
          "204": {
            "description": "contact successfully deleted response"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "putContact",
        "summary": "Update a contact",
        "description": "Updates the contact with the given {contactId} from the provided payload",
        "parameters": [
          {
            "name": "contactId",
            "in": "path",
            "description": "id of the contact",
            "required": true,
            "type": "string"
          },
          {
            "name": "contact",
            "in": "body",
            "description": "updated contact",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Contact"
            }
          },
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "204": {
            "description": "OK"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/phoneconfig/phones/{phoneId}/numbers": {
      "get": {
        "operationId": "getNumbersForAssignedPhone",
        "summary": "Fetches a list of NumberForPhoneAssignment",
        "description": "Fetches a list of NumberForPhoneAssignment of the User with the given {userId} and the Phone with the given {phoneId}.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          },
          {
            "name": "phoneId",
            "in": "path",
            "description": "Id of a phone",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "Ok. Returning a list of assigned numbers to the assigned phone with the given {phoneId} for the User with the given {userId}",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/NumberForPhoneAssignment"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "updateNumbersForAssignedPhones",
        "summary": "Updates the list of NumberForPhoneAssignment",
        "description": "Updates the list of NumberForPhoneAssignment of the User with the given {userId} and the Phone with the given {phoneId}. Only the active-flag can be changed. Elements in the list cannot be added or removed.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          },
          {
            "name": "phoneId",
            "in": "path",
            "description": "Id of a phone",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "Unexpected error"
          },
          "204": {
            "description": "No Content. The list of assigned numbers to the assigned phone with the given {phoneId} has been updated successfully."
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/managedConferences": {
      "post": {
        "operationId": "postManagedConference",
        "summary": "Create a new managed conference",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the user",
            "required": true,
            "type": "integer"
          },
          {
            "name": "conference",
            "in": "body",
            "description": "Managed conference object to be created",
            "required": true,
            "schema": {
              "$ref": "#/definitions/ManagedConference"
            }
          }
        ],
        "responses": {
          "201": {
            "description": "The conference has successfully been created"
          },
          "400": {
            "description": "Validation error"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      },
      "get": {
        "operationId": "getManagedConferenceList",
        "summary": "Fetch ManagedConferenceSummaryList",
        "description": "Fetch the ManagedConferenceSummaryList of the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the user",
            "required": true,
            "type": "integer"
          },
          {
            "name": "page",
            "in": "query",
            "description": "The page number for this request. This parameter is 0-indexed. Value 0 returns the first page",
            "required": false,
            "type": "integer"
          },
          {
            "name": "pagesize",
            "in": "query",
            "description": "The page size to use. Default is 20.",
            "required": false,
            "type": "integer"
          },
          {
            "name": "sort",
            "in": "query",
            "description": "The fieldname to sort for.",
            "required": false,
            "type": "string"
          },
          {
            "name": "sortdirection",
            "in": "query",
            "description": "The sort direction. <ASC< for ascending, <DESC< for descending",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "A list of configured managed conferences",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/ManagedConferenceSummary"
              }
            }
          },
          "400": {
            "description": "The sortdirection parameter contains an invalid value"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      }
    },
    "/redirects/{redirectId}": {
      "get": {
        "operationId": "redirectsRedirectIdGet",
        "summary": "Fetch a Redirection",
        "description": "Fetch the Redirection with the given {redirectId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "redirectId",
            "in": "path",
            "description": "Id of the Redirection that will be fetched",
            "required": true,
            "type": "string"
          },
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. Returning the Redirection object with the given {redirectId}",
            "schema": {
              "$ref": "#/definitions/Redirection"
            }
          },
          "404": {
            "description": "Not Found. A Redirection with the given {redirectId} was not found",
            "schema": {
              "$ref": "#/definitions/Redirection"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "redirectsRedirectIdPut",
        "summary": "Update a Redirection",
        "description": "Update the Redirection with the given {redirectId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "redirectId",
            "in": "path",
            "description": "Id of the Redirection that will be updated",
            "required": true,
            "type": "string"
          },
          {
            "name": "redirection",
            "in": "body",
            "description": "Redirection-Object with updated values that should be applied",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Redirection"
            }
          },
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "Unexpected error",
            "schema": {
              "$ref": "#/definitions/Redirection"
            }
          },
          "204": {
            "description": "OK. The Redirection with the given {redirectId} has successfully been updated"
          },
          "404": {
            "description": "Not Found. A Redirection with the given {redirectId} was not found",
            "schema": {
              "$ref": "#/definitions/Redirection"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/functionkeysets/{fkSetId}/{keyId}": {
      "get": {
        "operationId": "getFunctionKey",
        "description": "Fetch the FunctionKey with the given {keyId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fkSetId",
            "in": "path",
            "description": "The Id of the FunctionKeySet",
            "required": true,
            "type": "string"
          },
          {
            "name": "keyId",
            "in": "path",
            "description": "The Id of the FunctionKey",
            "required": true,
            "type": "string"
          },
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "Returning the FunctionKey object with the given {keyId}",
            "schema": {
              "$ref": "#/definitions/FunctionKey"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "delete": {
        "operationId": "deleteFunctionKey",
        "description": "Delete the FunctionKey with the given {keyId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fkSetId",
            "in": "path",
            "description": "The Id of the FunctionKeySet",
            "required": true,
            "type": "string"
          },
          {
            "name": "keyId",
            "in": "path",
            "description": "The Id of the FunctionKey",
            "required": true,
            "type": "string"
          },
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "204": {
            "description": "The FunctionKey with the given {keyId} has successfully been deleted"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "updateFunctionKey",
        "description": "Update the FunctionKey with the given {keyId}. NOTE keys on phones must be refreshed (GET /{fkSetId}/phones and PUT /{fkSetId}/phone).",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fkSetId",
            "in": "path",
            "description": "The Id of the FunctionKeySet",
            "required": true,
            "type": "string"
          },
          {
            "name": "keyId",
            "in": "path",
            "description": "The Id of the FunctionKey",
            "required": true,
            "type": "string"
          },
          {
            "name": "functionKey",
            "in": "body",
            "description": "The new functionKey to create",
            "required": true,
            "schema": {
              "$ref": "#/definitions/FunctionKey"
            }
          },
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "The FunctionKey with the given {keyId} has successfully been updated"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/voicemailboxes/{voicemailboxid}": {
      "get": {
        "operationId": "getVoicemailbox",
        "summary": "Retrieve a voicemailbox with id",
        "description": "Retrieve a list of STARFACE voicemailboxes the current user can access.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "voicemailboxid",
            "in": "path",
            "description": "Id of the voicemailbox.",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. A voicemailbox with id.",
            "schema": {
              "$ref": "#/definitions/Voicemailbox"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "delete": {
        "operationId": "deleteVoicemailbox",
        "summary": "Delete a voicemailbox with id",
        "description": "Delete a STARFACE voicemailbox.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "voicemailboxid",
            "in": "path",
            "description": "Id of the voicemailbox.",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "204": {
            "description": "OK. Voicemailbox deleted"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/permissions/{permissionId}/users": {
      "get": {
        "operationId": "getUsersWithPermission",
        "summary": "Retrieve users with specified permission",
        "description": "Retrieve users which have permission with the given {permissionId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "permissionId",
            "in": "path",
            "description": "Id of the Permission to search",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. Returning the array of users with the given permission",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/User"
              }
            }
          },
          "404": {
            "description": "Not Found. A Permission with the given {permissionId} was not found"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      },
      "put": {
        "operationId": "updatePermissionForUsers",
        "summary": "Update permission for users",
        "description": "Update permission with the given {permissionId} for users specified in usersList. Permission will be granted if \"granted\" parameter established to true and removed if false",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "usersList",
            "in": "body",
            "description": "List of user ids for updating permission with given {permissionId}",
            "required": true,
            "schema": {
              "type": "array",
              "items": {
                "type": "integer"
              }
            }
          },
          {
            "name": "permissionId",
            "in": "path",
            "description": "Id of the Permission",
            "required": true,
            "type": "integer"
          },
          {
            "name": "granted",
            "in": "query",
            "description": "Boolean parameter that define will be permission granted or removed",
            "required": true,
            "type": "boolean"
          }
        ],
        "responses": {
          "200": {
            "description": "Ok. Permissions for the User with the given {userId} has successfully been updated"
          },
          "404": {
            "description": "Not Found. A Permission with the given {permissionId} was not found"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      }
    },
    "/functionkeysets": {
      "get": {
        "operationId": "getFunctionKeySets",
        "summary": "Retrieve a list of FunctionKeySets",
        "description": "Retrieve a list of FunctionKeySets for the current user.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "A list of available FunctionKeySets",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/FunctionKeySet"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/permissions/users/{userId}": {
      "get": {
        "operationId": "getUserPermissions",
        "summary": "Retrieve a list of permissions for user",
        "description": "Retrieve a list of STARFACE permissions for user with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User which persissions will be fetched",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. A list of permissions for user with the given {userId}",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PermissionInfo"
              }
            }
          },
          "404": {
            "description": "Not Found. A User with the given {userId} was not found"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      },
      "put": {
        "operationId": "putUserPermissions",
        "summary": "Update a user<s permissions",
        "description": "Set the STARFACE user<s permissions with the given {userId}. Permissions user had before and not specified in this query will be removed",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User that will be updated",
            "required": true,
            "type": "integer"
          },
          {
            "name": "permissions",
            "in": "body",
            "description": "Array of permission Ids that should be granted to user",
            "required": true,
            "schema": {
              "type": "array",
              "items": {
                "type": "integer"
              }
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Ok. The permissions for user with the given {userId} has successfully been updated"
          },
          "404": {
            "description": "Not Found. An User with the given {userId} was not found"
          },
          "500": {
            "description": "Unexpected error"
          }
        }
      }
    },
    "/accounts": {
      "get": {
        "operationId": "getAccountsList",
        "summary": "Retrieve a list of accounts",
        "description": "Retrieve a list of accounts.",
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/Account"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/phonenumberconfig/phonenumbers/delete": {
      "post": {
        "operationId": "deletePhoneNumberAssignments",
        "summary": "Deletes the PhoneNumberAssignments",
        "description": "Deletes the PhoneNumberAssignments from the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          },
          {
            "name": "phoneNumberAssignments",
            "in": "body",
            "description": "A List of PhoneNumberAssignment-Objects",
            "required": true,
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PhoneNumberAssignment"
              }
            }
          }
        ],
        "responses": {
          "204": {
            "description": "No Content. The PhoneNumbers have successfully been unassigned from the User"
          },
          "400": {
            "description": "Unexpected error"
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/functionkeysets/{fkSetId}/edit/{keyId}": {
      "get": {
        "operationId": "getEditFunctionKey",
        "description": "Returns edit informations for the given key {keyId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "fkSetId",
            "in": "path",
            "description": "The Id of the FunctionKeySet",
            "required": true,
            "type": "string"
          },
          {
            "name": "keyId",
            "in": "path",
            "description": "The Id of the FunctionKey",
            "required": true,
            "type": "string"
          },
          {
            "name": "actOnBehalfOf",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "Returning the EditFunctionKey object with the given {keyId}",
            "schema": {
              "$ref": "#/definitions/EditFunctionKey"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/voicemailboxes": {
      "post": {
        "operationId": "createVoicemailbox",
        "summary": "Create a new voicemailbox",
        "description": "Create a STARFACE voicemailbox.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "voicemailbox",
            "in": "body",
            "description": "Voicemailbox to save.",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Voicemailbox"
            }
          }
        ],
        "responses": {
          "204": {
            "description": "OK. Voicemailbox created."
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "get": {
        "operationId": "getVoicemailboxes",
        "summary": "Retrieve a list of voicemailboxes",
        "description": "Retrieve a list of STARFACE voicemailboxes the current user can access.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "searchTerm",
            "in": "query",
            "description": "The searchTerm to query voicemailboxes.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "OK. A list of accessable voicemailboxes",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/VoicemailboxListItem"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "put": {
        "operationId": "saveVoicemailbox",
        "summary": "Save a voicemailbox",
        "description": "Save a STARFACE voicemailbox.",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "voicemailbox",
            "in": "body",
            "description": "Voicemailbox to save.",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Voicemailbox"
            }
          }
        ],
        "responses": {
          "204": {
            "description": "OK. Voicemailbox saved."
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/phonenumberconfig/phonenumbers/": {
      "post": {
        "operationId": "assignPhoneNumber",
        "summary": "Assignes phone numbers to the User",
        "description": "Assignes phone numbers to the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          },
          {
            "name": "phoneNumberAssignments",
            "in": "body",
            "description": "A List of PhoneNumberAssignment-Objects",
            "required": true,
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PhoneNumberAssignment"
              }
            }
          }
        ],
        "responses": {
          "200": {
            "description": "OK. The phone numbers have successfully been assigned to the User with the given {userId}",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PhoneNumberAssignment"
              }
            }
          },
          "400": {
            "description": "Request error",
            "schema": {
              "type": "string"
            }
          },
          "500": {
            "description": "Server error",
            "schema": {
              "type": "string"
            }
          }
        }
      },
      "get": {
        "operationId": "listPhoneNumberAssignment",
        "summary": "Fetches a list of assigned phone numbers",
        "description": "Fetches a list of assigned phone numbers for the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          }
        ],
        "responses": {
          "200": {
            "description": "Ok. Returning a list of assigned phone numbers for the User with the given {userId}",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PhoneNumberAssignment"
              }
            }
          },
          "400": {
            "description": "Unexpected error",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PhoneNumberAssignment"
              }
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    },
    "/users/{userId}/phonenumberconfig/phonenumbers": {
      "put": {
        "operationId": "updatePhoneNumberAssignments",
        "summary": "Update PhoneNumberAssignments of the User",
        "description": "Update the PhoneNumberAssignment with the given {phoneNumberId} of the User with the given {userId}",
        "consumes": [
          "application/json"
        ],
        "produces": [
          "application/json"
        ],
        "parameters": [
          {
            "name": "userId",
            "in": "path",
            "description": "Id of the User",
            "required": true,
            "type": "integer"
          },
          {
            "name": "phoneNumberAssignments",
            "in": "body",
            "description": "A List of PhoneNumberAssignment-Objects",
            "required": true,
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PhoneNumberAssignment"
              }
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Ok. Returning a list of assigned phone numbers for the User with the given {userId}",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/PhoneNumberAssignment"
              }
            }
          },
          "500": {
            "description": "Unexpected error",
            "schema": {
              "type": "string"
            }
          }
        }
      }
    },
    "/contacts": {
      "post": {
        "operationId": "postContact",
        "summary": "Create a new contact",
        "description": "Create a new contact",
        "parameters": [
          {
            "name": "contact",
            "in": "body",
            "description": "user to add to the system",
            "required": true,
            "schema": {
              "$ref": "#/definitions/Contact"
            }
          },
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "201": {
            "description": "the created contact",
            "schema": {
              "$ref": "#/definitions/Contact"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      },
      "get": {
        "operationId": "getContactList",
        "summary": "Retrieve a list of contacts",
        "description": "Retrieve a list of contacts this user can access.",
        "parameters": [
          {
            "name": "userId",
            "in": "query",
            "description": "Perform an operation on behalf of another user. This requires administrative privileges.",
            "required": false,
            "type": "string"
          },
          {
            "name": "tags",
            "in": "query",
            "description": "comma seperated list of tags to filter for",
            "required": false,
            "type": "array",
            "items": {
              "type": "string"
            }
          },
          {
            "name": "searchTerms",
            "in": "query",
            "description": "the string to search for ... to be defined",
            "required": false,
            "type": "string"
          },
          {
            "name": "page",
            "in": "query",
            "description": "The page number for this request",
            "required": false,
            "type": "integer"
          },
          {
            "name": "pagesize",
            "in": "query",
            "description": "The page size to use. Default is 20",
            "required": false,
            "type": "integer"
          },
          {
            "name": "sort",
            "in": "query",
            "description": "The fieldname to sort for",
            "required": false,
            "type": "string"
          },
          {
            "name": "sortdirection",
            "in": "query",
            "description": "The fieldname to order for",
            "required": false,
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/ContactList"
            }
          },
          "500": {
            "description": "Unexpected error."
          }
        }
      }
    }
  },
  "definitions": {
    "Account": {
      "description": "A basic account.",
      "properties": {
        "accountId": {
          "description": "the accountId of the account",
          "type": "integer"
        },
        "displayInformation": {
          "description": "the displayInformation of the account",
          "type": "string"
        },
        "federationname": {
          "description": "the federationname of the account",
          "type": "string"
        },
        "firstname": {
          "description": "the firstname of the account",
          "type": "string"
        },
        "lastname": {
          "description": "the lastname of the account",
          "type": "string"
        },
        "local": {
          "description": "the account is not an federation account",
          "type": "boolean"
        },
        "primaryInternalPhoneNumber": {
          "description": "the primary internal phone number of the account",
          "type": "string"
        },
        "type": {
          "description": "the type of this account",
          "type": "string",
          "enum": [
            "USER",
            "GROUP",
            "REMOTE_USER",
            "REMOTE_GROUP"
          ]
        }
      },
      "required": [
        "accountId",
        "displayInformation",
        "federationname",
        "firstname",
        "lastname",
        "local",
        "primaryInternalPhoneNumber",
        "type"
      ]
    },
    "AssignableNumber": {
      "description": "A representation of a STARFACE assignableNumber",
      "properties": {
        "assigned": {
          "description": "the assigned option of the assignableNumber",
          "type": "boolean"
        },
        "countryCode": {
          "description": "the countryCode of the assignableNumber",
          "type": "string"
        },
        "exitCode": {
          "description": "the exitCode of the assignableNumber",
          "type": "string"
        },
        "extension": {
          "description": "the extension of the assignableNumber",
          "type": "string"
        },
        "id": {
          "description": "the id of the assignableNumber",
          "type": "integer"
        },
        "intern": {
          "description": "the intern option of the assignableNumber",
          "type": "boolean"
        },
        "localAreaCode": {
          "description": "the localAreaCode of the assignableNumber",
          "type": "string"
        }
      }
    },
    "AssignableUser": {
      "description": "A representation of a STARFACE assignableUser",
      "properties": {
        "assigned": {
          "description": "the assigned option of the assignableUser",
          "type": "boolean"
        },
        "firstname": {
          "description": "the firstname of the assignableUser",
          "type": "string"
        },
        "id": {
          "description": "the id of the assignableUser",
          "type": "integer"
        },
        "lastname": {
          "description": "the lastname of the assignableUser",
          "type": "string"
        }
      }
    },
    "Attribute": {
      "description": "Schlüssel für String internationalisierung. Bei USER_DEFINED wird der der Attributname gezeigt",
      "properties": {
        "additionalValues": {
          "description": "Additional values for this Attribute, for example SHORT_DIAL",
          "type": "object",
          "additionalProperties": {
            "type": "string"
          }
        },
        "displayKey": {
          "type": "string",
          "enum": [
            "NAME",
            "SURNAME",
            "SALUTATION",
            "TITLE",
            "EMAIL",
            "COUNTRY",
            "CITY",
            "STATE",
            "POSTAL_CODE",
            "STREET",
            "URL",
            "COMPANY",
            "MESSENGER",
            "BIRTHDAY",
            "NOTE",
            "JOB_TITLE",
            "PHONE_NUMBER",
            "PRIVATE_PHONE_NUMBER",
            "OFFICE_PHONE_NUMBER",
            "MOBILE_PHONE_NUMBER",
            "FAX_NUMBER",
            "DESCRIPTION",
            "USER_DEFINED"
          ]
        },
        "i18nDisplayName": {
          "description": "Vom Server aufgelöster displayKey in jeweiliger Benutzersprache",
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "value": {
          "type": "string"
        }
      },
      "required": [
        "displayKey",
        "name"
      ]
    },
    "AuthToken": {
      "properties": {
        "token": {
          "type": "string"
        }
      },
      "required": [
        "token"
      ]
    },
    "Block": {
      "description": "Zusammenfassung von Attributen in Blöcke",
      "properties": {
        "attributes": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Attribute"
          }
        },
        "name": {
          "type": "string"
        },
        "resourceKey": {
          "type": "string"
        }
      },
      "required": [
        "attributes"
      ]
    },
    "CallService": {
      "description": "Representation of a call service",
      "properties": {
        "label": {
          "description": "the label of the CallService that is used in the UI",
          "type": "string"
        },
        "serviceId": {
          "description": "the Id of the CallService",
          "type": "integer"
        },
        "serviceName": {
          "description": "the name of the CallService",
          "type": "string"
        }
      },
      "required": [
        "serviceId"
      ]
    },
    "ConferenceConfiguration": {
      "description": "A representation of STARFACE conference configuration",
      "properties": {
        "eMailBody": {
          "type": "string"
        },
        "eMailSubject": {
          "type": "string"
        },
        "externalNumberId": {
          "type": "integer"
        },
        "getLanguage": {
          "type": "string",
          "enum": [
            "en",
            "de",
            "es",
            "fr",
            "nl",
            "pl",
            "sk",
            "default"
          ]
        },
        "internalNumberId": {
          "type": "integer"
        },
        "serverAddress": {
          "type": "string"
        },
        "variables": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/ConferenceConfigurationMailBodyVariable"
          }
        }
      },
      "required": [
        "eMailBody",
        "eMailSubject",
        "getLanguage",
        "variables"
      ]
    },
    "ConferenceConfigurationMailBodyVariable": {
      "description": "A representation of STARFACE managed conference mail body variable",
      "properties": {
        "name": {
          "type": "string"
        },
        "placeholder": {
          "type": "string"
        }
      },
      "required": [
        "name",
        "placeholder"
      ]
    },
    "ConferenceConfigurationTexts": {
      "description": "A representation of STARFACE managed configuration email subject and email body",
      "properties": {
        "eMailBody": {
          "type": "string"
        },
        "eMailSubject": {
          "type": "string"
        }
      },
      "required": [
        "eMailBody",
        "eMailSubject"
      ]
    },
    "Contact": {
      "description": "contact information",
      "properties": {
        "accountId": {
          "type": "integer"
        },
        "blocks": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Block"
          }
        },
        "editable": {
          "type": "boolean"
        },
        "id": {
          "type": "string"
        },
        "jabberId": {
          "type": "string"
        },
        "primaryExternalNumber": {
          "type": "string"
        },
        "primaryInternalNumber": {
          "type": "string"
        },
        "tags": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Tag"
          }
        }
      },
      "required": [
        "blocks",
        "editable",
        "tags"
      ]
    },
    "ContactList": {
      "description": "Bandbreitesparendes Rückgabeobjekt für Liste von Contacts. Einmal Schema für den Summary-Block sowie den Phonenumbers-Block. Die ContactSummary-Daten können mit diesem Schema interpretiert werden.",
      "properties": {
        "contacts": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/ContactSummary"
          }
        },
        "metadata": {
          "$ref": "#/definitions/RequestMetadata"
        },
        "phoneNumbersBlockSchema": {
          "$ref": "#/definitions/Block"
        },
        "summaryBlockSchema": {
          "$ref": "#/definitions/Block"
        }
      },
      "required": [
        "contacts"
      ]
    },
    "ContactSummary": {
      "description": "Kurzusammenfassung der Werte eines Contacts ohne Schema-Information",
      "properties": {
        "additionalValues": {
          "description": "Additional values for the ContactSummary, for example INTERNALPHONE, EXTERNALPHONE, AVATAR",
          "type": "object",
          "additionalProperties": {
            "type": "string"
          }
        },
        "id": {
          "type": "string"
        },
        "phoneNumberValues": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "summaryValues": {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "additionalValues",
        "id",
        "phoneNumberValues",
        "summaryValues"
      ]
    },
    "ContactsScheme": {
      "properties": {
        "detailBlocks": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Block"
          }
        },
        "phoneNumbersBlock": {
          "$ref": "#/definitions/Block"
        },
        "summaryBlock": {
          "$ref": "#/definitions/Block"
        }
      },
      "required": [
        "detailBlocks"
      ]
    },
    "EditFunctionKey": {
      "description": "A representation of a EditFunctionKey Form",
      "properties": {
        "editFunctionKeyBusyLampField": {
          "$ref": "#/definitions/EditFunctionKeyBusyLampField"
        },
        "editFunctionKeyCallList": {
          "$ref": "#/definitions/EditFunctionKeyCallList"
        },
        "editFunctionKeyCcbs": {
          "$ref": "#/definitions/EditFunctionKeyCcbs"
        },
        "editFunctionKeyDnd": {
          "$ref": "#/definitions/EditFunctionKeyDnd"
        },
        "editFunctionKeyDtmf": {
          "$ref": "#/definitions/EditFunctionKeyDtmf"
        },
        "editFunctionKeyForwardCall": {
          "$ref": "#/definitions/EditFunctionKeyForwardCall"
        },
        "editFunctionKeyForwardNumberUnconditional": {
          "$ref": "#/definitions/EditFunctionKeyForwardNumberUnconditional"
        },
        "editFunctionKeyGenericUrl": {
          "$ref": "#/definitions/EditFunctionKeyGenericUrl"
        },
        "editFunctionKeyGroupLogin": {
          "$ref": "#/definitions/EditFunctionKeyGroupLogin"
        },
        "editFunctionKeyModuleActivation": {
          "$ref": "#/definitions/EditFunctionKeyModuleActivation"
        },
        "editFunctionKeyParkAndOrbit": {
          "$ref": "#/definitions/EditFunctionKeyParkAndOrbit"
        },
        "editFunctionKeyPhoneContact": {
          "$ref": "#/definitions/EditFunctionKeyPhoneContact"
        },
        "editFunctionKeyQuickDial": {
          "$ref": "#/definitions/EditFunctionKeyQuickDial"
        },
        "editFunctionKeySeperator": {
          "$ref": "#/definitions/EditFunctionKeySeperator"
        },
        "editFunctionKeySignalNumber": {
          "$ref": "#/definitions/EditFunctionKeySignalNumber"
        }
      }
    },
    "EditFunctionKeyBusyLampField": {
      "description": "A representation of a EditFunctionKeyBusyLampField Form",
      "properties": {
        "availableAccounts": {
          "description": "the available accounts of the FunctionKey",
          "type": "array",
          "items": {
            "$ref": "#/definitions/Account"
          }
        },
        "blfAccountId": {
          "description": "accountId of busy lamp field",
          "type": "integer"
        },
        "blfDisplayInformation": {
          "description": "the display information of the blf accountid",
          "type": "string"
        },
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        },
        "number": {
          "description": "the user telephonenumber of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "blfAccountId",
        "blfDisplayInformation",
        "name",
        "number"
      ]
    },
    "EditFunctionKeyCallList": {
      "description": "A representation of a EditFunctionKeyCallList Form",
      "properties": {
        "callListRequest": {
          "description": "the call list type of the FunctionKey",
          "type": "string",
          "enum": [
            "INCOMING",
            "OUTGOING",
            "MISSED"
          ]
        },
        "callListRequests": {
          "description": "list of possible callListRequests",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "callListRequest",
        "callListRequests",
        "name"
      ]
    },
    "EditFunctionKeyCcbs": {
      "description": "A representation of a EditFunctionKeyCcbs Form",
      "properties": {
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "name"
      ]
    },
    "EditFunctionKeyDnd": {
      "description": "A representation of a EditFunctionKeyDnd Form",
      "properties": {
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "name"
      ]
    },
    "EditFunctionKeyDtmf": {
      "description": "A representation of a EditFunctionKeyDtmf Form",
      "properties": {
        "dtmf": {
          "description": "the dtmf of the FunctionKey",
          "type": "string"
        },
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "dtmf",
        "name"
      ]
    },
    "EditFunctionKeyForwardCall": {
      "description": "A representation of a EditFunctionKeyForwardCall Form",
      "properties": {
        "forwardType": {
          "description": "the forward type allways busy timeout",
          "type": "string",
          "enum": [
            "ALWAYS",
            "BUSY",
            "TIMEOUT"
          ]
        },
        "forwardTypes": {
          "description": "the name of the FunctionKey",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "forwardType",
        "forwardTypes",
        "name"
      ]
    },
    "EditFunctionKeyForwardNumberUnconditional": {
      "description": "A representation of a EditFunctionKeyForwardNumberUnconditional Form",
      "properties": {
        "editFunctionKeyFnuNumberSetting": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/EditFunctionKeyForwardNumberUnconditionalNumberSetting"
          }
        },
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "editFunctionKeyFnuNumberSetting",
        "name"
      ]
    },
    "EditFunctionKeyForwardNumberUnconditionalNumberSetting": {
      "description": "A representation of a EditFunctionKeyForwardNumberUnconditionalNumberSetting Form",
      "properties": {
        "activated": {
          "description": "is number setting activated",
          "type": "boolean"
        },
        "group": {
          "description": "is number setting a group",
          "type": "boolean"
        },
        "number": {
          "description": "the number of the setting",
          "type": "string"
        },
        "numberId": {
          "description": "the numberId of the setting",
          "type": "integer"
        }
      },
      "required": [
        "activated",
        "group",
        "number",
        "numberId"
      ]
    },
    "EditFunctionKeyGenericUrl": {
      "description": "A representation of a EditFunctionKeyGenericUrl Form",
      "properties": {
        "genericURL": {
          "description": "the url of the FunctionKey",
          "type": "string"
        },
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "genericURL",
        "name"
      ]
    },
    "EditFunctionKeyGroupLogin": {
      "description": "A representation of a EditFunctionKeyGroupLogin Form",
      "properties": {
        "editFunctionKeyGlGroupSettings": {
          "description": "the EditFunctionKeyGlGroupSettings of the FunctionKey",
          "type": "array",
          "items": {
            "$ref": "#/definitions/EditFunctionKeyGroupLoginGroupSettings"
          }
        },
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "editFunctionKeyGlGroupSettings",
        "name"
      ]
    },
    "EditFunctionKeyGroupLoginGroupSettings": {
      "description": "A representation of a EditFunctionKeyGroupLoginGroupSettings Form",
      "properties": {
        "activated": {
          "description": "is number setting activated",
          "type": "boolean"
        },
        "groupId": {
          "description": "the groupId",
          "type": "integer"
        },
        "groupname": {
          "description": "the groupname",
          "type": "string"
        }
      },
      "required": [
        "activated",
        "groupId",
        "groupname"
      ]
    },
    "EditFunctionKeyModuleActivation": {
      "description": "A representation of a EditFunctionKeyModuleActivation Form",
      "properties": {
        "editFunctionKeyMaModuleSettings": {
          "description": "the editFunctionKeyMaModuleSettings of the FunctionKey",
          "type": "array",
          "items": {
            "$ref": "#/definitions/EditFunctionKeyModuleActivationModuleSettings"
          }
        },
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "editFunctionKeyMaModuleSettings",
        "name"
      ]
    },
    "EditFunctionKeyModuleActivationModuleSettings": {
      "description": "A representation of a EditFunctionKeyModuleActivationModuleSettings Form",
      "properties": {
        "activated": {
          "description": "is setting activated",
          "type": "boolean"
        },
        "moduleId": {
          "description": "the moduleId of the FunctionKey",
          "type": "string"
        },
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "activated",
        "moduleId",
        "name"
      ]
    },
    "EditFunctionKeyParkAndOrbit": {
      "description": "A representation of a EditFunctionKeyParkAndOrbit Form",
      "properties": {
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        },
        "parkAndOrbitNumber": {
          "description": "the parkAndOrbitNumber of the FunctionKey",
          "type": "string"
        },
        "parkAndOrbitNumbers": {
          "description": "the list of park and orbit numbers",
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "name",
        "parkAndOrbitNumber",
        "parkAndOrbitNumbers"
      ]
    },
    "EditFunctionKeyPhoneContact": {
      "description": "A representation of a EditFunctionKeyPhoneContact Form",
      "properties": {
        "addressbookRequest": {
          "description": "the addressbookRequest of the FunctionKey",
          "type": "string",
          "enum": [
            "CONTACTLIST",
            "CONTACTSEARCH"
          ]
        },
        "addressbookRequests": {
          "description": "the possible request types of the adressbook",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "folders": {
          "description": "the folders of the FunctionKey",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        },
        "selectedFolder": {
          "description": "the selectedFolder of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "addressbookRequest",
        "addressbookRequests",
        "folders",
        "name",
        "selectedFolder"
      ]
    },
    "EditFunctionKeyQuickDial": {
      "description": "A representation of a EditFunctionKeyQuickDial Form",
      "properties": {
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        },
        "number": {
          "description": "the user telephonenumber of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "name",
        "number"
      ]
    },
    "EditFunctionKeySeperator": {
      "description": "A representation of a EditFunctionKeySeperator Form",
      "properties": {
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        }
      },
      "required": [
        "name"
      ]
    },
    "EditFunctionKeySignalNumber": {
      "description": "A representation of a EditFunctionKeySignalNumber Form",
      "properties": {
        "name": {
          "description": "the name of the FunctionKey",
          "type": "string"
        },
        "phoneNumber": {
          "description": "the phoneNumber of the FunctionKey",
          "type": "string"
        },
        "phoneNumberId": {
          "description": "the phoneNumberId of the FunctionKey",
          "type": "integer"
        },
        "possibleSignalnumbers": {
          "description": "the possible signal phonenumbers",
          "type": "array",
          "items": {
            "$ref": "#/definitions/PhoneNumber"
          }
        }
      },
      "required": [
        "name",
        "phoneNumber",
        "phoneNumberId",
        "possibleSignalnumbers"
      ]
    },
    "FmcPhone": {
      "description": "A representation of an FmcPhone",
      "properties": {
        "active": {
          "description": "whether this FmcPhone is activated or deactivated",
          "type": "boolean"
        },
        "confirm": {
          "description": "whether the user must confirm a call with the FmcPhone",
          "type": "boolean"
        },
        "delay": {
          "description": "defines the delay before the FmcPhone is called",
          "type": "integer"
        },
        "fmcSchedule": {
          "description": "List of TimeFrames that define when this FmcPhone is called",
          "type": "array",
          "items": {
            "$ref": "#/definitions/TimeFrame"
          }
        },
        "id": {
          "description": "the Id of the FmcPhone",
          "type": "string"
        },
        "number": {
          "description": "the number that will be called",
          "type": "string"
        },
        "telephoneId": {
          "description": "the Id of the corresponding telephone",
          "type": "string"
        }
      },
      "required": [
        "active",
        "confirm",
        "delay",
        "fmcSchedule",
        "id",
        "number"
      ]
    },
    "FunctionKey": {
      "description": "A representation of a FunctionKey",
      "properties": {
        "accountId": {
          "description": "the accountId of the FunctionKey",
          "type": "string"
        },
        "activateModuleIds": {
          "description": "Modules to activate",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "addressBookFolderName": {
          "description": "AddressBookFolderName",
          "type": "string"
        },
        "addressbookRequest": {
          "description": "Type of AddressbookRequest",
          "type": "string",
          "enum": [
            "CONTACTLIST",
            "CONTACTSEARCH"
          ]
        },
        "blfAccountId": {
          "description": "AccountId of busy lamp field",
          "type": "integer"
        },
        "callListRequest": {
          "description": "Type of requested list",
          "type": "string",
          "enum": [
            "INCOMING",
            "OUTGOING",
            "MISSED"
          ]
        },
        "directCallTargetnumber": {
          "description": "Number to call",
          "type": "string"
        },
        "displayNumberId": {
          "description": "Displaynumberid to signal",
          "type": "integer"
        },
        "dtmf": {
          "description": "Dtmf to send",
          "type": "string"
        },
        "forwardType": {
          "description": "Type of forward",
          "type": "string",
          "enum": [
            "ALWAYS",
            "BUSY",
            "TIMEOUT"
          ]
        },
        "functionKeyType": {
          "description": "The type of the FunctionKey determining the concrete FunctionKey implementation",
          "type": "string",
          "enum": [
            "SIGNALNUMBER",
            "SEPARATOR",
            "QUICKDIAL",
            "PHONEGENERICURL",
            "PHONEDTMF",
            "ADDRESSBOOK",
            "PHONECALLLIST",
            "PARKANDORBIT",
            "MODULEACTIVATION",
            "GROUPLOGIN",
            "FORWARDNUMBER",
            "FORWARD",
            "DONOTDISTURB",
            "COMPLETIONOFCALLSTOBUSYSUBSCRIBER",
            "BUSYLAMPFIELD"
          ]
        },
        "genericURL": {
          "description": "generic URL to send",
          "type": "string"
        },
        "groupIds": {
          "description": "Groupids to activate or deactivate",
          "type": "array",
          "items": {
            "type": "integer"
          }
        },
        "id": {
          "description": "the Id of the FunctionKey",
          "type": "string"
        },
        "name": {
          "description": "the display name of the FunctionKey",
          "type": "string"
        },
        "poNumber": {
          "description": "Number of park and orbit position",
          "type": "string"
        },
        "position": {
          "description": "the position of the FunctionKey wthin its FunctionKeySet",
          "type": "integer"
        },
        "redirectNumberIds": {
          "description": "NumberIds to redirect",
          "type": "array",
          "items": {
            "type": "integer"
          }
        }
      },
      "required": [
        "accountId",
        "functionKeyType",
        "id",
        "name",
        "position"
      ]
    },
    "FunctionKeySet": {
      "description": "An ordered set of FunctionKeys that can be used for changing the order of FunctionKeys",
      "properties": {
        "id": {
          "description": "the Id of the FunctionKeySet",
          "type": "string"
        },
        "keyOrder": {
          "description": "List of Ids of contained FunctionKeys. The ordering of this List defines the positioning of the FunctionKeys.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "name": {
          "description": "the name of the FunctionKeySet",
          "type": "string"
        }
      },
      "required": [
        "id",
        "keyOrder",
        "name"
      ]
    },
    "FunctionKeySetError": {
      "description": "Error informations about a function key that is saved",
      "properties": {
        "errorField": {
          "description": "the wrong filled field",
          "type": "string"
        },
        "functionKeyErrorType": {
          "description": "the error type ( DUBLICATE or CORRUPT )",
          "type": "string",
          "enum": [
            "DUPLICATE",
            "CORRUPT"
          ]
        },
        "position": {
          "description": "the keyposition",
          "type": "integer"
        }
      },
      "required": [
        "errorField",
        "functionKeyErrorType",
        "position"
      ]
    },
    "Group": {
      "description": "A representation of a STARFACE group",
      "properties": {
        "assignableNumbers": {
          "description": "the assignableNumbers of the group",
          "type": "array",
          "items": {
            "$ref": "#/definitions/AssignableNumber"
          }
        },
        "assignableUsers": {
          "description": "the assignableUsers of the group",
          "type": "array",
          "items": {
            "$ref": "#/definitions/AssignableUser"
          }
        },
        "chatGroup": {
          "description": "the chatGroup option of the group",
          "type": "boolean"
        },
        "groupId": {
          "description": "the groupId of the group",
          "type": "string"
        },
        "id": {
          "description": "the id of the group",
          "type": "integer"
        },
        "name": {
          "description": "the name of the group",
          "type": "string"
        },
        "voicemail": {
          "description": "the voicemail option of the group",
          "type": "boolean"
        }
      }
    },
    "GroupListItem": {
      "description": "A representation of a STARFACE group list item",
      "properties": {
        "groupexternalnumber": {
          "description": "the external number of the group",
          "type": "string"
        },
        "groupinternalnumber": {
          "description": "the internal number of the group",
          "type": "string"
        },
        "groupname": {
          "description": "the name of the group",
          "type": "string"
        },
        "id": {
          "description": "the id of the group",
          "type": "integer"
        }
      }
    },
    "Login": {
      "properties": {
        "loginType": {
          "type": "string",
          "enum": [
            "Internal",
            "ActiveDirectory"
          ]
        },
        "nonce": {
          "type": "string"
        },
        "secret": {
          "type": "string"
        }
      },
      "required": [
        "loginType",
        "nonce"
      ]
    },
    "ManagedConference": {
      "description": "A representation of a STARFACE conference",
      "properties": {
        "conferenceId": {
          "type": "integer"
        },
        "eMailBody": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "occurrence": {
          "type": "string",
          "enum": [
            "ONCE",
            "EVERYDAY",
            "EVERYWEEK",
            "EVERYMONTH"
          ]
        },
        "participants": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/ManagedConferenceParticipant"
          }
        },
        "startTime": {
          "type": "integer",
          "format": "int64"
        }
      },
      "required": [
        "eMailBody",
        "name",
        "occurrence",
        "startTime"
      ]
    },
    "ManagedConferenceParticipant": {
      "description": "A representation of STARFACE managed conference participant",
      "properties": {
        "callOnStart": {
          "type": "boolean"
        },
        "displayName": {
          "type": "string"
        },
        "eMailAddress": {
          "type": "string"
        },
        "isModerator": {
          "type": "boolean"
        },
        "participantId": {
          "type": "integer"
        },
        "phoneNumber": {
          "type": "string"
        },
        "userId": {
          "type": "integer"
        }
      },
      "required": [
        "callOnStart",
        "displayName",
        "isModerator",
        "phoneNumber",
        "userId"
      ]
    },
    "ManagedConferenceSummary": {
      "description": "A representation of STARFACE managed conference summary",
      "properties": {
        "conferenceId": {
          "type": "integer"
        },
        "isActive": {
          "type": "boolean"
        },
        "isReadonly": {
          "type": "boolean"
        },
        "isTerminated": {
          "type": "boolean"
        },
        "name": {
          "type": "string"
        },
        "startTime": {
          "type": "integer",
          "format": "int64"
        }
      },
      "required": [
        "conferenceId",
        "isActive",
        "isReadonly",
        "isTerminated",
        "name",
        "startTime"
      ]
    },
    "NumberForPhoneAssignment": {
      "description": "Representation of an assignment from a PhoneNumber to a Phone.",
      "properties": {
        "active": {
          "description": "the flag that indicates whether the PhoneNumber is active for this assignment.",
          "type": "boolean"
        },
        "phoneNumber": {
          "description": "The number of the PhoneNumber",
          "type": "string"
        },
        "phoneNumberId": {
          "description": "the Id of the PhoneNumber that is assigned",
          "type": "integer"
        }
      },
      "required": [
        "active",
        "phoneNumber",
        "phoneNumberId"
      ]
    },
    "PermissionInfo": {
      "description": "Representation of permission that can be granted to a User",
      "properties": {
        "description": {
          "description": "description of the permission",
          "type": "string"
        },
        "id": {
          "description": "Id of the permission",
          "type": "integer"
        },
        "permission": {
          "description": "name of the permission",
          "type": "string"
        }
      }
    },
    "PhoneAssignment": {
      "description": "Representation of an assignment from a Phone to a User",
      "properties": {
        "active": {
          "description": "the flag that indicates whether the Phone is active for the User. Inactive Phones won<t ring on incoming calls.",
          "type": "boolean"
        },
        "isIFMC": {
          "description": "the flag that indicates whether the assigned Phone is a STARFACE iFMC Phone",
          "type": "boolean"
        },
        "phoneId": {
          "description": "the Id of the Phone that is assigned to the User",
          "type": "integer"
        },
        "phoneName": {
          "description": "The name of the Phone that is assigned to the User.",
          "type": "string"
        },
        "userId": {
          "description": "the Id of the User",
          "type": "integer"
        }
      },
      "required": [
        "active",
        "isIFMC",
        "phoneId",
        "phoneName",
        "userId"
      ]
    },
    "PhoneConfig": {
      "description": "Representation of phone config options for a User",
      "properties": {
        "callWaiting": {
          "description": "the flag that indicates whether a call gets rejected if the User is currently busy",
          "type": "boolean"
        },
        "displayNumberId": {
          "description": "the Id of the PhoneNumber that is displayed when the User makes a call",
          "type": "integer"
        },
        "doNotDisturb": {
          "description": "the flag that indicates whether the user is DND and thus won<t recieve calls",
          "type": "boolean"
        },
        "primaryPhoneId": {
          "description": "the Id of the primary Phone of the User",
          "type": "integer"
        }
      },
      "required": [
        "callWaiting",
        "displayNumberId",
        "doNotDisturb",
        "primaryPhoneId"
      ]
    },
    "PhoneNumber": {
      "description": "A representation of a phone number",
      "properties": {
        "assignedGroupAccountId": {
          "description": "the id of the account this phone number is assigned to or null if it is not assigned to an account",
          "type": "integer"
        },
        "assignedModuleInstanceId": {
          "description": "the id of the module instance this phone number is assigned to or null if it is not assigned to a module",
          "type": "string"
        },
        "assignedServiceId": {
          "description": "the id of the service this phone number is assigned to or null",
          "type": "integer"
        },
        "assignedUserAccountId": {
          "description": "the id of the account this phone number is assigned to or null if it is not assigned to an account",
          "type": "integer"
        },
        "exitCode": {
          "description": "the exit code of the phone number",
          "type": "string"
        },
        "id": {
          "description": "the Id of the phone number",
          "type": "integer"
        },
        "localPrefix": {
          "description": "the local prefix of the phone number",
          "type": "string"
        },
        "nationalPrefix": {
          "description": "the national prefix of the phone number",
          "type": "string"
        },
        "number": {
          "description": "the number itself (extention)",
          "type": "string"
        },
        "numberBlockId": {
          "description": "the id of the corresponding NumberBlock",
          "type": "integer"
        },
        "type": {
          "description": "the type of the phone number",
          "type": "string",
          "enum": [
            "INVALID",
            "INTERNAL",
            "EXTERNAL",
            "RESERVED",
            "NT",
            "DISPLAY",
            "FXO"
          ]
        }
      },
      "required": [
        "id",
        "number",
        "type"
      ]
    },
    "PhoneNumberAssignment": {
      "description": "Representation of an assignment from a PhoneNumber to a User",
      "properties": {
        "accountId": {
          "description": "the Id of the Account",
          "type": "integer"
        },
        "phoneNumberId": {
          "description": "the Id of the PhoneNumber that is assigned to the User",
          "type": "integer"
        },
        "serviceId": {
          "description": "the Id of the call service rule that is used for this phone number.",
          "type": "integer"
        }
      },
      "required": [
        "accountId",
        "phoneNumberId",
        "serviceId"
      ]
    },
    "PhoneNumberConfig": {
      "description": "Representation of phone number config options for a User",
      "properties": {
        "possibleSignalnumbers": {
          "description": "the possible signal phonenumbers",
          "type": "array",
          "items": {
            "$ref": "#/definitions/PhoneNumber"
          }
        },
        "primaryExternalNumberId": {
          "description": "the Id of the PhoneNumber that is used as the primary external phone number",
          "type": "integer"
        },
        "primaryInternalNumberId": {
          "description": "the Id of the PhoneNumber that is used as the primary internal phone number",
          "type": "integer"
        },
        "signalingNumberId": {
          "description": "the Id of the PhoneNumber that is used as the signaling phone number",
          "type": "integer"
        }
      },
      "required": [
        "possibleSignalnumbers",
        "primaryExternalNumberId"
      ]
    },
    "RedirectDestination": {
      "description": "Abstract base for mailbox and phonenumber destination",
      "properties": {
        "redirectDestinationType": {
          "description": "The type of the RedirectDestination determining the concrete RedirectDestination implementation",
          "type": "string",
          "enum": [
            "MAILBOX",
            "PHONENUMBER"
          ]
        }
      },
      "required": [
        "redirectDestinationType"
      ]
    },
    "RedirectMailboxDestination": {
      "description": "This RedirectDestination will redirect to the mailbox with the given mailboxId",
      "properties": {
        "mailboxId": {
          "type": "string"
        },
        "redirectDestinationType": {
          "description": "The type of the RedirectDestination determining the concrete RedirectDestination implementation",
          "type": "string",
          "enum": [
            "MAILBOX",
            "PHONENUMBER"
          ]
        }
      },
      "required": [
        "mailboxId",
        "redirectDestinationType"
      ]
    },
    "RedirectPhoneNumberDestination": {
      "description": "This RedirectDestination will redirect to a phoneNumber",
      "properties": {
        "phoneNumber": {
          "type": "string"
        },
        "redirectDestinationType": {
          "description": "The type of the RedirectDestination determining the concrete RedirectDestination implementation",
          "type": "string",
          "enum": [
            "MAILBOX",
            "PHONENUMBER"
          ]
        }
      },
      "required": [
        "phoneNumber",
        "redirectDestinationType"
      ]
    },
    "RedirectTrigger": {
      "description": "Abstract base for always, busy and timeout trigger",
      "properties": {
        "redirectTriggerType": {
          "description": "The type of the RedirectTrigger determining the concrete RedirectTrigger implementation",
          "type": "string",
          "enum": [
            "ALWAYS",
            "BUSY",
            "TIMEOUT"
          ]
        }
      },
      "required": [
        "redirectTriggerType"
      ]
    },
    "Redirection": {
      "description": "A representation of a Redirection",
      "properties": {
        "enabled": {
          "description": "Whether this Redirection is enabled or disabled",
          "type": "boolean"
        },
        "groupNumber": {
          "description": "True if the phoneNumber of this Redirection is assigned to a group, false otherwise",
          "type": "boolean"
        },
        "id": {
          "description": "The Id of the Redirection",
          "type": "string"
        },
        "lastMailboxDestination": {
          "$ref": "#/definitions/RedirectMailboxDestination"
        },
        "lastPhoneNumberDestination": {
          "$ref": "#/definitions/RedirectPhoneNumberDestination"
        },
        "phoneNumber": {
          "description": "The phoneNumber that will be handled by this Redirection",
          "type": "string"
        },
        "redirectDestination": {
          "$ref": "#/definitions/RedirectDestination"
        },
        "redirectTrigger": {
          "$ref": "#/definitions/RedirectTrigger"
        }
      },
      "required": [
        "enabled",
        "id",
        "redirectDestination",
        "redirectTrigger"
      ]
    },
    "RequestMetadata": {
      "properties": {
        "page": {
          "description": "Page number",
          "type": "integer"
        },
        "pagesize": {
          "description": "Number of items per page",
          "type": "integer"
        },
        "sort": {
          "description": "Name of the property used for sorting",
          "type": "string"
        },
        "sortdirection": {
          "description": "Sort direction",
          "type": "string",
          "enum": [
            "ASC",
            "DESC"
          ]
        },
        "totalPages": {
          "description": "Number of pages",
          "type": "integer"
        }
      },
      "required": [
        "page",
        "pagesize",
        "sortdirection",
        "totalPages"
      ]
    },
    "Tag": {
      "properties": {
        "alias": {
          "type": "string"
        },
        "id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "owner": {
          "type": "string"
        }
      },
      "required": [
        "name"
      ]
    },
    "TimeFrame": {
      "description": "A TimeFrame defines a TimeRange in 24 hour format between 00:00 and 24:00 for each day of week",
      "properties": {
        "friday": {
          "description": "Enabled on fridays",
          "type": "boolean"
        },
        "monday": {
          "description": "Enabled on mondays",
          "type": "boolean"
        },
        "saturday": {
          "description": "Enabled on saturdays",
          "type": "boolean"
        },
        "sunday": {
          "description": "Enabled on sundays",
          "type": "boolean"
        },
        "thursday": {
          "description": "Eanabled on thursdays",
          "type": "boolean"
        },
        "timeBegin": {
          "description": "The time defining the beginning of the TimeRange (inclusive)",
          "type": "string"
        },
        "timeEnd": {
          "description": "The time defining the end of the TimeRange (inclusive)",
          "type": "string"
        },
        "tuesday": {
          "description": "Enabled on tuesdays",
          "type": "boolean"
        },
        "wednesday": {
          "description": "Enabled on wednesdays",
          "type": "boolean"
        }
      },
      "required": [
        "friday",
        "monday",
        "saturday",
        "sunday",
        "thursday",
        "timeBegin",
        "timeEnd",
        "tuesday",
        "wednesday"
      ]
    },
    "User": {
      "description": "A representation of a STARFACE user",
      "properties": {
        "email": {
          "description": "the email address of the user",
          "type": "string"
        },
        "familyName": {
          "description": "the family name of the user",
          "type": "string"
        },
        "faxCallerId": {
          "description": "the callerId for faxes send by this user",
          "type": "string"
        },
        "faxCoverPage": {
          "description": "whether to send a cover page for faxes send by this user",
          "type": "boolean"
        },
        "faxEmailJournal": {
          "description": "whether the user recieves a email journal of send faxes",
          "type": "boolean"
        },
        "faxHeader": {
          "description": "the header for faxes send by this user",
          "type": "string"
        },
        "firstName": {
          "description": "the name of the user",
          "type": "string"
        },
        "id": {
          "description": "the Id of the user",
          "type": "integer"
        },
        "language": {
          "description": "the language of a user (default, de, en, ...)",
          "type": "string"
        },
        "login": {
          "description": "the login number for this user. The login number will be used as Jabber Id",
          "type": "string"
        },
        "missedCallReport": {
          "description": "whether the user recieves a report on missed calls",
          "type": "boolean"
        },
        "namespace": {
          "description": "the namespace defining the location of an user account",
          "type": "string"
        },
        "password": {
          "description": "defines a new password when a user is created or updated. This field will be empty when a user is fetched.",
          "type": "string"
        },
        "personId": {
          "description": "the Id of the corresponding person contact object",
          "type": "string"
        }
      },
      "required": [
        "email",
        "familyName",
        "firstName",
        "language",
        "login"
      ]
    },
    "VoicemailGroup": {
      "description": "A representation of a STARFACE voicemailbox group",
      "properties": {
        "accountId": {
          "description": "the account id of the voicemailbox group",
          "type": "integer"
        },
        "name": {
          "description": "the name of the voicemailbox group",
          "type": "string"
        },
        "sendMail": {
          "description": "the send mail option of the voicemailbox group",
          "type": "boolean"
        }
      }
    },
    "VoicemailUser": {
      "description": "A representation of a STARFACE voicemailbox user",
      "properties": {
        "accountId": {
          "description": "the account id of the voicemailbox user",
          "type": "integer"
        },
        "name": {
          "description": "the name of the voicemailbox user",
          "type": "string"
        },
        "sendMail": {
          "description": "the send mail option of the voicemailbox user",
          "type": "boolean"
        },
        "voicemailboxName": {
          "description": "the voicemailbox name of the voicemailbox user",
          "type": "string"
        }
      }
    },
    "Voicemailbox": {
      "description": "A representation of a STARFACE voicemailbox",
      "properties": {
        "id": {
          "description": "the id of the voicemailbox",
          "type": "integer"
        },
        "maximumDuration": {
          "description": "the maximumDuration of the voicemailbox in seconds",
          "type": "integer"
        },
        "name": {
          "description": "the name of the voicemailbox",
          "type": "string"
        },
        "noRecord": {
          "description": "the record option of the voicemailbox",
          "type": "boolean"
        },
        "number": {
          "description": "the number of the voicemailbox",
          "type": "string"
        },
        "password": {
          "description": "the password of the voicemailbox",
          "type": "string"
        },
        "voicemailGroups": {
          "description": "the voicemailGroups of the voicemailbox",
          "type": "array",
          "items": {
            "$ref": "#/definitions/VoicemailGroup"
          }
        },
        "voicemailUsers": {
          "description": "the voicemailUsers of the voicemailbox",
          "type": "array",
          "items": {
            "$ref": "#/definitions/VoicemailUser"
          }
        }
      }
    },
    "VoicemailboxListItem": {
      "description": "A representation of a STARFACE voicemailbox list item",
      "properties": {
        "assignedgroups": {
          "description": "the assigned groups of the voicemailbox",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "assignedusers": {
          "description": "the assigned users of the voicemailbox",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "id": {
          "description": "the id of the voicemailbox",
          "type": "integer"
        },
        "mailboxnumber": {
          "description": "the number of the voicemailbox",
          "type": "string"
        },
        "voiceboxname": {
          "description": "the name of the voicemailbox",
          "type": "string"
        }
      }
    }
  }
}' | Convertfrom-Json

$StarfaceFQDN = $PSBoundParameters.StarfaceFQDN
$Credential = $PSBoundParameters.Credentials

}

process{
        try {$APIObj = Import-Clixml "$ENV:temp\SWAGGER\APIOBJ.TMP" -ErrorAction SilentlyContinue}catch{""}

        if($logout){
             Remove-Item -Path "$ENV:temp\SWAGGER" -Recurse -Force -ErrorAction Ignore
             New-Item -Path "$ENV:temp" -Name "SWAGGER" -ItemType Directory -Force
             return $Null
         }
        if($login){
             if($APIiobj.logintoken){return "allready logged in please first logout with -logout"}
             Remove-Item -Path "$ENV:temp\SWAGGER" -Recurse -Force -ErrorAction Ignore
             New-Item -Path "$ENV:temp" -Name "SWAGGER" -ItemType Directory -Force
             if($Credential -eq $Null){return "No Creds Given try again!"}

         }
        

        if($APIObj -eq $Null -and $Login -eq $false)
        {
           return Start-InitStarfaceAPI -login
        }


        if(($APIObj.InstanceName) -and ($APIObj.Credentials) )
        {
                
           return Start-StarfaceAPICall -login -Credential $APIObj.Credentials

        }
         if(($APIObj.Credentials -eq "" -and ($login -eq $False)) -and ($APIObj.Credentials) )
            {
                if($APIObj.InstanceName){
                    
                    return Start-InitStarfaceAPI -login -StarfaceFQDN $APIObj.InstanceName
                }
                else
                {
                    
                    return Start-InitStarfaceAPI -login
                }


            }





        if ($APIObj.StarfaceFQDN){ # Is a User logged in ?
            if($APIObj.Retention -le (Get-Date)){ # When Retention reached
                
                if(($SaveCreds) -and ($APIObj.Credentials -ne $Null)){
                $APIObj.Credentials = $Credential
                Start-StarfaceAPICall -login -Credential $Credential 
                $APIObj | Export-Clixml "$ENV:temp\SWAGGER\APIOBJ.TMP"
                return 0 
                }
                elseif(($APIObj.Credentials -ne $Null)){
                $APIObj.Credentials =  "Null"
                Start-StarfaceAPICall -Login -Credential $Credential 
                $APIObj | Export-Clixml "$ENV:temp\SWAGGER\APIOBJ.TMP"
                return 0 
                }
                Start-StarfaceAPICall
                $APIObj | Export-Clixml "$ENV:temp\SWAGGER\APIOBJ.TMP"
                return 0 
                

            }
            
        }

        else{
        
             Remove-Item -Path "$ENV:temp\SWAGGER" -Recurse -Force -ErrorAction Ignore
             New-Item -Path "$ENV:temp" -Name "SWAGGER" -ItemType Directory -Force
             $APIObj = $Null
             $APIObj = $JsonData
             $APIObj | Add-Member -MemberType NoteProperty -Name "InstanceName" -Value $StarfaceFQDN -Force
             if($SaveCreds){
                $APIObj | Add-Member -MemberType NoteProperty -Name "Credentials" -Value  $Credential
             }
             else{
                $APIObj | Add-Member -MemberType NoteProperty -Name "Credentials" -Value  "Null"
             }
             $APIObj | Add-Member -MemberType NoteProperty -Name "logintoken" -Value $Null
             $APIObj | Add-Member -MemberType NoteProperty -Name "Retention" -Value $Null
             $APIObj | Export-Clixml "$ENV:temp\SWAGGER\APIOBJ.TMP"    
             return Start-StarfaceAPICall -Credential $Credential -Login
        
        }





return $APIObj
}

}

function Get-StarfaceUserPermission
{
Param
  (
       [parameter(Position=0)][String]$UserID,
       [Parameter(ValueFromPipeline)]$DATA 
  )
    process
    {
        if($DATA)
        {
            $OutObj =  Start-StarfaceAPICall -Type Get -call '/permissions/users/{userId}' -UserID $DATA.id
        }
        elseif($UserID)
        {
            $OutObj =  Start-StarfaceAPICall -Type Get -call '/permissions/users/{userId}' -UserID $UserID
        }
        else
        {
            $OutObj =  return Start-StarfaceAPICall -Type Get -call '/permissions'
        }
        
        return $OutObj

    }

}

function Add-StarfaceUserPermission
{
Param
  (
       [parameter(Position=1)][String]$UserID,
       [parameter(Position=0)][ValidateSet(
       "1", 
       "3", 
       "4",
       "5", 
       "6",
       "7",
       "8",
       "9",
       "10",
       "11",
       "13",
       "14",
       "16",
       "17",
       "18",
       "19",
       "22",
       "23",
       "24",
       "25",
       "26",
       "27",
       "28",
       "29",
       "30",
       "31",
       "32",
       "33",
       "34",
       "35",
       "36",
       "38",
       "39",
       "40",
       "41",
       "42",
       "43",
       "45"
       )]$Permissions,
       [Parameter(ValueFromPipeline)]$DATA

  )
    begin
    {
    }
    process
    {
        if($DATA){$UserID = $DATA.id}

        $CurrentPermissions = (Get-StarfaceUser -UserID $UserID | Get-StarfaceUserPermission).id


        foreach ($Permission in $Permissions){
            $Contains = $False
            
            foreach($CurrentPermission in $CurrentPermissions){
                if($CurrentPermission.tostring() -eq $Permissions.tostring()){
                $Contains = $True
                
                }
             
            
            }
            
        if($Contains -eq $False){$CurrentPermissions += $Permission}

        }
    if($Contains){return "No Changes Made"}
    $Body = $CurrentPermissions | ConvertTo-Json

    return Start-StarfaceAPICall -type put -call '/permissions/users/{userId}' -UserID $UserID -Body $Body

    return $OutputObj
    }

}

function Set-StarfaceUserPermission
{
Param
  (
       [parameter(Position=1)][String]$UserID,
       [Switch]$SetDefaultRights,
       [Switch]$SetAdminRights,
       [Parameter(ValueFromPipeline)]$DATA
  )
    begin
    {
    $DefaultRights= @(18,19,22,23,31,1,33,34,3,4,5,6,7,8,40,41,9,10,13,45,14,16,17)
    $AdminRights = @(40,41,45,1,3,4,5,6,7,8,9,10,11,13,14,16,17,18,19,22,23,25,26,27,28,29,30,31,32,33,36)
    }
    process
    {
        if($DATA){$UserID = $DATA.id}

        if($SetDefaultRights){ return Start-StarfaceAPICall -type put -call '/permissions/users/{userId}' -UserID $UserID -Body ($DefaultRights | ConvertTo-Json)}
        if($SetAdminRights){ return Start-StarfaceAPICall -type put -call '/permissions/users/{userId}' -UserID $UserID -Body ($AdminRights | ConvertTo-Json)}

        
    }

}

function Remove-StarfaceUserPermission
{
Param
  (
       [parameter(Position=1)][String]$UserID,
       [parameter(Position=0)][ValidateSet(
       "1", 
       "3", 
       "4",
       "5", 
       "6",
       "7",
       "8",
       "9",
       "10",
       "11",
       "13",
       "14",
       "16",
       "17",
       "18",
       "19",
       "22",
       "23",
       "24",
       "25",
       "26",
       "27",
       "28",
       "29",
       "30",
       "31",
       "32",
       "33",
       "34",
       "35",
       "36",
       "38",
       "39",
       "40",
       "41",
       "42",
       "43",
       "45"
       )]$Permissions,
       [Parameter(ValueFromPipeline)]$DATA

  )
    begin
    {
    }
    process
    {
        if($DATA){$UserID = $DATA.id}

        $CurrentPermissions = (Get-StarfaceUser -UserID $UserID | Get-StarfaceUserPermission).id
        $Body = @()
        
        foreach ($Permission in $Permissions){
            $Contains = $False
            
            foreach($CurrentPermission in $CurrentPermissions){
                if($CurrentPermission.tostring() -eq $Permissions.tostring()){
                $Contains = $True
                
                }
                else
                {
                    $Body += $CurrentPermission
                }
             
            
            }
            
        if($Contains -eq $False){$CurrentPermissions += $Permission}

        }
    if($Contains -ne $True){return "Permission was not Set!"}

    $Body =$Body | ConvertTo-Json
    return Start-StarfaceAPICall -type put -call '/permissions/users/{userId}' -UserID $UserID -Body $Body

    }

}