/*
  phishing_html.yar
  HTML phishing and credential-harvesting detection rules
*/

rule CredentialHarvestingForm
{
    meta:
        description = "HTML page with password input and external form action"
        severity     = "high"
    strings:
        $pwd    = "type=\"password\""  nocase
        $pwd2   = "type='password'"    nocase
        $form   = "<form"              nocase
        $submit = "type=\"submit\""    nocase
        $http   = "action=\"http"      nocase
    condition:
        ($pwd or $pwd2) and $form and ($submit or $http)
}

rule ObfuscatedJavaScript
{
    meta:
        description = "Obfuscated JavaScript patterns common in phishing kits"
        severity     = "high"
    strings:
        $eval        = "eval("         nocase
        $fromchar    = "fromCharCode"  nocase
        $unescape    = "unescape("     nocase
        $atob        = "atob("         nocase
        $docwrite    = "document.write" nocase
    condition:
        2 of them
}

rule HiddenIframe
{
    meta:
        description = "Hidden iframe used for silent redirection or content injection"
        severity     = "medium"
    strings:
        $iframe  = "<iframe"         nocase
        $dnone   = "display:none"    nocase
        $dnone2  = "display: none"   nocase
        $w0      = "width=\"0\""
        $h0      = "height=\"0\""
    condition:
        $iframe and ($dnone or $dnone2 or $w0 or $h0)
}

rule PhishingKeywords
{
    meta:
        description = "Common phishing page keywords"
        severity     = "low"
    strings:
        $kw1 = "verify your account"   nocase
        $kw2 = "confirm your identity" nocase
        $kw3 = "unusual sign-in"       nocase
        $kw4 = "account suspended"     nocase
        $kw5 = "update your payment"   nocase
        $kw6 = "click here to unlock"  nocase
    condition:
        2 of them
}