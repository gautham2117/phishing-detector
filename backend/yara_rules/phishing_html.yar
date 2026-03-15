/*
  phishing_html.yar
  YARA rules specifically targeting phishing HTML attachments.
  These detect credential harvesting forms, hidden iframes,
  and obfuscated redirects in HTML files.
*/

rule Phishing_Login_Form
{
    meta:
        description = "Detects HTML login forms with password fields typical of phishing"
        severity    = "HIGH"
        author      = "PhishingDetector"

    strings:
        $form     = "<form" nocase
        $password = "type=\"password\"" nocase
        $password2 = "type='password'" nocase
        $submit   = "type=\"submit\"" nocase
        $submit2  = "type='submit'" nocase

    condition:
        $form and ($password or $password2) and ($submit or $submit2)
}

rule Hidden_iframe_Redirect
{
    meta:
        description = "Detects hidden iframes used for phishing redirects"
        severity    = "CRITICAL"
        author      = "PhishingDetector"

    strings:
        $iframe1 = "<iframe" nocase
        $hidden1 = "display:none" nocase
        $hidden2 = "visibility:hidden" nocase
        $hidden3 = "width=\"0\"" nocase
        $hidden4 = "height=\"0\"" nocase

    condition:
        $iframe1 and any of ($hidden*)
}

rule Credential_Harvesting_Form_Action
{
    meta:
        description = "Detects form actions posting to suspicious external URLs"
        severity    = "CRITICAL"
        author      = "PhishingDetector"

    strings:
        $form   = "<form" nocase
        $action = "action=" nocase
        $http   = "http://" nocase
        $post   = "method=\"post\"" nocase
        $post2  = "method='post'" nocase

    condition:
        $form and $action and $http and ($post or $post2)
}

rule Phishing_Brand_Impersonation
{
    meta:
        description = "Detects brand name impersonation patterns in HTML"
        severity    = "MEDIUM"
        author      = "PhishingDetector"

    strings:
        $paypal    = "paypal" nocase
        $google    = "google" nocase
        $microsoft = "microsoft" nocase
        $apple     = "apple" nocase
        $amazon    = "amazon" nocase
        $login_kw  = "sign in" nocase
        $verify_kw = "verify your" nocase
        $update_kw = "update your" nocase

    condition:
        any of ($paypal, $google, $microsoft, $apple, $amazon) and
        any of ($login_kw, $verify_kw, $update_kw)
}

rule Obfuscated_HTML_Redirect
{
    meta:
        description = "Detects obfuscated JavaScript redirects in HTML"
        severity    = "HIGH"
        author      = "PhishingDetector"

    strings:
        $loc1 = "window.location" nocase
        $loc2 = "document.location" nocase
        $loc3 = "location.href" nocase
        $loc4 = "location.replace" nocase
        $enc1 = "atob(" nocase
        $enc2 = "unescape(" nocase
        $enc3 = "fromCharCode" nocase

    condition:
        any of ($loc*) and any of ($enc*)
}