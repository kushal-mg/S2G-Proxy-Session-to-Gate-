@echo off
echo =======================================================
echo   S2G ZERO-TRUST SECURE BROWSER LAUNCHER
echo =======================================================
echo.
echo Make sure the S2G Proxy Dashboard is RUNNING on port 8080!
echo Launching an isolated Chrome instance routed through S2G...
echo.

:: We use an isolated temporary profile so your main Chrome isn't affected.
:: We use ignore-certificate-errors so you don't have to manually install the proxy CA in Windows right now for the demo.
:: Launching to Google Gruyere - a deliberately vulnerable web app by Google designed for security education.
:: Sign in at google-gruyere.appspot.com, then run cookie_stealer_poc.exe to demonstrate the attack + S2G protection.
start "" "chrome.exe" --proxy-server="http=127.0.0.1:8080;https=127.0.0.1:8080" --ignore-certificate-errors --user-data-dir="%TEMP%\s2g_demo_profile" "https://google-gruyere.appspot.com"

echo Browser launched to Google Gruyere (deliberately vulnerable training app).
echo.
echo DEMO STEPS:
echo   1. In the browser: Click 'Sign Up' on Gruyere and create a test account.
echo   2. Once logged in, open DevTools (F12) -^> Application -^> Cookies
echo      You should see GRUYERE_ID with value 'S2G_VAULT_...' (AES-256 encrypted by S2G!)
echo   3. Run cookie_stealer_poc.exe (as Admin) to show an attacker trying to steal cookies.
echo      The stolen value will be encrypted garbage - useless without S2G's key.
echo   4. Run demo_attacker.exe to show a malware process being blocked at the network level.
echo.
pause
