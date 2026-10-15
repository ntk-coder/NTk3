NTk3 — COMPLETE PROJECT FILES

IMPORTANT: This ZIP contains the complete website project. You do not need to copy code manually.

HOW TO UPDATE YOUR GITHUB PAGES WEBSITE
1. Download this ZIP and extract it.
2. Open your GitHub repository for NTk3 in a browser.
3. Open the repository's main/root folder.
4. Upload the files from this extracted folder: index.html, style.css, script.js, manifest.json, service-worker.js. Upload them to the ROOT of the repository (not inside another folder).
5. If GitHub asks whether to replace existing files, choose to replace them.
6. Commit the changes. Wait a minute or two.
7. Visit https://ntk-coder.github.io/NTk3/ and press Ctrl+Shift+R.
8. If the old design remains, open the website in a private/incognito window once.

KEEP YOUR EXISTING SUPABASE SETUP
- Do not run supabase-setup.sql again if you already configured Supabase and messaging was working.
- The publishable key in script.js is intended for browser use; never put a Supabase service-role/secret key in website code.

FILES
- index.html: page layout
- style.css: visual design
- script.js: sign-in, encryption and messaging behavior
- manifest.json: installable app settings
- service-worker.js: offline/cache behavior
- supabase-setup.sql: reference only; not needed for a visual update

NOTE
The code has been syntax-checked, but the complete live messaging workflow should still be tested with two accounts. This is not a security audit or a guarantee of production-grade end-to-end encryption.
