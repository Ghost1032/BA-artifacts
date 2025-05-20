# KESTREL

## Artifacts Structure

```
.
├── Android
│   ├── CID-fridafilename.sh            # Script to help configuring Frida's filename 
│   ├── CID-fridaport.sh                # Script to help configuring Frida's port 
│   ├── oracle I-bioHookForAndroid11.js # Frida script for biometric APIs on Android 11 and lower
│   ├── oracle I-bioHookForAndroid12.js # Frida script for biometric APIs on Android 12
│   ├── oracle II-android-migrate.sh    # Script to assist in Android data migration
│   ├── oracle II-fullbackup.sh         # Script to perform a full backup on Android
│   ├── oracle III-mitm.py              # Script for hosting a MitM server to filter/export requests/responses
│   └── oracle III-sslpin[1-4].js       # Frida script to bypass SSL pinning on Android
├── iOS
│   ├── CID-fridafilename.sh            # Script to help configuring Frida's filename 
│   ├── CID-fridaport.sh                # Script to help configuring Frida's port 
│   ├── RIC-iOS-BCbypass.js             # Frida script to bypass BC on iOS devices
│   ├── RIC-iOS-ABCbypass.js            # Frida script to bypass ABC on iOS devices
│   └── mitm.py                         # Script for hosting a MitM server to filter/export requests/responses
│
└── sheets                              # Folder for extended results
```

## Scripts and Tools Description

- **Android/iOS**
  - `CID-fridafilename.sh`: Configures the filename of the Frida  binary when testing CID of an app.
  - `CID-fridaport.sh`: Configures the listening port of Frida when testing CID of an app.
  - `mitm.py`: Hosts a MitM proxy server for further PSAT extraction from requests.
- **Android**
  - `oracle I-bioHookForAndroid11.js` and `oracle I-bioHookForAndroid12.js`:  Hooks for biometric APIs on Android for test oracle I.
  - `oracle II-android-migrate.sh`: Facilitates the migration of app data across different Android devices for test oracle II.
  - `oracle II-fullbackup.sh`: Enables complete backup capabilities for Android devices for test oracle II.
  - `oracle III-sslpin[1-4].js`: Provides methods to disable SSL pinning, enhancing testing capabilities on secure Android applications for test oracle III.
- **iOS Specific**
  - `RIC-iOS-ABCbypass.js` : Frida script used to bypass jailbreak checks for ABC.
  - `RIC-iOS-BCbypass.js` : Frida script used to bypass jailbreak checks for BC.

## Comparative Studies
The comparative studies include the following aspects:
- The deployment of app hardening techniques in 100 banking apps.
- Test results for 7 non-banking apps and 7 additional banking apps.

Details can be found at [here](https://anonymous.4open.science/r/BankApps-0B90/Comparative_Study.md)

## Additional Notes
- For test oracle I,III on iOS, we utilize a hooking framework, [objection](https://github.com/sensepost/objection/).
- For test oracle II on iOS, we utilize [Apps Manager](https://www.tigisoftware.com/) from TIGI Software to backup and restore app's sandbox/Keychain data.
- For BC/ABC app on iOS, we connect to the JavaScript context through Safari hence there's no Frida script for it.
