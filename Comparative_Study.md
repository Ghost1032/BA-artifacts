# Comparative Studies

## APP Hardening techniques of banking apps

We conducted two additional comparative studies to demonstrate our findings are pervasive. The first comparative study is to extend a [2019 survey](https://doi.org/10.1109/EuroSP.2019.00011) against 34 iOS banking apps. We additionally chose 50 banks worldwide, and examined the applied app hardening techniques using the same approach as described in the paper. We tested 100 apps of these banks (50 Android apps and 50 iOS apps), and list the result in [this table](sheets/protection_of_100_banking_apps.csv).

In short, 88% of investigated apps deployed at least one category of app-hardening technique. In comparison, the 2019 survey reported a ratio of 56%. Our study also showed big differences between banking apps in China and other regions: code packer is widely adapted (25/25) in Chinese Android banking apps, while only 9 of 25 non-Chinese banking apps use it. Note that although Apple prohibits a global code obfuscation against the entire executable, a large portion of (15/25, 60%) Chinese iOS banking apps contained a small amount of obfuscated classes in their Mach-O binaries, and we define this case as a *partial* code transformation. This portion is much lower (3/25, 12%) in banking apps from other regions. For the aspects of runtime integrity check, 56/100 apps explicitly prompt users about the status of runtime tampering (i.e., rooted/jailbroken devices), and 61 of them detect the existence of code injection tools.

## Comparative Study of Banking Apps and Other App Categories

We select popular apps in other app categories to check if such critical flaws also existed. The selected 7 apps supported biometric based local authentication and thus we could compare them to the banking apps. Moreover, each app had at least 500 million users by June 2024. 

| App Name | Category | User Number |
| --- | --- | --- |
| Alipay | Lifestyle | 1.3B+ |
| 12306 | Travel | 500M+ |
| QQ | Social Networking | 597M+ |
| Taobao | Shopping | 895M+ |
| Outlook | Productivity | 500M+ |
| Telegram | Social Networking | 1.56B+ |
| LinkedIn | Business | 1B+ |

In comparison, besides the top 10 banks, we additionally chose 7 banks, ranked 12, 17, 18, 19, 22, 28 and 35, each had at least 79 million users by June 2024) to which our authors had a legal user account for the test.

Our investigation re-confirmed our findings against RQ2: each of the 28 apps applied at least one type of app hardening techniques, but we were still able to test them with three oracles, and there was no correlation between the strong security and the used app hardening techniques.

#### Non-Banking Apps

| App       | Android TO-I | Android TO-II | Android TO-III | iOS TO-I | iOS TO-II | iOS TO-III |
|-----------|--------------|---------------|----------------|----------|-----------|------------|
| Telegram  | ⬤           | ⬤            | ◯             | ⬤       | ⬤        | ◯          |
| Alipay    | ⬤           | ⬤            | ◑             | ⬤       | ◑        | ◑          |
| LinkedIn  | ◯           | ⬤            | ⬤             | ◯       | ⬤        | ⬤          |
| Taobao    | ⬤           | ◯            | ◯             | ⬤       | ◑        | ◯          |
| QQ        | ◯           | ◑            | ◑             | ◯       | ⬤        | ◑          |
| 12306     | ⬤           | ⬤            | ◯             | ⬤       | ⬤        | ◯          |
| Outlook   | ⬤           | ◑            | ⬤             | ⬤       | ⬤        | ⬤          |

#### Banking Apps

| Bank | Android TO-I | Android TO-II | Android TO-III | iOS TO-I | iOS TO-II | iOS TO-III |
|------|--------------|---------------|----------------|----------|-----------|------------|
| CMB  | ◯           | ◑            | ◯             | ◯       | ◑        | ◯          |
| PSBC | ⬤           | ◯            | ◯             | ⬤       | ⬤        | ◯          |
| CIB  | ⬤           | ◑            | ◯             | ⬤       | ◑        | ◯          |
| SPDB | ⬤           | ◑            | ⬤             | ⬤       | ◑        | ◯          |
| CITIC| ◯           | ◯            | ◯             | ◯       | ◑        | ◯          |
| CMBC | ◯           | ◯            | ◯             | ⬤       | ◯        | ◯          |
| CEB  | ◯           | ◯            | ◑             | ⬤       | ◑        | ◯          |

- ⬤: Fail to pass the test
- ◑: Partially pass the test
- ◯: Pass the test

We found the implementation correctness among the tested apps are in accord with the result of apps of top 10 banks. The three concerned PSAT-relevant issues were still common in those apps (only the Android apps of CITIC and CMBC passed all tests). Again, we observed no obvious connection between adopting app-hardening techniques and PSAT security. Take the apps of CMB as an example, they were almost immune to all three PSAT-related attacks (only a part of user information would be leaked under a state migration attack), but they did not attempt to detect any runtime tampering, and the iOS app even did not detect code injection. In comparison, the apps of Outlook employed both code obfuscation and runtime integrity check, but were still vulnerable to all three PSAT-related attacks.

As listed in the table, the three PSAT-relevant security issues are much more severe in non-banking apps, while 87.5% of them do not implement biometric authentication correctly. 13 out of 14 do not bind the PSAT to the device, and 9 of them is vulnerable to a complete data migration attack, meaning that a potential attack can take over the account with full access after migration. 4 apps fail to employ ssl-pinning and the essential auth requests can be replayed with a valid token in response.    

