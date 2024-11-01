# Comparative Studies

## APP Hardening techniques of banking apps

We conducted two additional comparative studies to demonstrate our findings are pervasive. The first comparative study is to extend a [2019 survey](https://doi.org/10.1109/EuroSP.2019.00011) against 34 iOS banking apps. We additionally chose 50 banks worldwide, and examined the applied app hardening techniques using the same approach as described in the paper. We tested 100 apps of these banks (50 Android apps and 50 iOS apps), and list the result in the table below.

| Rank | Android Package Name                      | Code Transformation             | Runtime Integrity Check | Code Injection Detection | iOS Package Name                            | Code Transformation      | Runtime Integrity Check | Code Injection Detection |
|------|-------------------------------------------|---------------------------------|-------------------------|--------------------------|--------------------------------------------|--------------------------|-------------------------|--------------------------|
| 10   | cmb.pb                                    | SecNeo.A                        | -                       | true                     | com.cmbchina.MPBBank                       | -                        | -                       | -                        |
| 12   | com.td                                    | DexGuard                        | -                       | -                        | com.tdbank.iphoneapp                       | -                        | -                       | -                        |
| 13   | com.sovereign.santander                   | partial detected                | -                       | true                     | com.sovereign.santander.us.public..Personal-Banking | -             | exit                    | true                     |
| 14   | com.yitong.mbank.psbc                     | multiple transformation schemes | exit                    | true                     | com.psbc.mobilebank                        | -                        | exit                    | true                     |
| 18   | com.rbc.mobile.android                    | partial detected                | -                       | -                        | com.rbcc.mobile.rlz0                       | -                        | -                       | -                        |
| 19   | com.ecitic.bank.mobile                    | Bangcle                         | alert                   | true                     | com.citic.mobile                           | partial detected         | alert                   | true                     |
| 21   | com.barclays.android.barclaysmobilebanking| partial detected                | -                       | true                     | com.barclaycardus.iphonesvc                | -                        | -                       | true                     |
| 22   | net.bnpparibas.mescomptes                 | partial detected                | -                       | -                        | pl.bgzbnpparibas.gomobile                  | -                        | exit                    | -                        |
| 23   | com.ubs.swidKXJ.android                   | partial detected                | exit                    | -                        | com.ubs.clientMobile                       | -                        | -                       | -                        |
| 26   | com.pingan.paces.ccms                     | multiple transformation schemes | -                       | -                        | com.pingan.creditcard                      | partial detected         | -                       | -                        |
| 28   | com.cib.cibmb                             | Ijiami                          | exit                    | true                     | com.cib.cibmb                              | -                        | exit                    | -                        |
| 29   | com.scotiabank.banking                    | partial detected                | -                       | true                     | com.scotiabank.ccau.mobile                 | -                        | -                       | -                        |
| 30   | com.ing.mobile                            | Verimatrix                      | alert                   | true                     | nl.ing.iphone.app.Bankieren                | -                        | -                       | -                        |
| 31   | cn.com.spdb.mobilebank.per                | Bangcle                         | alert                   | true                     | com.spdb.retail.bank                       | -                        | alert                   | true                     |
| 33   | com.mufgbank.cmc                          | partial detected                | -                       | -                        | com.unionbank.ccm                          | -                        | -                       | -                        |
| 36   | jp.co.smbc.direct                         | partial detected                | exit                    | true                     | jp.co.smbc.direct                          | partial detected         | alert                   | -                        |
| 38   | com.cebbank.mobile.cemb                   | Bangcle                         | alert                   | true                     | com.cebbank.ebank                          | -                        | alert                   | true                     |
| 41   | com.scb.breezebanking.hk                  | partial detected                | exit                    | true                     | com.sc.breezehk                            | -                        | exit                    | true                     |
| 42   | com.latuabancaperandroid                  | partial detected                | -                       | -                        | com.intesasanpaolo.ibiphone                | -                        | -                       | -                        |
| 45   | cn.com.cmbc.newmbank                      | Bangcle                         | exit                    | -                        | com.cmbc.cn.iphone                        | partial detected         | exit                    | -                        |
| 46   | com.rbs.mobile.android.natwest            | partial detected                | -                       | -                        | com.monitise.matm.Monitise-iPhone-NatWest-EN-GB | -                  | -                       | -                        |
| 47   | com.bancomer.mbanking                     | -                               | exit                    | true                     | com.bancomer.bbva.bancomermovil           | -                        | -                       | true                     |
| 52   | fr.creditagricole.androidapp              | partial detected                | exit                    | true                     | fr.creditagricole.monbudget               | -                        | exit                    | -                        |
| 55   | com.cm_prod.bad                           | DexGuard                        | exit                    | true                     | ei.cm.release                             | partial detected         | exit                    | -                        |
| 60   | mobi.societegenerale.mobile.lappli        | partial detected                | -                       | -                        | mobi.societegenerale.mobile.lappli        | -                        | -                       | -                        |
| 62   | com.db.pwcc.dbmobile                      | Verimatrix                      | -                       | true                     | com.db.pbc.ng.mobile                      | -                        | exit                    | true                     |
| 63   | com.kbstar.kbbank                         | partial detected                | -                       | -                        | com.kbstar.global                         | -                        | exit                    | true                     |
| 65   | se.nordea.mobilebank                      | partial detected                | -                       | -                        | com.nordea.mobilebank.se                  | -                        | exit                    | -                        |
| 67   | jp.co.mizuhobank.mizuhoapp                | CrackProof                      | exit                    | true                     | jp.co.mizuhobank.mizuhoapp                | -                        | exit                    | true                     |
| 69   | cn.jsb.china                              | Bangcle                         | alert                   | true                     | cn.jsbchina.iphone                        | partial detected         | alert                   | true                     |
| 70   | com.hxb.mobile.client                     | multiple transformation schemes | alert                   | true                     | com.hxb.mobile.client                     | partial detected         | exit                    | true                     |
| 78   | com.cgbchina.xpt                          | multiple transformation schemes | -                       | true                     | com.gdb.mobilegdb                         | -                        | alert                   | true                     |
| 90   | com.bankofbeijing.mobilebanking           | Ijiami                          | -                       | true                     | 95526.mobi                                | partial detected         | -                       | true                     |
| 93   | com.nbbank                                | Bangcle                         | -                       | true                     | com.nbcb.mobilebank                       | partial detected         | alert                   | true                     |
| 98   | com.cic_prod.bad                          | DexGuard                        | exit                    | true                     | ei.cic.release                            | partial detected         | -                       | true                     |
| 99   | com.bca                                   | DexGuard                        | -                       | -                        | com.bca.bcamobile                         | -                        | -                       | -                        |
| 102  | no.apps.dnbnor                            | partial detected                | exit                    | true                     | no.dnbnor.toolbox                         | -                        | exit                    | true                     |
| 103  | cn.com.shbank.mper                        | Bangcle                         | -                       | true                     | com.BankOfShangHai.1.0                    | partial detected         | exit                    | true                     |
| 104  | com.czbank.mbank                          | Bangcle                         | exit                    | true                     | com.czbank.mbank                          | partial detected         | exit                    | true                     |
| 113  | cn.com.njcb.android.mobilebank            | Bangcle                         | exit                    | true                     | com.njcb.NJCBMobileBank                   | partial detected         | exit                    | true                     |
| 126  | com.danskebank.mobilebank3.dk             | partial detected                | -                       | -                        | com.danskebank.mobilebank3uk              | -                        | -                       | -                        |
| 139  | cn.com.hzb.mobilebank.per                 | multiple transformation schemes | exit                    | true                     | com.hzbank.hzbank.per                     | partial detected         | exit                    | true                     |
| 146  | com.hsbank.mobilebank                     | Bangcle                         | exit                    | true                     | cn.com.hsbank.personal.iphone             | partial detected         | exit                    | true                     |
| 153  | com.magicpoint.mobile.bank                | multiple transformation schemes | -                       | true                     | com.cqrcb.mbank                           | partial detected         | -                       | -                        |
| 165  | cn.com.csbank                             | multiple transformation schemes | -                       | -                        | com.bankofchangsha.directBank             | -                        | alert                   | -                        |
| 174  | com.srcb.pmbank                           | multiple transformation schemes | exit                    | true                     | com.srcb.pmbankiOSClient                  | partial detected         | exit                    | true                     |
| 185  | cn.com.cbhb.mbank.per                     | multiple transformation schemes | alert                   | true                     | com.cbhb.mbank.per                        | partial detected         | alert                  

In short, 88% of investigated apps deployed at least one category of app-hardening technique. In comparison, the 2019 survey reported a ratio of 56%. Our study also showed big differences between banking apps in China and other regions: code packer is widely adapted (25/25) in Chinese Android banking apps, while only 9 of 25 non-Chinese banking apps use it. Note that although Apple prohibits a global code obfuscation against the entire executable, a large portion of (15/25, 60%) Chinese iOS banking apps contained a small amount of obfuscated classes in their Mach-O binaries, and we define this case as a *partial* code transformation. This portion is much lower (3/25, 12%) in banking apps from other regions. For the aspects of runtime integrity check, 56/100 apps explicitly prompt users about the status of runtime tampering (i.e., rooted/jailbroken devices), and 61 of them detect the existence of code injection tools.

## Comparative Study of Banking Apps and Other App Categories

We select popular apps in other app categories to check if such critical flaws also existed. The selected 7 apps supported biometric based local authentication and thus we could compare them to the banking apps. Moreover, each app had at least 500 million users by June 2024. 

| App Name | Category | User Number |
| --- | --- | --- |
| Telegram | Social Networking | 1.56B+ |
| Alipay | Lifestyle | 1.3B+ |
| LinkedIn | Business | 1B+ |
| Taobao | Shopping | 895M+ |
| QQ | Social Networking | 597M+ |
| 12306 | Travel | 500M+ |
| Outlook | Productivity | 500M+ |

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

