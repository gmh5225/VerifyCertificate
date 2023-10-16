# VerifyCertificate
Verify Certificate In Windows Driver

在驱动中获取数字签名（最好支持cat的）信息，是多么美好和惬意的事。  

开始的时候是在驱动使用openssl，但是这个太复杂和庞大，毕竟不少的代码，各种的算法。  

后来发现了ci.dll.  
无奈的自己的IDA水平太菜，不高，那个结构没有逆向出来，而且函数的参数的个数也没弄好。  
毕竟这个文件太大，且符号文件的信息也少。  

直到后来的某天，一个同事发现了下面的这个仓库。  
本工程修改自：https://github.com/Ido-Moshe-Github/CiDllDemo.git  
反过来，结合本工程，windbg，ida可以更深入的了解ci.dll.  

在应用层有：winVerifyTrust，CertVerifyCertificateChainPolicy，CertGetCertificateChain 等系列函数，  
本仓库都命名VerifyCertificate吧！
