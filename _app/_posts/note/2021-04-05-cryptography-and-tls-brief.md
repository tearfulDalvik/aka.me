---
layout: post
title: 🔒 密码学小记
category: note
permalink: note/cryptography/
tags: blog_notes
plugin: twemoji lazyload lightense
css: |
  img.inline {
    display: inline-block;
    height: 1em;
    width: auto;
    margin: 0;
    vertical-align: middle;
  }
---

当客户端和服务器建立了安全连接之后，浏览器会显示一个小锁在地址栏旁：![](https://img.akacdn.app/b01839032157c7fd052777df1372388c.png){: .no-lightense .inline}。这时候，你和网页中的所有元素打交道，黑客都是看不到的。如果浏览器检测到了风险，有一些元素没有通过安全的连接发送和接收，浏览器会显示一个醒目的红色感叹号 ![](https://img.akacdn.app/cca179c52eb7eeb8856dd36627baa652.png){: .no-lightense .inline} 来提醒你。  
或者，你掏出新买的手机，输入家里的 Wi-Fi 密码，开始上网。  
这些平凡得理所应当的场景，背后的技术在默默保护我们的信息安全。在这样的小锁后面，计算机系统里都发生了什么呢？

本文的前 11 小节主要记录当前几种密码学的基本概念，其后的小节演示了几种密码学的应用场景。

## 目录
{:.no_toc}
1. Table of contents
{:toc}

## OpenSSL
OpenSSL 是业界中属于商用级别的，具有强鲁棒性的一套用于 TLS 的加密套件。应用程序可以通过调用它来实现大多数的 TLS 算法。
本文将使用 OpenSSL 用作演示。
```powershell
PS C:\> choco install openssl
```
```powershell
PS C:\> openssl version
OpenSSL 1.1.1k  25 Mar 2021
```

## 加密、摘要、数字签名和编码
加密算法旨在将明文通过一定算法变为不可理解的密文，并能通过一定的算法将密文恢复为原文。其中，在原文相同的情况下，随着提供的密钥不同，得到的密文也不同。**加密通常用来保护明文。常见的加密算法有 AES、RCx、RSA（非对称）、ECC（非对称） 系列。**  
  
摘要算法是指将一串不定长度的信息通过一定变换，得到一串固定长度的新信息。只要信息和摘要算法不变，摘要结果就一定一致；反之，如果信息出现了任何变化，摘要的变化将会非常明显。摘要算法不可逆，但可以碰撞。在防碰撞的摘要算法设计中，算法应当更耗时。**摘要通常用在数字签名、生成树、完整性检验、P2P 信息共享、拖时间等场景。常见的摘要算法有 MDx、SHA、RIPEMD、xcrypt、CRC 和 HMAC 系列。**   
  
数字签名指通过私钥，对另一串不定长度的信息的摘要进行加密，得到一串可供任何拥有公钥的人解密的新字符串。请注意，数字签名必须使用非对称加密。**通常用于信任链。常见的数字签名算法有 ECDSA、RSA、SHA 等系列和他们的组合。** 
  
编码则指通过一定的变换，使信息从一种表现形式变成另一种表现形式。这样的变化必须存在逆变换，且逆变换所消耗的计算资源和正向变换应该相当。**通常用于将二进制转换成能够复制、便携的字符串，或者在字符串间转换。常见的编码算法有 BaseX、UTF、ASCII 等系列。** 
  
可见，加密、摘要和签名的使用场景非常直观。通常，生活中加密的目的就是为了保护信息，将自己隐藏起来；摘要的目的就是为了将不定长度的信息变为简短的几个段落；而签名却用于建立信任关系，把自己宣告出去。而编码的名字则相对抽象，可以类比为生活中的翻译：既不能不保护你的信息，也没有别人给你担保，但是却让你能够更方便的传播这些信息了。

## 对称加密
了解对称加密和非对称加密对于理解现代安全算法非常重要。顾名思义，对称加密指的是加密和解密用的同一套密钥；而非对称加密则指通过密钥 A 加密的密文只能通过密钥 B 来解密。  

对称加密有很多种模式，在并行、减少错误扩散、防止主动碰撞攻击等方面进行取舍，通常使用将文本分组的方式实现。典型的加密模式分为流式密码（如：AES-GCM）和块式密码（如：AES-CBC）两种，这两种都是针对每个分组的块密钥而言的。流式不要求文本具有固定长度。块式密码则要求文本块和块密钥具有相对应的长度（不足则补齐）。

通过一定算法演变出每个分组的密钥（即通过算法演变出一堆密钥，分别针对对应的组各搞各的就行了）的加密模式支持并行计算。通过上一个组的加密结果得到下一个组所需的密钥的模式不支持并行计算，因为下一个组的密钥依赖于上一个组的加密结果。

以 `AES（Advanced Encryption Standard）` 为例，AES-GCM 支持并行计算、能提供校验、能防止差分密码攻击，是 AEAD（Authenticated Encryption with Associated Data） 的典型实现（即将加密和摘要结合，同时满足机密性、完整性和认证性），但需要保存 IV（初始化向量）；AES-CBC 则不支持并行计算、并且任何错误将扩散到剩余的块中；AES-ECB 支持并行、错误不会扩散、但在差分密码攻击面前很脆弱。AES 还有很多其他模式，无非继续做做取舍，或者增加特殊的无关变量。具体的模式选择应根据具体的需要而定。

AES 涉及有限域上的乘法运算，本文在[椭圆曲线密码学（ECC）](#椭圆曲线密码学（ECC）)一节将会详细介绍。

对称加密非常常见，也非常容易理解。其中，任意随机数、字符串都可被用来当作密码。只是在某些情况下，加密可能会要求密钥长度是定值，简单的摘要即可确保该密钥长度特性。  

## 非对称加密
非对称加密使用一对密钥，即公钥和私钥。以目前的计算机速度可以轻松通过私钥计算出公钥，但只通过公钥却无法计算出私钥。他俩只能交叉使用，公钥加密的内容只能由私钥解密，而私钥加密的内容只能用公钥解密。

非对称加密在数字签名领域的地位不言而喻。同时，通常还使用非对称加密为对称加密的密钥协商提供保护。数字签名和密钥协商在后文中都有涉及。

使用 OpenSSL 生成一对 ECC 密钥对，生成的结果被 base64 编码：
```powershell
PS C:\> openssl ecparam -name prime256v1 -genkey -noout | tee key.pem
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKEaP4e12IpCJPpT9Flg687NAKmYPw1jzBcV5VCvnJ9foAoGCCqGSM49
AwEHoUQDQgAE92M8zCUKv5AZNBB/0mPCnEzXRinFcXVDTR1RXNwaTgDhsqIYqsm8
GU5XOxnQ733g+0ttlC6xi+zi1qb7vNq7RQ==
-----END EC PRIVATE KEY-----

PS C:\> openssl ec -in .\key.pem -pubout -out pub.pem 2>&1 > $null; cat .\pub.pem
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkfOYhjBzGVTkZMtDMpl71pR1XfHw
frg7h8mbXkbHfIB0Qv4gW3nIUUDJ8a3ipdMAQGkztpOCt2G7CPNMdCvd3w==
-----END PUBLIC KEY-----
```

## 证书和信任链
证书是非对称加密的玩具。可以用于代码签名、TLS 握手、电子邮件签名、VPN 等场景  

证书是一系列信息、公钥和签名的容器，可以被打包成为文件。证书不包含私钥，公钥和其他信息是平等的，通常使用 ASN.1 编码，并保存为 X.509 文件格式。如果要将证书和私钥一起打包，则可以使用 PKCS#12 再次封装。  

首先，个人计算机操作系统都内置了很多根证书(也称 CA：Certificate Authority)。每个人都可以创建根证书，只需要一对公钥和私钥即可。但不是每个人的根证书都被系统默认信任。你可以在 “运行” 窗口中输入 `certlm.msc`，然后在弹出的窗口中依次选择 “凭证” 和 “受信任的根证书授权单位” 看到你的电脑信任的所有根证书颁发单位。

![](){: .lazy data-src="https://img.akacdn.app/4661c0cd5e24f1e60aacbd1a6194e245.png"}

根证书是证书的起点，一般由顶级的互联网公司掌握。在向这些机构申请证书时，会被要求提供相关的证明才能获取到他们的签名。出于安全和效率的目的，通常不直接向根证书机构申请，而是通过中间 CA 来进行颁发。中间 CA 可以继续给其他机构颁发中间 CA 证书，也可以颁发最后的叶子证书。  

在申请叶子证书时，需要准备一份 CSR(Certificate Signing Request)，发送给中间证书申请机构。在生成 CSR 的同时，你的私钥也同时生成了。CSR 包含你的公钥和相关信息，全部明文保存，但是最后要加上你刚生成的私钥对这些信息的签名，使用 ASN.1 编码，并通过 PKCS#10 封装。将 CSR 发送给颁发机构，机构核实你的身份、签名、在明文信息中加入自己的名称（颁发机构栏）并使用机构自己的私钥签名替换你的签名后，你就得到可以使用的 X.509 证书。  

以上，就是证书信任链的产生方式。当你拿出你的证书时，别人只需要根据颁发机构证书的序列号去自己的 CA 库找到机构的公钥，解密签名，并和明文部分的摘要对比即可知道你的证书是否真实。如果涉及中间证书，你需要同时把中间证书交给别人，别人使用中间证书中的公钥验证你的证书的签名。如果还有其他中间证书就以此类推，最后又用在 CA 库中查找到的 CA 证书去验证最后一张中间证书的签名即可。无论中间有多少层中间证书，该信任链都非常坚固。但是，证书链越长，因为要把中间证书也一并发送给别人，别人也要一层一层验证，信任握手的开销就越大。

使用刚才创建的 ECC 密钥对，通过 OpenSSL 合成 X.509 证书。你会被要求回答几个问题，让系统知道这个证书颁发给谁（相当于创建 CSR，只不过不用发给别人，也不用证明你是你，就在本地简易询问了。你也可以使用 OpenSSL 先生成 CSR，然后再输入 CSR 和 CA 私钥来颁发）。回答的内容会被明文包含在证书中，并被该 ECC 密钥对的私钥签名：
```powershell
PS C:\> openssl req -new -x509 -key .\key.pem -out .\cert.pem -days 1; cat .\cert.pem
<输出被删减>
-----
Country Name (2 letter code) [AU]:CN
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
-----BEGIN CERTIFICATE-----
MIIB3zCCAYWgAwIBAgIUEbJhIOHfTHG8oi2y8ZhW6VenqmMwCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCQ04xEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTA0MDUxMTMzNDdaFw0yMTA0MDYx
MTMzNDdaMEUxCzAJBgNVBAYTAkNOMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASR85iGMHMZVORky0MymXvWlHVd8fB+uDuHyZteRsd8gHRC/iBbechR
QMnxreKl0wBAaTO2k4K3YbsI80x0K93fo1MwUTAdBgNVHQ4EFgQUe46okztDEZJ1
aGn3Oq3NdKSJzEgwHwYDVR0jBBgwFoAUe46okztDEZJ1aGn3Oq3NdKSJzEgwDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA3ICMVEgJnLSwu5gGrxwA
IcJ6tAA17ZU/2DtJIlXx1R8CIGLbk7qj04WPdiM+uQunrr/Jt07HsXGYswKymwne
Y6xU
-----END CERTIFICATE-----
```
因为该证书不由其他 CA 签署，该证书本身就是 CA 证书。查看证书的信息：
```powershell
PS C:\> openssl x509 -in .\cert.pem -text -noout
<输出被删减>
        Issuer: C = CN, ST = Some-State, O = Internet Widgits Pty Ltd
        Validity
            Not Before: Apr  5 11:33:47 2021 GMT
            Not After : Apr  6 11:33:47 2021 GMT
        Subject: C = CN, ST = Some-State, O = Internet Widgits Pty Ltd
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:91:f3:98:86:30:73:19:54:e4:64:cb:43:32:99:
                    7b:d6:94:75:5d:f1:f0:7e:b8:3b:87:c9:9b:5e:46:
                    c7:7c:80:74:42:fe:20:5b:79:c8:51:40:c9:f1:ad:
                    e2:a5:d3:00:40:69:33:b6:93:82:b7:61:bb:08:f3:
                    4c:74:2b:dd:df
<输出被删减>
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:dc:80:8c:54:48:09:9c:b4:b0:bb:98:06:af:
         1c:00:21:c2:7a:b4:00:35:ed:95:3f:d8:3b:49:22:55:f1:d5:
         1f:02:20:62:db:93:ba:a3:d3:85:8f:76:23:3e:b9:0b:a7:ae:
         bf:c9:b7:4e:c7:b1:71:98:b3:02:b2:9b:09:de:63:ac:54
```
其中，Issuer 是颁发者，该证书是 CA 证书，颁发者就是他自己。同时包含了过期时间、该证书颁发给的对象、公钥类型（此处为 `ecPublicKey`，即采用 ECC 算法的公钥）、签名算法和 CA 签名等信息。Signature Algorithm 其后就是 CA 对这张证书的签名。叶子证书不能再颁发新证书。

将上述的 Subject Public Key Info 中的 pub 与公钥比对，发现完全一致。
```powershell
PS C:\> echo "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkfOYhjBzGVTkZMtDMpl71pR1XfHwfrg7h8mbXkbHfIB0Qv4gW3nIUUDJ8a3ipdMAQGkztpOCt2G7CPNMdCvd3w==" | base64 -d | xxd
00000000: xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx  ................
00000010: xxxx xxxx xxxx xxxx xxxx 0491 f398 8630  ...............0
00000020: 7319 54e4 64cb 4332 997b d694 755d f1f0  s.T.d.C2.{..u]..
00000030: 7eb8 3b87 c99b 5e46 c77c 8074 42fe 205b  ~.;...^F.|.tB. [
00000040: 79c8 5140 c9f1 ade2 a5d3 0040 6933 b693  y.Q@.......@i3..
00000050: 82b7 61bb 08f3 4c74 2bdd df              ..a...Lt+..
```

## 证书吊销
证书吊销在 [RFC 5280](https://tools.ietf.org/html/rfc5280) 定义。客户应在每次收到对方证书时查询证书吊销列表（CRL：Certificate Revocation List）。CRL 是公钥基础设施（PKI：Public Key Infrastructure）的一部分，它是一个有固定 URL 的文件，包含所有被吊销证书的序列号和日期等基础信息。

CRL 的 URL 称为 CDP（CRL Distribution Point），通常被固定在证书的明文部分，因此也受到 CA 的私钥签名的保护。

OCSP（Online Certificate Status Protocol）是用于在线查询证书是否被吊销的协议。你想，如果你每打开一个网站系统都要先下载 CRL，然后在所有被吊销的证书中搜索服务器给你的证书存不存在，是不是很慢？OCSP 协议就可以让客户端直接通过序列号搜索该证书是否被吊销。通常是由服务器经常向 CDP 查询后缓存，通过 OCSP stapling 在 TLS 握手时一并装订传送回客户端（[RFC 6961](https://tools.ietf.org/html/rfc6961)）。在知道了证书签名之后，很容易就能想到其实现方式：OCSP 记录也被 CA 签名。只要在有效期内，由服务器代为发送也很安全。

## 密钥交换
以上的加密和签名算法建立在同一个假设上：验证方知道加密方的密钥（对称加密）或公钥（非对称加密）。而现实生活中，服务器往往同时拥有公钥和私钥，但客户端却什么都没有。   

密钥交换技提供了很好的解决方案，在不互相发送密钥的情况下，双方在本地都拥有具有随机数的密钥交换信息，并且仅通过共享其中的少量信息即可让双方可以通过一定的算法计算出一样的密钥（称为会话前密钥）。相当于打暗号，但是别人如果仅仅知道被相互发送的少量信息，是无法推断出密钥的。同时，因为每次交换密钥后都存在随机信息，因此每次协商出的会话密钥🔑都不相同。  
有了会话密钥🔑，即可快速建立通过对称加密的加密信道。  

常见的密钥交换协议有 PAKE（对称）、PSK（对称）、SRP（对称）、ECDHE（非对称）、RSA（非前向保密；非对称） 等。

## 前向保密（PFS）
前向保密又称为前向安全性。  

如果有很多次通讯都长期使用一套密钥，并且所有的加密后的通讯内容都被恶意第三方保存下来了。那么将来这套密钥泄露是否会导致先前的通讯内容被破解呢？如果是，那么这些通讯不具备前向保密的性质。  

如果回头再看[密钥交换](#密钥交换)小节就会发现，长期使用的主密钥根本不重要（仅用于验证身份而不用于加密通讯），或者直接就没有主密钥。此时，如果其中主密钥或者其中一次通讯的会话密钥🔑泄露，也不会导致其他通讯被破解，该方法就具有前向保密性。

## 椭圆曲线密码学（ECC）
ECC 是新一代的公钥加密算法，现常用于加密货币，中国二代身份证和 HTTPS 的加密。基于 ECC 的 ECDHE 将用于替代传统的 RSA 密钥交换方式，因为 RSA 不具备 PFS。其他情况下，ECC 具有显著的性能优势。请注意，ECC 会受到秀尔算法（Shor's algorithm）的威胁，但是秀尔算法目前只能在量子计算机上运行。  

ECC 中曲线的核心在于有限域上的阿贝尔群，是数论和几何学的一部分。在阿贝尔群中，定义了新的加减元运算，椭圆上的坐标仍然满足加法和乘法的交换律和结合律。在该群上的曲线满足方程 $$ y^2=x^3+ax+b $$，其中 $$ a $$ 和 $$ b $$ 是常数，但不能随意取值，因为满足阿贝尔群的曲线是有限的。常见的曲线有：`secp256k1`、`P-384` 和 `Curve25519`。在公开的曲线上，曲线方程（即 $$ a $$ 和 $$ b $$）、基点坐标 $$ G $$ 和大质数 $$ \rho $$ 也同时公开。基点 $$ G $$ 必须要是 $$ \rho $$ 的一个原根，满足离散对数难解性，不能随意选择，因此该点也被固定下来。  

通常，一方选择一个公开的曲线，通过随机数生成私钥，并通过曲线上定义的新运算将私钥和基点相乘，即 $$ pubKey=privKey \times G $$。由于曲线上满足加法和乘法的交换、结合律，该乘法的复杂度是 $$ O(log(n)) $$，其中，$$ n_{max}=2^{私钥长度} $$，即最多运算次数不会超过密钥长度。

该运算的逆运算在缺少私钥 $$ privKey $$ 的情况下因为存在太多分解的可能性，几乎不可逆，暴力破解私钥的复杂度为 $$ O(n) $$。在密钥长度为 256 位时，加密最多需要进行 256 次迭代，而解密至少需要迭代 $$ 1.15 \times 10^{77} $$ 次。拥有这样的性质的函数被称为活版门函数（Trapdoor function）。

![trapdoor function explained](){: .lazy data-src="https://upload.wikimedia.org/wikipedia/commons/8/8f/Trapdoor_permutation.svg"}
*来源：维基百科*

## 迪菲-赫尔曼密钥交换协议（DH）
迪菲-赫尔曼密钥交换协议（DH 密钥交换）是[密钥交换](#密钥交换)的一种实现方式。核心在于将双方的公钥和私钥组合即可得到共享密钥。

本节内容是中静态 ECDH 算法的实现（非前向保密）。因为双方都在椭圆曲线上计算出公钥，这样的情况下 DH 算法升级为 ECDH 算法。

已知 $$ pubKey=privKey \times G $$，交换的双方 $$ A $$ 和 $$ B $$ 在协商好曲线名称和其他公开信息后，分别生成自己的私钥，并在与基点 $$ G $$ 相乘后向对方公开自己的公钥 $$ pubKey A $$ 和 $$ pubKey B $$，各自在用对方的公钥和自己的私钥相乘，即可得到相同的密钥。

<div style="display: block; overflow: auto;">$$ sharedKey = pubKey A \times privKey B = privKey A \times G \times privKey B = pubKey B \times privKey A $$</div>

该式能够在阿贝尔域内被满足（乘法结合律）。因此使用 $$ sharedKey $$ 即可建立加密信道。

![](){: .lazy data-src="https://upload.wikimedia.org/wikipedia/commons/4/4c/Public_key_shared_secret.svg"}
*来源：维基百科*

## 熵、随机数和盐
熵指系统的失序现象，即越混乱，熵越大。而熵越大，就越不好还原信息的真实面目。

随机数的字面意思很好理解，即一段让人摸不着头脑、没有规律的数。随机数分伪随机数和真随机数：伪随机是一串预编码的随机数序列，保存在计算机中，每次使用算法取出；而真随机数则使用系统中的随机数发生器根据系统熵（如用户输入、驱动程序和其他噪声来源）来生成。随机数越随机，在密钥交换的过程中参与的运算越多，熵越大。

在 Linux 系统中，可以通过读取 `/dev/random` 设备来获取源源不断的伪随机数，通过 `/dev/urandom` 来获得真随机数。显然，伪随机数的读取速度会快很多。

盐的作用在于向一串熵很小的密钥中增加随机数，即增加熵。

DH 本身是静态的，非前向安全。DHE 在 DH 的基础上增加了临时密钥（ephemeral key），使用临时密钥而不是 $$ sharedKey $$ 来加密通讯。 DHE 协商出的密钥与生成的随机数有关，每次的临时密钥也因此不同。相对于 DH，DHE 的熵明显增加，因此 ECDHE/DHE 是前向安全的。

## 安全元素（SE）
安全元素（SE：Secure Element）在不同的厂商拥有不同的名字，因为他们的功能略有不同。微软称之为 TPM，而苹果称之为 Secure Enclave，还有其他的厂商如 Yubico 的 YubiKey 就是作为 USB HID 设备的安全元素。

安全元素的主要功能就是生成随机数、生成密钥对、加解密加速器、根证书和密钥存储等安全功能。一些企业会将根证书烧录在安全元素的只读存储器中，只读存储器从物理角度保护内容不被修改，安全元素中的证书就被可信的固定下来，为系统提供可靠的可信平台。同时，安全元素对 AES 等运算提供流式硬件加速，可以类比为显卡加速游戏，因此系统在进行 AES 加解密操作时，不会占用 CPU 的轮转时间。

Chrome 在 67 版本开始支持 [Web Authentication API](https://www.w3.org/TR/webauthn/)，该 API 允许 Chrome 调用设备上的安全元素来进行登录。所以，在启用了该技术的网站上，你可以使用 Windows Hello、Face ID、Yubikey 等方式直接登录。

如果你为你的计算机启用了安全启动（Secure Boot）功能，则主板在每次启动时都会从 TPM 读取主密钥来验证启动的操作系统。

Windows 的磁盘加密 BitLocker，macOS 的 FileVault 都使用 AES 对称加密。在使用时，都被安全元素保护或加速。

## 加密货币
以加密货币中的老大哥比特币（BTC）为例。在注册比特币钱包时会生成一串私钥，然后通过 ECC 和 `secp256k1` 曲线生成对应的公钥。使用 SHA-256、RIPEMD160 等方法将公钥摘要后通过除去符号和普通易混淆字母后的 base58 等算法编码即可得到成为比特币钱包地址[^1]。因为地址是摘要的结果，所以无法通过地址推回公钥。即使加了校验，也只能在拥有公钥的情况下验证地址是正确的，没有方法能保证这个地址存在对应的公钥。

### 交易
比特币的核心是区块链，区块链由无数区块组成，每个区块保存了数千笔交易，由矿工将交易打包成区块添加到区块链中。因此比特币交易（不是炒币）的信用体系就通过公开交易记录来实现，所有的交易、区块和地址都能在 [Blockchain.com](https://www.blockchain.com/) 查询到。大家都知道你之前收到过多少钱，花了多少，也就都知道了你的余额。每一笔交易都保存了付款的数量（Value）、对方的地址（Address）、付款者的公钥（Pkscript）等基本信息，并被付款者的私钥签名（Sigscript）。付款交易被你签名过，所以大家都认可是由你发出的转账；反过来，别人签名付款给你的交易就可以确定别人的确是转给你的。

![](){: .lazy data-src="https://developer.bitcoin.org/_images/en-micropayment-channel.svg"}
*来源：bitcoin.org*

从你的第一笔付款开始，你的公钥就显示在交易记录里，并流传在网络中。在此之前，别人是不知道你的地址是否是真实存在的。将公钥和地址公开后，别人先将公钥 Hash 后与地址比对，成功后两者就公开绑定了，之前这个地址上的所有收入也就可以算到这把公钥上了。如果想自己弄一把自己的公钥绑定到某个其他地址上是行不通的，因为所有人都会发现这把公钥 Hash 后不能得到这个地址。所以如果打钱给了不存在的地址，那这笔钱还真就人间蒸发了，因为没有人拥有这个地址的密钥对，也就没有人能再从该地址发出转账。

所有的交易记录都公开。比如，地址 `bc1qvx7u3d3ln2l8s8akk0rfm7zcdkenjzefledrs4` 进行的一次 Hash 为 [d8f81f61...31f6cd65](https://www.blockchain.com/btc/tx/d8f81f613501a3f801a440c22dcf3b87f5579dc1d28e372cae08c1d131f6cd65) 的交易，这笔交易一共转出了 $17.12 美元，其中 $4.07 美元交给矿工用作手续费，$13.06 美元成功到账。在 Inputs 中可以看到由该地址私钥签名的 Sigscript 和该地址的公钥 Pkscript，也同时包含了这笔交易的转出数量和目的地址。这项交易被记录在区块 Block 677983 中。

而在区块 [Block 677983](https://www.blockchain.com/btc/block/0000000000000000000861dacbeaeef253591e6e4fc7b7bef37de76e5b91de02) 中，一共存在 2,603 笔交易，总交易额为 $5,672,091,896.90 美元。

### 挖矿
最后，将交易打包成块并存放到区块链的行为就称为挖矿。不仅可以从交易中赚到手续费，只要成功把区块附加到主链，就会得到一笔系统奖励。比如提交刚才 Block 677983 区块的矿工，就得到了价值 $56,979.08 美元的奖励。奖励的币显示为 “COINBASE (Newly Generated Coins)”，直接转入钱包地址。每一个新的区块都有新的 COINBASE。

区块中也存在 Hash 摘要，这次既不是签名，也不是为了摘要，而是单纯为了增加挖矿的难度。只有少数人能够将区块打包到区块链中：如果人人都能同时附加区块，那么链中必然会出现信息不一致，并且会由能够更快附加新块的人所控制（最长链原则）。BTC 采用的机制是 PoW（Proof of Work），做的工作越多，得到的奖励就越多（即 one-CPU-one-vote[^2]）。PoW 指的是在打包时，矿工必须通过调整区块头的一个随机数（nonce）使得区块头的 SHA-256 结果的前 $$ n $$ 位数全部[^3]为 0。这样，挖到币的几率为 $$ \frac{1}{2^n} $$，并且 $$ n $$ 越大，找到一个使 SHA-256 结果的前 $$ n $$ 位全部为 0 的随机数就越难。

$$ n $$ 的值随着参与挖矿的人数动态改变，根据区块头的 Bits、规定的每十分钟产生一个块和计算移动平均线（MA）自动调整。规定比特币的创世块 [Block 0](https://www.blockchain.com/btc/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f) 的难度为 1，将最新块的 Hash 和 Block 0 的 Hash 相除，就可以近似的到当前的全网难度。

比如，刚才提到的区块 Block 677983 的 Hash 值为 `0x0000000000000000000861<省略>`，前 76 位全部为 0，挖到币的机率为 $$ \frac{1}{2^{76}} $$。因此，现在个人使用显卡挖 BTC 已经几乎不可能。

矿场一般这样挖矿：

![](){: .lazy data-src="https://developer.bitcoin.org/_images/en-pooled-mining-overview.svg"}
*来源：bitcoin.org*

加密货币还拥有其他功能和性质，比如托管和仲裁等，本文只是简单介绍涉及密码学的关键部分。你可以在 [Learn Bitcoin and start building Bitcoin-based applications](https://developer.bitcoin.org/index.html) 查看完整的比特币网络运作原理。比特币是开源的货币，你可以在 [bitcoin/bitcoin: Bitcoin Core integration/staging tree](https://github.com/bitcoin/bitcoin/) 查看比特币的源代码。

## Wi-Fi 访问保护（WPA）
Wi-Fi 访问保护（WPA：Wi-Fi Protected Access®） 目前的最新版本是 WPA-3[^4]，用于保护无线局域网。在你的手机输入 Wi-Fi 密码开始，WPA 系统就在为你服务。WPA-3 在现代路由器和无线接入点产品中已经普及。

在 WPA-3 个人级中，使用 SAE（Simultaneous Authentication of Equals）进行密钥交换。SAE 算法是 ECDHE 密钥交换的变种，区别在于协商出来的密钥还受到预共享的密钥（即设定的 Wi-Fi 密码）及设备 MAC 地址的影响。密钥共享完毕后，设备使用 128 位 AES 对称加密的信道通信。同时 Wi-Fi 联盟规定使用 `P-384` 曲线用于参与 ECC 算法。

WPA-3 企业级同样使用 ECDHE 进行密钥交换， 192 位 AES-GCMP 对称加密，ECDSA 进行签名。

可见，WPA-3 是前向保密的。同样的，在 3G、4G 和 5G 数字蜂窝网络中，也采用类似的握手和加密流程。

## 数字电影发行
数字电影使用 KDM（Key Delivery Message） 进行密钥分发。KDM 的本质就是张 XML 格式的 X.509 明文证书，外加被加密的影片对称密钥（用来解密影片文件），最后把明文证书和加密后的对称密钥一起签个名的结果。  

影片发行方先对影片文件进行对称加密得到加密后的影片文件 DCP（Digital Cinema Package），然后使用各个影院播放设备的公钥对影片文件 DCP 的对称密钥进行加密，再使用发行方的私钥进行数字签名。最后将加密后的影片文件 DCP 和 KDM 一并传送至数字影院。影院播放设备在接收到 DCP 和 KDM 之后，使用发行方的公钥验证签名，核对日期，再使用播放设备的自己的私钥进行解密，以从 KDM 中提取出内容解密密钥，最后对加密的电影文件 DCP 进行解密和播放。

每台播放设备都有自己的一套公私钥。设备必须经过认证，类似 HDCP。这样可以保证播放设备必须会先验证授权信息再播放，而非直接取出对称密钥随意播放。同样的，发行商可以单独吊销某台设备的设备的公私钥，用来 ban 机。


## BitTorrent（BT）和分散哈希表（DHT）网络


## 传输层安全（TLS）
最后，终于可以看到一开始的 HTTPS 问题啦！浏览器建立安全连接背后的技术是传输层安全（TLS），现在通常使用的是 1.3 版本。  
TLSv1.3 的核心流程为：
1. 客户端发送 Hello，快速进行密钥交换。使用上次的预共享密钥 PSK 或者 ECDHE 进行新的密钥交换。作为客户端，为节省时间，说我不管你服务器同不同意 PSK，反正 PSK 和选好的 ECDHE 的曲线名和公钥，直接都先发送过去。
2. 服务器选择一项交换方法，返回对应的 Hello。双方通过密钥交换或者 PSK 已经得到会话的前密钥🔑。
3. 使用密钥演变算法（HKDF：HMAC-based key-derivation function）将会话前密钥变成会话密钥🔑（类似摘要。用来保证不同算法的结果一致）。在会话密钥🔑加密的信道中验证服务器身份，然后直接开始传输数据。

得益于 TLSv1.3 的全新连接流程，在下图中从带大括号的开始数据就已经开始被加密了。双方不管三七二十一赶紧先把加密连接建立了，你认不认识我都一会儿再说。这样做主要是为了避免降维打击，即中间人强制让双方降级到不安全的加密方式。

![](){: .lazy data-src="https://img.akacdn.app/5576424a94f5f08f2775ad88d37bef74.png"}
*来源： IETF 8446*

使用 OpenSSL 的 `s_client` 子系统建立 TLS 连接：

```powershell
PS C:\> openssl s_client -connect cloudflare.com:443
CONNECTED(000001A4)
<输出被删减>
---
Certificate chain
 0 s:C = US, ST = CA, L = San Francisco, O = "Cloudflare, Inc.", CN = sni.cloudflaressl.com
   i:C = US, O = "Cloudflare, Inc.", CN = Cloudflare Inc ECC CA-3
 1 s:C = US, O = "Cloudflare, Inc.", CN = Cloudflare Inc ECC CA-3
   i:C = IE, O = Baltimore, OU = CyberTrust, CN = Baltimore CyberTrust Root
---
Server certificate
-----BEGIN CERTIFICATE-----
<输出被删减>
-----END CERTIFICATE-----
<输出被删减>
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
<输出被删减>
---
GET / HTTP/1.1

---
Post-Handshake New Session Ticket arrived:
<输出被删减>
---
read R BLOCK
HTTP/1.1 400 Bad Request
Server: cloudflare
<输出被删减>
```
可以看到，从建立连接到开始传输 Application Data 仅仅使用了一个 RTT。  

这次 TLS 握手选择了加密套件 `TLS_AES_256_GCM_SHA384`，即使用 AES_256_GCM 算法来维护后续的对称加密，使用 SHA384 来对消息签名，实现了 AEAD。  

在连接建立之后过了很久，服务器才传回一个新的 Session Ticket，这也是 TLSv1.3 赶紧建立连接的一个体现，即 Post-Handshake 机制：  

![](){: .lazy data-src="https://img.akacdn.app/2167a420695e96e074a76e1923864f28.png"}

也许你会发现，以上的 TLS 流程只让客户端验证了服务器。如果要使服务器可以验证客户端，则需要在安全连接彻底建立之后，由客户端发送自己的公钥。该部分严格来说不在 TLS 范畴。

## GnuPG（GPG）
GPG（GnuPG）是用于加密和签名文件、电子邮件等信息的工具，同时支持对称和非对称加密。同时 GPG 还有公开的公钥服务器，任何人可以将自己的公钥上传到服务器中，供他人查询。

GPG 常用于签名 Linux 软件包。任何包管理器都支持导入 GPG 公钥，并在安装软件包时验证其签名。由于大部分发行版的软件包都由少数几个机构维护，因此大部分软件源中的包全部使用同一对 GPG 密钥签名。

使用 `--encrypt` 和 `--decrypt` 进行文件加解密，使用 `--sign` 命令对文件签名。在 [gpg(1) - Linux man page](https://linux.die.net/man/1/gpg) 可以查看 GPG 的使用手册。

如果你愿意，可以尝试通过 GPG 工具验证 [证书和信任链](#证书和信任链) 中的证书签名是否与 [对称和非对称密钥](#对称和非对称密钥) 中的私钥相符。

[keybase.io](https://keybase.io/) 是一个在线管理 GPG 密钥、加解密、签名的平台。

## 攻击和破解
散列函数如 SHA 通常使用原像抗性和次原像抗性作为其性能指标。这些指标的影响因子之一就是不能算得太快，不然查找某一散列值的原像就会很容易（比如已经宣告不安全的 MD5）。

比特币的算力不能用来破解 SHA 算法，因为比特币的工作方式是次原像攻击。值得一提的是，SHA-1 散列函数已被国内王小云教授等人成功以小于 $$ 2^{69} $$ 的计算复杂度使用碰撞攻击攻破。在量子计算机出现后，对于原像的碰撞攻击复杂度会显著下降。目前，多重散列是缓解该问题的一个办法。

WPA-2 曾因为密钥协商流程不够严谨而被破解，称作 KRACK[^5]（Key Reinstallation Attacks）。

BitLocker 也曾因为可以简单绕过 Kerberos 认证被破解（KB3101246）。这是双密钥机制的弊端。

还有一些以分析取胜的方法，比如线性密码分析和差分密码分析，及侧信道信息分析等手段。辅以机器学习，这些分析的方法其实很强大。但是，这些方法本身已经偏离加密学范畴，更符合统计学和概率论的定义。

以上，大部分目前标记为「安全」的加密算法，尽管从数学上看仍然是安全的，在使用过程中也有可能存在漏洞。同时，今天标记为安全的算法，在计算机速度高速发展的进程中，也可以随时被宣告死亡。在设计安全系统时，实时更新才是最重要的。

## 附录
在使用 CDN 时，无论你是把 TLS 的私钥交给云服务商，还是采用 Keyless 部署，云服务商可以看到并修改传输的内容。因为私钥只在建立 TLS 连接时有效，Session Key 仍然掌握在云服务商手中。或者在某些极端情况下，CDN 到源服务器的连接甚至直接使用没有加密的普通 HTTP。在传输关键信息时，还需要使用 JWE 和 JWT 等手段辅助。

通常，非对称密钥在加密通讯时，仅用于协商密钥，最后使用协商的密钥来进行对称加密通信。退化的原因一是因为协商出来的密钥可以用来实现前向保密，其二也因为对称加密可以使系统负载降低几个数量级。

最后，加密学的假设是 $$ P \neq NP $$。当今世界瞬息万变，如果有一天人们找到了更好的解题办法，现存的加密方法都将土崩瓦解。关心信息安全的你，也许应该保持一颗时常关注行业信息的心。

<script src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>

[^1]: 简化版本，请参阅：https://en.bitcoin.it/wiki/Wallet_import_format
[^2]: 来自 BTC 白皮书：https://bitcoin.org/bitcoin.pdf
[^3]: 具体的实现是使用 Bits 计算 target，并使 SHA-256 结果小于 target，小于 target 的 SHA-256 结果前 n 位通常是 0，但并不是单纯置零
[^4]: Wi-Fi Protected Access® 3 是 Wi-Fi 联盟的注册商标。请参阅： https://www.wi-fi.org/download.php?file=/sites/default/files/private/Wi-Fi_Alliance_Brand_Style_Guide_202006.pdf
[^5]: 有限制：要求攻击者的辐射功率要远大于无线接入点的辐射功率
