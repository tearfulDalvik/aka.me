---
layout: post
title: 📈 区块链小记
category: note
permalink: note/blockchain/
tags: blog_notes
plugin: lazyload lightense
---

> 有关签名、公钥和私钥等密码学知识，请移步 [🔣 密码学小记](/note/cryptography/)

## 目录
{:.no_toc}
1. Table of contents
{:toc}

## 区块和区块链
顾名思义，区块链由无数区块组成。其中，每个区块保存了数千笔交易，由矿工将交易打包成区块添加到区块链中。因此由区块链构成的信用体系是通过公开交易记录来实现的。大家都知道你之前收到过多少钱，花了多少，也就都知道了你的余额。通常，一个区块的大小是有限制的。

常用的链有 `BTC`、`ERC-20`、`TRC-20` 等，不同的链其实就是不同的区块链协议，拥有不同的区块链查看器。山寨币大多数不自己创造链，而是附加到某个链上（见[智能合约（Smart Contract）](#智能合约smart-contract)小节）。

本文以 `BTC` 为基准。`BTC` 链中的所有的交易、区块和地址都能在 [Blockchain.com](https://www.blockchain.com/) 查询到。每一笔交易都保存了付款的数量（Value）、对方的地址（Address）、付款者的公钥（Pkscript）等基本信息，并被付款者的私钥签名（Sigscript）。逻辑是这样：如果一笔付款交易被你签名过，大家就都认为是经你确认而从你的账户发出的转账；反过来，别人签名的付款，所有人就都可以确定这笔付款是给你的。

比如，地址 `bc1qvx7u3d3ln2l8s8akk0rfm7zcdkenjzefledrs4` 进行的一次 Hash 为 [d8f81f61...31f6cd65](https://www.blockchain.com/btc/tx/d8f81f613501a3f801a440c22dcf3b87f5579dc1d28e372cae08c1d131f6cd65) 的交易，这笔交易一共转出了 $17.12 美元，其中 $4.07 美元交给矿工用作手续费，$13.06 美元成功到账。在 Inputs 中可以看到由该地址私钥签名的 Sigscript 和该地址的公钥 Pkscript，也同时包含了这笔交易的转出数量和目的地址。这项交易被记录在区块 Block 677983 中。

而在区块 [Block 677983](https://www.blockchain.com/btc/block/0000000000000000000861dacbeaeef253591e6e4fc7b7bef37de76e5b91de02) 中，一共存在 2,603 笔交易，总交易额为 $5,672,091,896.90 美元。

## 共识算法
共识算法实际上是区块链中的所有人必须遵守的协议的实现。用来约束产生新块的速度，并约束参与挖矿的人。只有少数人能够将区块打包到区块链中：如果人人都能同时附加区块，那么链中必然会出现信息不一致，并且会由能够更快附加新块的人所控制（最长链原则，也称作 51% 攻击）。

比如，比特币采用的是 PoW（Proof of Work）算法，即做的工作越多，得到的奖励就越多（即 one-CPU-one-vote[^1]。PoW 指的是在打包时，矿工必须通过调整区块头的一个随机数（nonce）使得区块头的 SHA-256 结果的前 $$ n $$ 位数全部[^2]为 0。这样，挖到币的几率为 $$ \frac{1}{2^n} $$，并且 $$ n $$ 越大，找到一个使 SHA-256 结果的前 $$ n $$ 位全部为 0 的随机数就越难。

$$ n $$ 的值随着参与挖矿的人数动态改变，根据区块头的 Bits、规定的每十分钟产生一个块和计算移动平均线（MA）自动调整。规定比特币的创世块 [Block 0](https://www.blockchain.com/btc/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f) 的难度为 1，将最新块的 Hash 和 Block 0 的 Hash 相除，就可以近似的到当前的全网难度。

比如，刚才提到的区块 Block 677983 的 Hash 值为 `0x0000000000000000000861<省略>`，前 76 位全部为 0，挖到币的机率为 $$ \frac{1}{2^{76}} $$。因此，现在个人使用显卡挖 BTC 已经几乎不可能。

以及其他的共识算法，如权益证明（Proof of Stake：PoS，在本文稍后的「权益质押」章节会详细介绍）、委托权益证明（DPoS）、空间证明（Proof of space，就是用磁盘来挖矿）、权威证明（Proof of authority：PoA）等。

## 加密货币
以加密货币中的老大哥比特币（BTC）为例。在注册比特币钱包时会生成一串私钥，然后通过 ECC 和 `secp256k1` 曲线生成对应的公钥。使用 SHA-256、RIPEMD160 等方法将公钥摘要后通过除去符号和普通易混淆字母后的 base58 等算法编码即可得到成为比特币钱包地址[^3]。因为地址是摘要的结果，所以无法通过地址推回公钥。即使加了校验，也只能在拥有公钥的情况下验证地址是正确的，没有方法能保证这个地址存在对应的公钥。

从你的第一笔付款开始，你的公钥就显示在交易记录里，并流传在网络中。在此之前，别人是不知道你的地址是否是真实存在的。将公钥和地址公开后，别人先将公钥 Hash 后与地址比对，成功后两者就公开绑定了，之前这个地址上的所有收入也就可以算到这把公钥上了。如果想自己弄一把自己的公钥绑定到某个其他地址上是行不通的，因为所有人都会发现这把公钥 Hash 后不能得到这个地址。所以如果打钱给了不存在的地址，那这笔钱还真就人间蒸发了，因为没有人拥有这个地址的密钥对，也就没有人能再从该地址发出转账。

![](){: .lazy data-src="https://developer.bitcoin.org/_images/en-micropayment-channel.svg"}
*来源：bitcoin.org*

## 挖矿和手续费
将交易打包成块并存放到区块链的行为就称为挖矿。不仅可以从交易中赚到手续费，只要成功把区块附加到主链，就会得到一笔系统奖励。比如提交刚才 Block 677983 区块的矿工，就得到了价值 $56,979.08 美元的奖励。奖励的币显示为 “COINBASE (Newly Generated Coins)”，直接转入钱包地址。每一个新的区块都有新的 COINBASE。

手续费在挖矿中很重要，不同的链一般有不同的手续费计算方法。`BTC` 交易按照交易所占的空间大小来计费（因为一个区块只有 1MB），而 `ERC-20` 网络则使用「燃料」来进行计费。矿工通常优先打包手续费更高的交易，因此手续费的存在还可以避免因为过多的恶意请求而导致的网络繁忙。在网络繁忙时，手续费往往会更高。但是，过高的手续费会导致交易的成本急剧增加，并牺牲一定的流动性。

矿场一般这样挖矿：

![](){: .lazy data-src="https://developer.bitcoin.org/_images/en-pooled-mining-overview.svg"}
*来源：bitcoin.org*

## 货币、加密货币和稳定币
货币其实就是人们用来交换东西的一个符号，常用的有法定货币（如人民币、美元等），代用货币（黄金、汇票）和加密货币。

加密货币是去中心化的货币，通过公开透明来实现强大的信用体系；而由国家垄断的中心化的货币也一样拥有强大的信用体系，依靠国家军队等资源来维护。

稳定币则是加密货币网络中用于锚定法定货币的加密货币，就像港币锚定美元一样。它使加密货币市场中存在可长期存放的中间货币。一般稳定币的发行量应等于发行人所质押的法定货币量，但由于信息不对称，发行人具体是否持有等额的法定货币无法简单判断。

常用的稳定币有泰达币（Tether USD₮）和 BGBP 等。在稳定币之间转换也可以直接理解成进行外汇交易。

## 中心化交易所（CEX）和去中心化交易所（DEX）

## 通货膨胀和通货紧缩
通货膨胀和通货紧缩很容易理解，即大家都有钱了，大家就都大手大脚的花钱了，所以物价水平会更高；而通货紧缩则反之。

根据费希尔方程 $$ MV=PY $$，其中 M 是货币流通量，V 是货币流通速度，P 是平均物价，Y 是社会货物总量。可见，在其他条件不变的情况下，货币流通量和平均物价成正比。

消费者物价指数（CPI）是衡量通货膨胀的一个工具，一般由国家统计局周期性发布。CPI 和其他技术指标一样，是滞后的，只能作为参考。

恶性通货膨胀是 Phillip D. Cagan 提出的，当商品和服务的价格在一个月内上涨了 50% 的时候就开始了恶性通货膨胀。恶性通货膨胀会引起连连锁反应，比如公司倒闭、失业率上升、税收减少等。说白了其实就是经济危机。

通货膨胀的原因主要是中央银行选择增加流动性，而通缩的原因是流动性减少。加密货币通过智能合约来增加或者减少流通的货币，因此它们的流动性并不由政府或金融机构来决定。

## 智能合约（Smart Contract）
区块链的交易是通过共识算法完成的，智能合约就是把共识算法也打包进区块中[^5]。

Bitcoin 的链不是智能链，因此一般智能合约不出现在比特币网络中。Ethereum 主网络实现了图灵完备的编程语言，即 Solidity。每个人都可以将自己的区块链软件通过 Solidity 编写出来，然后发布到链中。

`ERC-20` 协议就是通过合约部署的：

```solidity
contract EIP20 is EIP20Interface {
    mapping (address => uint256) public balances;
    string public name;
    uint8 public decimals;
    string public symbol;

    function EIP20(uint256 _initialAmount, string, uint8 _decimalUnits, string _tokenSymbol) public {
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    // ...
}
```

这段代码作为合约就被直接打包进入区块链中。需要注意的是，合约和合约调用都是链上的一笔 Transaction 而已。因此发行新币的成本也就是一定的交易手续费。

打个比方：当你发行自己的新货币时，你的以 `ERC-20` 为根本开发的软件就会被部署到 ETH 主链上。其他人使用你的币交易时，就在 ETH 主链发布新交易，只是这个交易说清楚了你的币的合约地址指针以及你要求他们给出的参数。

## 新币发行（ICO）和上新
想要发行自己的新币，最基本的是发布自己的智能合约。如果想让大家都参与进来，还需要写一份白皮书（White Paper），做个官网，申请 Twitter 官方账号等一系列标准操作。

这时候已经可以进行比较麻烦的手动转账交易了（比如手动设置下 Uniswap），但还是显得非常山寨。如果想做大，可以给 CEX 交易所交一份上新费，还有之后每年的年费，就可以供大家轻松交易了。常见的 CEX 交易所的工作模式和 Nasdaq、App Store 很像，发行新币其实就是敲钟上市。目前上新需要花几千万到几亿人民币，只要之后创造了流动性，这笔钱还是可以收回来的。

数字货币的增发同样享受铸币利差，只是谁来享受就由协议（白皮书）来决定了。BTC 是矿工。

你可以在 [Create your ERC20 Token](https://vittominacori.github.io/erc20-generator/create-token/) 发行自己的货币。

## DeFi
去中心化金融（Decentralized Finance：DeFi）的目标是以区块链技术和密码货币为基础，重新创造并完善已有的金融体系。其实就是把其他金融手段也去中心化，比如借贷、保险、基础设施、稳定币、去中心化交易所（DEX）、支付、衍生品与预测市场等。

通过 DeFi，任何人都可以交易任何山寨币。智能合约是 DeFi 的灵魂。

## 流通池和无常损失

## 市场流动性（Liquidity）、权益质押和流动性挖矿
既然不能通过发行货币来刺激市场流动性，在加密货币中，通常就需要其他手段鼓励人们出来交易。

挂单（Maker）一般称为创造流动性，所以很多交易所会给挂单的人更优的手续费[^4]，吃单因此就被视为减少流动性。Maker 就是 CEX 的流动性提供者（LP：Liquidity Provider）。

在 DEX 交易所中，流动性提供者就是将币质押到平台的人，他们可以从中获得平台手续费的分成。这就称为权益质押和流动性挖矿。简单的说，你就把币存进指定账户，吃利息。

## 自动做市（AMM）
在一般的市场中，需要靠买盘和卖盘的 Maker 来提供报价，而 AMM 的出现可以让价格曲线按照需求曲线自动生成。

简单的例子是：$$ X * Y = K $$ 的公式中，$$ K $$ 是常数，$$ X $$ 和 $$ Y $$ 分别代表剩余的代币数量和单价。因此 $$ X $$ 和 $$ Y $$ 简单的成反比关系，即库存越少，价格越贵。

自动做市商使用 $$ Y $$ 来提供报价，套利者会将价格与 CEX 交易所同步。

常见的自动做市商有 Uniswap，Curve 等。

![lp](){: .lazy data-src="https://uniswap.org/static/94f9a497b001a6b27df2c37adadc05b4/824f2/lp.jpg"}

更多信息，请参考 [How Uniswap works](https://uniswap.org/docs/v2/protocol-overview/how-uniswap-works/)

<script src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>

[^1]: 来自 BTC 白皮书：https://bitcoin.org/bitcoin.pdf
[^2]: 具体的实现是使用 Bits 计算 target，并使 SHA-256 结果小于 target，小于 target 的 SHA-256 结果前 n 位通常是 0，但并不是单纯置零
[^3]: 简化版本，请参阅：https://en.bitcoin.it/wiki/Wallet_import_format
[^4]: [手续费表](https://www.binance.com/zh-CN/fee/schedule)
[^5]: [Introduction to Smart Contracts](https://docs.soliditylang.org/en/v0.8.4/introduction-to-smart-contracts.html)