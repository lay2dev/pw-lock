## pw-lock机制在CKB上的实现

CKB官方的锁定脚本使用blake2b计算hash，使用secp256k1_ecdsa_recover进行签名验证。其与ETH生态的验签主要差别在于hash的计算方式，ETH使用的是keccak256来计算hash。

由于CKB脚本的灵活性，能支持各种自定义的脚本。 我们开发了一种能够验证ETH生态签名的锁定脚本，并将其命名为pw-lock。

## 原理

### 官方交易签名基本逻辑：

1. 计算CKB交易hash tx_hash

2. 计算交易签名前hash = blake2b(tx_hash, input_witnesses, extra_witnesses)

3. 使用私钥进行签名signedWitness = ecsda_sign(hash, privateKey)


## pw-lock脚本实现

鉴于EIP712能够为用户展示更加直观和安全的信息，pw-lock优先支持了EIP712相关的签名方式signTypedData_v4。但是EIP712目前只有少数的几个ETH钱包能够完全支持，为了能够全面支持ETH生态，pw-lock同时也适配了当前绝大多数ETH钱包都能支持的personalSign签名方式。

因此，pw-lock脚本提供了两种签名的验证方式: personalSign和signTypedData_v4。

### 验证签名：eth_personalSign

#### hash计算方式
同CKB交易官方计算hash方式(参考官方lock脚本[secp256k1_blake160_sighash_all.c](https://github.com/nervosnetwork/ckb-system-scripts/blob/master/c/secp256k1_blake160_sighash_all.c))，只是将blake2b替换成keccak256。

#### 验签
```javascript
// 以下为伪代码，实际代码为c语言编写
const newHash = hashPersonalMessage(hash)

/*
hashPersonalMessage = function(message: Buffer): Buffer {
  const prefix = Buffer.from(
    `\u0019Ethereum Signed Message:\n${message.length.toString()}`,
    'utf-8',
  )
  return keccak(Buffer.concat([prefix, message]))
}
*/

const pubkey = secp256k1_ecdsa_recover(signature, newHash)
if (pubkey.slice(12, 32) === lock.args){
    return 0;
}
```

1. 使用ECDSA_RECOVER算法从newHash和签名计算出32位pubkey。
2. 检测pubkey的后20位是否等于lock args（也就是ETH地址)。

### 验证签名：eth_signTypedData_v4

#### hash计算方式
同CKB交易官方计算hash方式，只是将blake2b替换成keccak256。

```javascript
// 以下为伪代码，实际代码为c语言编写
const newHash = hashPersonalMessage(hash)
const typedData = {
    domain: {
      chainId: 1,
      name: 'ckb.pw',
      verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
      version: '1'
    },

    message: {
      hash:
        '0x545529d4464064d8394c557afb06f489e7044a63984c6113385431d93dcffa1b',
      fee: '0.00100000CKB',
      'input-sum': '100.00000000CKB',
      to: [
        {
          address: 'ckb1qyqv4yga3pgw2h92hcnur7lepdfzmvg8wj7qwstnwm',
          amount: '100.00000000CKB'
        },
        {
          address:
            'ckb1qftyhqxwuxdzp5zk4rctscnrr6stjrmfjdx54v05q8t3ad3493m6mhcekrn0vk575h44ql9ry53z3gzhtc2exudxcyg',
          amount: '799.99800000CKB'
        }
      ]
    },
    primaryType: 'CKBTransaction',
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' }
      ],
      CKBTransaction: [
        { name: 'hash', type: 'bytes32' },
        { name: 'fee', type: 'string' },
        { name: 'input-sum', type: 'string' },
        { name: 'to', type: 'Output[]' }
      ],
      Output: [
        { name: 'address', type: 'string' },
        { name: 'amount', type: 'string' }
      ]
    }
}

typedData.message.hash = newHash
typedData.message['input-sum'] = total_input_amount(tx)
typedData.message.fee = total_input_amount(tx) - total_output_amount(tx)
typedData.message.to = extractTxOutputsInfo(tx)

```
根据CKB交易信息计算出input-sum/fee/to相关信息，并赋值给typedData的对应属性。

#### 验签
```javascript
// 以下为伪代码，实际代码为c语言编写

const sigUtil = require('eth-sig-util')

const typedHash =  sigUtil.TypedDataUtils.sign(typedData)
const pubkey = secp256k1_ecdsa_recover(signature, typedHash) 
if( pubkey.slice(12,32) === lock.args){
    return 0;
}
```

1. 根据typedData计算出typedHash，使用ECDSA_RECOVER算法从typedHash和签名计算出32位pubkey。
2. 检测pubkey的后20位是否等于lock args（也就是ETH地址）。


