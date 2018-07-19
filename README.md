# TASSL
## 北京江南天安科技有限公司支持国密证书和协议的TASSL

OpenSSL是一套件开放源代码的安全套接字密码学基础库，囊括主要的密码算法、常用的密钥和证书封装管理功能及SSL/TLS协议，并提供丰富的API，以供应用程序开发、测试或其它目的使用。它广泛地集成在各种类型的操作系统中，作为其基础组件之一，深爱广大IT爱好者的喜爱。即使用某些操作系统没有将其集成为组件，通过源代码下载，也是十分轻松地构建OpenSSL的开发及应用环境。
 
尽管OpenSSL的功能十分强大且丰富，然而对于中国商用密码体系的算法及相关应用来说，它距离我们还是十分遥远，因为它仅仅包含的国际通用的密码算法、认证体系及相关协议，却没有将中国商用密码体系中的公开算法SM2、SM3、SM4及祖冲之流密码算法纳入其中，也不支持双证书体系的应用及相关协议。这对于推广及研究中国商用密码体系的广大密码爱好者来说，却是十分无奈的事情。
 国内也存在着不少密码界同仁，尝试着将OpenSSL国密化，但其大多都局限于公司内部交流使用，这对于国密SSL的推广不利。针对这种现状，北京江南天安公司经过长时间的研究分析，于2017年上半年推出天安版国密OpenSSL，也就是TaSSL，解决了中国商用密码体系无法构建基于OpenSSL应用的实际问题。现以源码的形式提供出来，供大家参考使用，为促进国密的推广和应用贡献自己的一份力量。

### (一)天安TaSSL的功能特点


1. 将国密算法SM2、SM3、SM4及祖冲之流密码算法作为OpenSSL的内置算法，并且严格按照《GMT 0006-2012 密码应用标识规范》定义的OID来对相关国密算法进行标识；
2. 将SM2作为EC的内置曲线，可通过ECDSA、ECDH分别完成SM2的签名和密钥协商；
3. 可通过
 *EVP_DigestSignInit、
 EVP_DigestSignUpdate、
 EVP_DigestSignFinal
 EVP_DigestVerifyInit、
 EVP_DigestVerifyUpdate、
 EVP_DigestVerifyFinal*
 智能化、自动化完成SM2的签名和验签过程；
4. 实现SM2公钥加密算法的同时，也将ECIES的公钥加密算法添加到OpenSSL中，可完成国际EC曲线的公钥加密；
5. 可通过引擎的方式来实现SM1算法的应用；
6. 实现了《GMT 0024-2014 SSL VPN技术规范》中与SM2相关的国密TLSv1.1的密码套件；
7. 添加了对中国商用密码体系的双证书的支持；
8. 完善了OpenSSL命令行工具对中国商用密码体系算法的支持；
9. 完善了X509对中国商用密码体系的支持。

### (二)天安TaSSL添加的及完善的API

#### Crypto相关的API
1. EVP_sm3()：取摘要算法SM3算法的EVP调用函数指针；
2. EVP_sm4()、EVP_sm4_cbc()：取SM4对称加密算法CBC模式的EVP调用的函数指针；
3. EVP_sm4_cfb()：取SM4对称加密算法CFB模式的EVP调用的函数指针；
4. EVP_sm4_ecb()：取SM4对称加密算法ECB模式的EVP调用的函数指针；
5. EVP_sm4_ofb()：取SM4对称加密算法OFB模式的EVP调用的函数指针；
6. EVP_PKEY系列函数：完善了此系列函数对SM2算法的调用；
7. EVP_DigestSignInit()、EVP_DigestVerifyInit()：完善了SM2签名时的Z值的计算；
8. EVP_PKEY_CTX_set_sm2_peer_id()：设置SM2密钥协商所需对方的可辨识ID及长度；
9. EVP_PKEY_CTX_set_sm2_self_id()：设置SM2密钥协商所需己方的可辨识ID及长度；
10. EVP_PKEY_CTX_set_sm2_server_tag()：设置SM2密钥协商所需的发起方或者客户端标识；
11. EVP_PKEY_CTX_set_sm2_peer_ecdhe()：设置SM2密钥协商所需的对方SM2临时公钥；
12. EVP_PKEY_CTX_gen_sm2_ecdhe_key()：生成并获取己方SM2临时密钥对；
13. EVP_PKEY_CTX_get_sm2_ecdhe_key()：获取己方SM2临时密钥对；
14. EVP_PKEY_CTX_set_sm2_ecdhe_key()：设置己方SM2临时密钥对
15. EVP_PKEY_CTX_set_sm2_encdata_format()：设置EVP_PKEY调用SM2加、解密的密文格式，其中，format为0为DER编码格式，即国密标准SM2密文格式；非0为C1C3C2二进制串；
16. ECDSA系列函数：完善了此系列函数对SM2签名、验签算法的调用；
17. ECDSA_sm2_get_Z()：计算SM2签名算法中的Z值。详细情况，请参见GMT 0003-2012的5.5节“用户其它信息”；
18. ECDH_compute_key()：完善了它对SM2密钥协商的调用；
19. SM2Kap_compute_key()：国密TLSv1.1的共享密钥计算函数；
20. SM3()、SM3_Init()、SM3_Transform()、SM3_Update()、SM3_Final()：SM3摘要算法系列函数；
21. SM4_set_key()、SM4_encrypt()、SM4_decrypt()、SM4_ecb_encrypt()、SM4_cbc_encrypt()、SM4_cfb_encrypt()、SM4_ofb_encrypt()：SM4对称算法系列函数；
22. sm2_encrypt()、sm2_decrypt()、sm2_do_sign()、sm2_do_verify()、i2d_sm2_enc()、d2i_sm2_enc()：SM2算法的签名、验签、加密、解密相关函数；
23. EVP_sm1()、EVP_sm1_cbc()、EVP_sm1_cfb()、EVP_sm1_ecb()、EVP_sm1_ofb()：预留的SM1接口函数，用于使用引擎实现SM1算法。

#### ssl相关的API
1. CNTLS_client_method()：获取国密TLSv1.1标准协议的相关SSL/TLS相关方法，以使用客户端使用标准的TLSv1.1协议进行握手、通讯；
2. *SSL_CTX_check_enc_private_key()、SSL_check_enc_private_key()、SSL_use_enc_PrivateKey()、SSL_use_enc_PrivateKey_ASN1()、SSL_CTX_use_enc_PrivateKey()、SSL_CTX_use_enc_PrivateKey_ASN1()、SSL_use_enc_PrivateKey_file()、SSL_CTX_use_enc_PrivateKey_file()*
为支持国密双证书体系而添加的函数。

### (三)TASSL使用说明
1. 目前开源的版本是基于OpenSSL 1.0.2o  27 Mar 2018版本；
2. 关于开发，编译，测试证书以及跟360国密浏览器联调的问题，参见Issues；
3. 我们开源的主要目的是推进国密算法的推广及应用，让你身边的人都知道TASSL，让更多的公司和个人用TASSL，一起创造活跃的社区，让国密算法应用更广。

### (四)关于江南天安

地址：北京市海淀区马甸东路17号金澳国际大厦11层1110室

邮编：100088 

电话：010-82326383 

传真：010-82328039 

邮箱：tassl@tass.com.cn 

网址：www.tass.com.cn 
