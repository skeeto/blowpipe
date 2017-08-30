#include <string.h>
#include "blowfish.h"

static const uint32_t blowfish_p[] = {
    0X243f6a88, 0X85a308d3, 0X13198a2e, 0X03707344,
    0Xa4093822, 0X299f31d0, 0X082efa98, 0Xec4e6c89,
    0X452821e6, 0X38d01377, 0Xbe5466cf, 0X34e90c6c,
    0Xc0ac29b7, 0Xc97c50dd, 0X3f84d5b5, 0Xb5470917,
    0X9216d5d9, 0X8979fb1b
};

static const uint32_t blowfish_s[] = {
    0Xd1310ba6, 0X98dfb5ac, 0X2ffd72db, 0Xd01adfb7,
    0Xb8e1afed, 0X6a267e96, 0Xba7c9045, 0Xf12c7f99,
    0X24a19947, 0Xb3916cf7, 0X0801f2e2, 0X858efc16,
    0X636920d8, 0X71574e69, 0Xa458fea3, 0Xf4933d7e,
    0X0d95748f, 0X728eb658, 0X718bcd58, 0X82154aee,
    0X7b54a41d, 0Xc25a59b5, 0X9c30d539, 0X2af26013,
    0Xc5d1b023, 0X286085f0, 0Xca417918, 0Xb8db38ef,
    0X8e79dcb0, 0X603a180e, 0X6c9e0e8b, 0Xb01e8a3e,
    0Xd71577c1, 0Xbd314b27, 0X78af2fda, 0X55605c60,
    0Xe65525f3, 0Xaa55ab94, 0X57489862, 0X63e81440,
    0X55ca396a, 0X2aab10b6, 0Xb4cc5c34, 0X1141e8ce,
    0Xa15486af, 0X7c72e993, 0Xb3ee1411, 0X636fbc2a,
    0X2ba9c55d, 0X741831f6, 0Xce5c3e16, 0X9b87931e,
    0Xafd6ba33, 0X6c24cf5c, 0X7a325381, 0X28958677,
    0X3b8f4898, 0X6b4bb9af, 0Xc4bfe81b, 0X66282193,
    0X61d809cc, 0Xfb21a991, 0X487cac60, 0X5dec8032,
    0Xef845d5d, 0Xe98575b1, 0Xdc262302, 0Xeb651b88,
    0X23893e81, 0Xd396acc5, 0X0f6d6ff3, 0X83f44239,
    0X2e0b4482, 0Xa4842004, 0X69c8f04a, 0X9e1f9b5e,
    0X21c66842, 0Xf6e96c9a, 0X670c9c61, 0Xabd388f0,
    0X6a51a0d2, 0Xd8542f68, 0X960fa728, 0Xab5133a3,
    0X6eef0b6c, 0X137a3be4, 0Xba3bf050, 0X7efb2a98,
    0Xa1f1651d, 0X39af0176, 0X66ca593e, 0X82430e88,
    0X8cee8619, 0X456f9fb4, 0X7d84a5c3, 0X3b8b5ebe,
    0Xe06f75d8, 0X85c12073, 0X401a449f, 0X56c16aa6,
    0X4ed3aa62, 0X363f7706, 0X1bfedf72, 0X429b023d,
    0X37d0d724, 0Xd00a1248, 0Xdb0fead3, 0X49f1c09b,
    0X075372c9, 0X80991b7b, 0X25d479d8, 0Xf6e8def7,
    0Xe3fe501a, 0Xb6794c3b, 0X976ce0bd, 0X04c006ba,
    0Xc1a94fb6, 0X409f60c4, 0X5e5c9ec2, 0X196a2463,
    0X68fb6faf, 0X3e6c53b5, 0X1339b2eb, 0X3b52ec6f,
    0X6dfc511f, 0X9b30952c, 0Xcc814544, 0Xaf5ebd09,
    0Xbee3d004, 0Xde334afd, 0X660f2807, 0X192e4bb3,
    0Xc0cba857, 0X45c8740f, 0Xd20b5f39, 0Xb9d3fbdb,
    0X5579c0bd, 0X1a60320a, 0Xd6a100c6, 0X402c7279,
    0X679f25fe, 0Xfb1fa3cc, 0X8ea5e9f8, 0Xdb3222f8,
    0X3c7516df, 0Xfd616b15, 0X2f501ec8, 0Xad0552ab,
    0X323db5fa, 0Xfd238760, 0X53317b48, 0X3e00df82,
    0X9e5c57bb, 0Xca6f8ca0, 0X1a87562e, 0Xdf1769db,
    0Xd542a8f6, 0X287effc3, 0Xac6732c6, 0X8c4f5573,
    0X695b27b0, 0Xbbca58c8, 0Xe1ffa35d, 0Xb8f011a0,
    0X10fa3d98, 0Xfd2183b8, 0X4afcb56c, 0X2dd1d35b,
    0X9a53e479, 0Xb6f84565, 0Xd28e49bc, 0X4bfb9790,
    0Xe1ddf2da, 0Xa4cb7e33, 0X62fb1341, 0Xcee4c6e8,
    0Xef20cada, 0X36774c01, 0Xd07e9efe, 0X2bf11fb4,
    0X95dbda4d, 0Xae909198, 0Xeaad8e71, 0X6b93d5a0,
    0Xd08ed1d0, 0Xafc725e0, 0X8e3c5b2f, 0X8e7594b7,
    0X8ff6e2fb, 0Xf2122b64, 0X8888b812, 0X900df01c,
    0X4fad5ea0, 0X688fc31c, 0Xd1cff191, 0Xb3a8c1ad,
    0X2f2f2218, 0Xbe0e1777, 0Xea752dfe, 0X8b021fa1,
    0Xe5a0cc0f, 0Xb56f74e8, 0X18acf3d6, 0Xce89e299,
    0Xb4a84fe0, 0Xfd13e0b7, 0X7cc43b81, 0Xd2ada8d9,
    0X165fa266, 0X80957705, 0X93cc7314, 0X211a1477,
    0Xe6ad2065, 0X77b5fa86, 0Xc75442f5, 0Xfb9d35cf,
    0Xebcdaf0c, 0X7b3e89a0, 0Xd6411bd3, 0Xae1e7e49,
    0X00250e2d, 0X2071b35e, 0X226800bb, 0X57b8e0af,
    0X2464369b, 0Xf009b91e, 0X5563911d, 0X59dfa6aa,
    0X78c14389, 0Xd95a537f, 0X207d5ba2, 0X02e5b9c5,
    0X83260376, 0X6295cfa9, 0X11c81968, 0X4e734a41,
    0Xb3472dca, 0X7b14a94a, 0X1b510052, 0X9a532915,
    0Xd60f573f, 0Xbc9bc6e4, 0X2b60a476, 0X81e67400,
    0X08ba6fb5, 0X571be91f, 0Xf296ec6b, 0X2a0dd915,
    0Xb6636521, 0Xe7b9f9b6, 0Xff34052e, 0Xc5855664,
    0X53b02d5d, 0Xa99f8fa1, 0X08ba4799, 0X6e85076a,
    0X4b7a70e9, 0Xb5b32944, 0Xdb75092e, 0Xc4192623,
    0Xad6ea6b0, 0X49a7df7d, 0X9cee60b8, 0X8fedb266,
    0Xecaa8c71, 0X699a17ff, 0X5664526c, 0Xc2b19ee1,
    0X193602a5, 0X75094c29, 0Xa0591340, 0Xe4183a3e,
    0X3f54989a, 0X5b429d65, 0X6b8fe4d6, 0X99f73fd6,
    0Xa1d29c07, 0Xefe830f5, 0X4d2d38e6, 0Xf0255dc1,
    0X4cdd2086, 0X8470eb26, 0X6382e9c6, 0X021ecc5e,
    0X09686b3f, 0X3ebaefc9, 0X3c971814, 0X6b6a70a1,
    0X687f3584, 0X52a0e286, 0Xb79c5305, 0Xaa500737,
    0X3e07841c, 0X7fdeae5c, 0X8e7d44ec, 0X5716f2b8,
    0Xb03ada37, 0Xf0500c0d, 0Xf01c1f04, 0X0200b3ff,
    0Xae0cf51a, 0X3cb574b2, 0X25837a58, 0Xdc0921bd,
    0Xd19113f9, 0X7ca92ff6, 0X94324773, 0X22f54701,
    0X3ae5e581, 0X37c2dadc, 0Xc8b57634, 0X9af3dda7,
    0Xa9446146, 0X0fd0030e, 0Xecc8c73e, 0Xa4751e41,
    0Xe238cd99, 0X3bea0e2f, 0X3280bba1, 0X183eb331,
    0X4e548b38, 0X4f6db908, 0X6f420d03, 0Xf60a04bf,
    0X2cb81290, 0X24977c79, 0X5679b072, 0Xbcaf89af,
    0Xde9a771f, 0Xd9930810, 0Xb38bae12, 0Xdccf3f2e,
    0X5512721f, 0X2e6b7124, 0X501adde6, 0X9f84cd87,
    0X7a584718, 0X7408da17, 0Xbc9f9abc, 0Xe94b7d8c,
    0Xec7aec3a, 0Xdb851dfa, 0X63094366, 0Xc464c3d2,
    0Xef1c1847, 0X3215d908, 0Xdd433b37, 0X24c2ba16,
    0X12a14d43, 0X2a65c451, 0X50940002, 0X133ae4dd,
    0X71dff89e, 0X10314e55, 0X81ac77d6, 0X5f11199b,
    0X043556f1, 0Xd7a3c76b, 0X3c11183b, 0X5924a509,
    0Xf28fe6ed, 0X97f1fbfa, 0X9ebabf2c, 0X1e153c6e,
    0X86e34570, 0Xeae96fb1, 0X860e5e0a, 0X5a3e2ab3,
    0X771fe71c, 0X4e3d06fa, 0X2965dcb9, 0X99e71d0f,
    0X803e89d6, 0X5266c825, 0X2e4cc978, 0X9c10b36a,
    0Xc6150eba, 0X94e2ea78, 0Xa5fc3c53, 0X1e0a2df4,
    0Xf2f74ea7, 0X361d2b3d, 0X1939260f, 0X19c27960,
    0X5223a708, 0Xf71312b6, 0Xebadfe6e, 0Xeac31f66,
    0Xe3bc4595, 0Xa67bc883, 0Xb17f37d1, 0X018cff28,
    0Xc332ddef, 0Xbe6c5aa5, 0X65582185, 0X68ab9802,
    0Xeecea50f, 0Xdb2f953b, 0X2aef7dad, 0X5b6e2f84,
    0X1521b628, 0X29076170, 0Xecdd4775, 0X619f1510,
    0X13cca830, 0Xeb61bd96, 0X0334fe1e, 0Xaa0363cf,
    0Xb5735c90, 0X4c70a239, 0Xd59e9e0b, 0Xcbaade14,
    0Xeecc86bc, 0X60622ca7, 0X9cab5cab, 0Xb2f3846e,
    0X648b1eaf, 0X19bdf0ca, 0Xa02369b9, 0X655abb50,
    0X40685a32, 0X3c2ab4b3, 0X319ee9d5, 0Xc021b8f7,
    0X9b540b19, 0X875fa099, 0X95f7997e, 0X623d7da8,
    0Xf837889a, 0X97e32d77, 0X11ed935f, 0X16681281,
    0X0e358829, 0Xc7e61fd6, 0X96dedfa1, 0X7858ba99,
    0X57f584a5, 0X1b227263, 0X9b83c3ff, 0X1ac24696,
    0Xcdb30aeb, 0X532e3054, 0X8fd948e4, 0X6dbc3128,
    0X58ebf2ef, 0X34c6ffea, 0Xfe28ed61, 0Xee7c3c73,
    0X5d4a14d9, 0Xe864b7e3, 0X42105d14, 0X203e13e0,
    0X45eee2b6, 0Xa3aaabea, 0Xdb6c4f15, 0Xfacb4fd0,
    0Xc742f442, 0Xef6abbb5, 0X654f3b1d, 0X41cd2105,
    0Xd81e799e, 0X86854dc7, 0Xe44b476a, 0X3d816250,
    0Xcf62a1f2, 0X5b8d2646, 0Xfc8883a0, 0Xc1c7b6a3,
    0X7f1524c3, 0X69cb7492, 0X47848a0b, 0X5692b285,
    0X095bbf00, 0Xad19489d, 0X1462b174, 0X23820e00,
    0X58428d2a, 0X0c55f5ea, 0X1dadf43e, 0X233f7061,
    0X3372f092, 0X8d937e41, 0Xd65fecf1, 0X6c223bdb,
    0X7cde3759, 0Xcbee7460, 0X4085f2a7, 0Xce77326e,
    0Xa6078084, 0X19f8509e, 0Xe8efd855, 0X61d99735,
    0Xa969a7aa, 0Xc50c06c2, 0X5a04abfc, 0X800bcadc,
    0X9e447a2e, 0Xc3453484, 0Xfdd56705, 0X0e1e9ec9,
    0Xdb73dbd3, 0X105588cd, 0X675fda79, 0Xe3674340,
    0Xc5c43465, 0X713e38d8, 0X3d28f89e, 0Xf16dff20,
    0X153e21e7, 0X8fb03d4a, 0Xe6e39f2b, 0Xdb83adf7,
    0Xe93d5a68, 0X948140f7, 0Xf64c261c, 0X94692934,
    0X411520f7, 0X7602d4f7, 0Xbcf46b2e, 0Xd4a20068,
    0Xd4082471, 0X3320f46a, 0X43b7d4b7, 0X500061af,
    0X1e39f62e, 0X97244546, 0X14214f74, 0Xbf8b8840,
    0X4d95fc1d, 0X96b591af, 0X70f4ddd3, 0X66a02f45,
    0Xbfbc09ec, 0X03bd9785, 0X7fac6dd0, 0X31cb8504,
    0X96eb27b3, 0X55fd3941, 0Xda2547e6, 0Xabca0a9a,
    0X28507825, 0X530429f4, 0X0a2c86da, 0Xe9b66dfb,
    0X68dc1462, 0Xd7486900, 0X680ec0a4, 0X27a18dee,
    0X4f3ffea2, 0Xe887ad8c, 0Xb58ce006, 0X7af4d6b6,
    0Xaace1e7c, 0Xd3375fec, 0Xce78a399, 0X406b2a42,
    0X20fe9e35, 0Xd9f385b9, 0Xee39d7ab, 0X3b124e8b,
    0X1dc9faf7, 0X4b6d1856, 0X26a36631, 0Xeae397b2,
    0X3a6efa74, 0Xdd5b4332, 0X6841e7f7, 0Xca7820fb,
    0Xfb0af54e, 0Xd8feb397, 0X454056ac, 0Xba489527,
    0X55533a3a, 0X20838d87, 0Xfe6ba9b7, 0Xd096954b,
    0X55a867bc, 0Xa1159a58, 0Xcca92963, 0X99e1db33,
    0Xa62a4a56, 0X3f3125f9, 0X5ef47e1c, 0X9029317c,
    0Xfdf8e802, 0X04272f70, 0X80bb155c, 0X05282ce3,
    0X95c11548, 0Xe4c66d22, 0X48c1133f, 0Xc70f86dc,
    0X07f9c9ee, 0X41041f0f, 0X404779a4, 0X5d886e17,
    0X325f51eb, 0Xd59bc0d1, 0Xf2bcc18f, 0X41113564,
    0X257b7834, 0X602a9c60, 0Xdff8e8a3, 0X1f636c1b,
    0X0e12b4c2, 0X02e1329e, 0Xaf664fd1, 0Xcad18115,
    0X6b2395e0, 0X333e92e1, 0X3b240b62, 0Xeebeb922,
    0X85b2a20e, 0Xe6ba0d99, 0Xde720c8c, 0X2da2f728,
    0Xd0127845, 0X95b794fd, 0X647d0862, 0Xe7ccf5f0,
    0X5449a36f, 0X877d48fa, 0Xc39dfd27, 0Xf33e8d1e,
    0X0a476341, 0X992eff74, 0X3a6f6eab, 0Xf4f8fd37,
    0Xa812dc60, 0Xa1ebddf8, 0X991be14c, 0Xdb6e6b0d,
    0Xc67b5510, 0X6d672c37, 0X2765d43b, 0Xdcd0e804,
    0Xf1290dc7, 0Xcc00ffa3, 0Xb5390f92, 0X690fed0b,
    0X667b9ffb, 0Xcedb7d9c, 0Xa091cf0b, 0Xd9155ea3,
    0Xbb132f88, 0X515bad24, 0X7b9479bf, 0X763bd6eb,
    0X37392eb3, 0Xcc115979, 0X8026e297, 0Xf42e312d,
    0X6842ada7, 0Xc66a2b3b, 0X12754ccc, 0X782ef11c,
    0X6a124237, 0Xb79251e7, 0X06a1bbe6, 0X4bfb6350,
    0X1a6b1018, 0X11caedfa, 0X3d25bdd8, 0Xe2e1c3c9,
    0X44421659, 0X0a121386, 0Xd90cec6e, 0Xd5abea2a,
    0X64af674e, 0Xda86a85f, 0Xbebfe988, 0X64e4c3fe,
    0X9dbc8057, 0Xf0f7c086, 0X60787bf8, 0X6003604d,
    0Xd1fd8346, 0Xf6381fb0, 0X7745ae04, 0Xd736fccc,
    0X83426b33, 0Xf01eab71, 0Xb0804187, 0X3c005e5f,
    0X77a057be, 0Xbde8ae24, 0X55464299, 0Xbf582e61,
    0X4e58f48f, 0Xf2ddfda2, 0Xf474ef38, 0X8789bdc2,
    0X5366f9c3, 0Xc8b38e74, 0Xb475f255, 0X46fcd9b9,
    0X7aeb2661, 0X8b1ddf84, 0X846a0e79, 0X915f95e2,
    0X466e598e, 0X20b45770, 0X8cd55591, 0Xc902de4c,
    0Xb90bace1, 0Xbb8205d0, 0X11a86248, 0X7574a99e,
    0Xb77f19b6, 0Xe0a9dc09, 0X662d09a1, 0Xc4324633,
    0Xe85a1f02, 0X09f0be8c, 0X4a99a025, 0X1d6efe10,
    0X1ab93d1d, 0X0ba5a4df, 0Xa186f20f, 0X2868f169,
    0Xdcb7da83, 0X573906fe, 0Xa1e2ce9b, 0X4fcd7f52,
    0X50115e01, 0Xa70683fa, 0Xa002b5c4, 0X0de6d027,
    0X9af88c27, 0X773f8641, 0Xc3604c06, 0X61a806b5,
    0Xf0177a28, 0Xc0f586e0, 0X006058aa, 0X30dc7d62,
    0X11e69ed7, 0X2338ea63, 0X53c2dd94, 0Xc2c21634,
    0Xbbcbee56, 0X90bcb6de, 0Xebfc7da1, 0Xce591d76,
    0X6f05e409, 0X4b7c0188, 0X39720a3d, 0X7c927c24,
    0X86e3725f, 0X724d9db9, 0X1ac15bb4, 0Xd39eb8fc,
    0Xed545578, 0X08fca5b5, 0Xd83d7cd3, 0X4dad0fc4,
    0X1e50ef5e, 0Xb161e6f8, 0Xa28514d9, 0X6c51133c,
    0X6fd5c7e7, 0X56e14ec4, 0X362abfce, 0Xddc6c837,
    0Xd79a3234, 0X92638212, 0X670efa8e, 0X406000e0,
    0X3a39ce37, 0Xd3faf5cf, 0Xabc27737, 0X5ac52d1b,
    0X5cb0679e, 0X4fa33742, 0Xd3822740, 0X99bc9bbe,
    0Xd5118e9d, 0Xbf0f7315, 0Xd62d1c7e, 0Xc700c47b,
    0Xb78c1b6b, 0X21a19045, 0Xb26eb1be, 0X6a366eb4,
    0X5748ab2f, 0Xbc946e79, 0Xc6a376d2, 0X6549c2c8,
    0X530ff8ee, 0X468dde7d, 0Xd5730a1d, 0X4cd04dc6,
    0X2939bbdb, 0Xa9ba4650, 0Xac9526e8, 0Xbe5ee304,
    0Xa1fad5f0, 0X6a2d519a, 0X63ef8ce2, 0X9a86ee22,
    0Xc089c2b8, 0X43242ef6, 0Xa51e03aa, 0X9cf2d0a4,
    0X83c061ba, 0X9be96a4d, 0X8fe51550, 0Xba645bd6,
    0X2826a2f9, 0Xa73a3ae1, 0X4ba99586, 0Xef5562e9,
    0Xc72fefd3, 0Xf752f7da, 0X3f046f69, 0X77fa0a59,
    0X80e4a915, 0X87b08601, 0X9b09e6ad, 0X3b3ee593,
    0Xe990fd5a, 0X9e34d797, 0X2cf0b7d9, 0X022b8b51,
    0X96d5ac3a, 0X017da67d, 0Xd1cf3ed6, 0X7c7d2d28,
    0X1f9f25cf, 0Xadf2b89b, 0X5ad6b472, 0X5a88f54c,
    0Xe029ac71, 0Xe019a5e6, 0X47b0acfd, 0Xed93fa9b,
    0Xe8d3c48d, 0X283b57cc, 0Xf8d56629, 0X79132e28,
    0X785f0191, 0Xed756055, 0Xf7960e44, 0Xe3d35e8c,
    0X15056dd4, 0X88f46dba, 0X03a16125, 0X0564f0bd,
    0Xc3eb9e15, 0X3c9057a2, 0X97271aec, 0Xa93a072a,
    0X1b3f6d9b, 0X1e6321f5, 0Xf59c66fb, 0X26dcf319,
    0X7533d928, 0Xb155fdf5, 0X03563482, 0X8aba3cbb,
    0X28517711, 0Xc20ad9f8, 0Xabcc5167, 0Xccad925f,
    0X4de81751, 0X3830dc8e, 0X379d5862, 0X9320f991,
    0Xea7a90c2, 0Xfb3e7bce, 0X5121ce64, 0X774fbe32,
    0Xa8b6e37e, 0Xc3293d46, 0X48de5369, 0X6413e680,
    0Xa2ae0810, 0Xdd6db224, 0X69852dfd, 0X09072166,
    0Xb39a460a, 0X6445c0dd, 0X586cdecf, 0X1c20c8ae,
    0X5bbef7dd, 0X1b588d40, 0Xccd2017f, 0X6bb4e3bb,
    0Xdda26a7e, 0X3a59ff45, 0X3e350a44, 0Xbcb4cdd5,
    0X72eacea8, 0Xfa6484bb, 0X8d6612ae, 0Xbf3c6f47,
    0Xd29be463, 0X542f5d9e, 0Xaec2771b, 0Xf64e6370,
    0X740e0d8d, 0Xe75b1357, 0Xf8721671, 0Xaf537d5d,
    0X4040cb08, 0X4eb4e2cc, 0X34d2466a, 0X0115af84,
    0Xe1b00428, 0X95983a1d, 0X06b89fb4, 0Xce6ea048,
    0X6f3f3b82, 0X3520ab82, 0X011a1d4b, 0X277227f8,
    0X611560b1, 0Xe7933fdc, 0Xbb3a792b, 0X344525bd,
    0Xa08839e1, 0X51ce794b, 0X2f32c9b7, 0Xa01fbac9,
    0Xe01cc87e, 0Xbcc7d1f6, 0Xcf0111c3, 0Xa1e8aac7,
    0X1a908749, 0Xd44fbd9a, 0Xd0dadecb, 0Xd50ada38,
    0X0339c32a, 0Xc6913667, 0X8df9317c, 0Xe0b12b4f,
    0Xf79e59b7, 0X43f5bb3a, 0Xf2d519ff, 0X27d9459c,
    0Xbf97222c, 0X15e6fc2a, 0X0f91fc71, 0X9b941525,
    0Xfae59361, 0Xceb69ceb, 0Xc2a86459, 0X12baa8d1,
    0Xb6c1075e, 0Xe3056a0c, 0X10d25065, 0Xcb03a442,
    0Xe0ec6e0e, 0X1698db3b, 0X4c98a0be, 0X3278e964,
    0X9f1f9532, 0Xe0d392df, 0Xd3a0342b, 0X8971f21e,
    0X1b0a7441, 0X4ba3348c, 0Xc5be7120, 0Xc37632d8,
    0Xdf359f8d, 0X9b992f2e, 0Xe60b6f47, 0X0fe3f11d,
    0Xe54cda54, 0X1edad891, 0Xce6279cf, 0Xcd3e7e6f,
    0X1618b166, 0Xfd2c1d05, 0X848fd2c5, 0Xf6fb2299,
    0Xf523f357, 0Xa6327623, 0X93a83531, 0X56cccd02,
    0Xacf08162, 0X5a75ebb5, 0X6e163697, 0X88d273cc,
    0Xde966292, 0X81b949d0, 0X4c50901b, 0X71c65614,
    0Xe6c6c7bd, 0X327a140a, 0X45e1d006, 0Xc3f27b9a,
    0Xc9aa53fd, 0X62a80f00, 0Xbb25bfe2, 0X35bdd2f6,
    0X71126905, 0Xb2040222, 0Xb6cbcf7c, 0Xcd769c2b,
    0X53113ec0, 0X1640e3d3, 0X38abbd60, 0X2547adf0,
    0Xba38209c, 0Xf746ce76, 0X77afa1c5, 0X20756060,
    0X85cbfe4e, 0X8ae88dd8, 0X7aaaf9b0, 0X4cf9aa7e,
    0X1948c25c, 0X02fb8a8c, 0X01c36ae4, 0Xd6ebe1f9,
    0X90d4f869, 0Xa65cdea0, 0X3f09252d, 0Xc208e69f,
    0Xb74e6132, 0Xce77e25b, 0X578fdfe3, 0X3ac372e6,
};

static uint32_t
blowfish_f(uint32_t s[4][256], uint32_t x)
{
    /* big endian */
    uint32_t b = 0xff;
    uint32_t h = s[0][(x >> 24) & b]  + s[1][(x >> 16) & b];
    return  (h ^ s[2][(x >>  8) & b]) + s[3][(x >>  0) & b];
}

static uint32_t
blowfish_read(const uint8_t *p)
{
    /* big endian */
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | (p[3] << 0);
}

static void
blowfish_write(uint8_t *p, uint32_t v)
{
    /* big endian */
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v >>  0);
}

void
blowfish_encrypt(struct blowfish *ctx, void *dst, const void *src, size_t len)
{
    for (size_t n = 0; n < len; n += 8) {
        uint32_t xl = blowfish_read((uint8_t *)src + n + 0);
        uint32_t xr = blowfish_read((uint8_t *)src + n + 4);
        for (int i = 0; i < 16; i += 2) {
            xl ^= ctx->p[i];
            xr ^= blowfish_f(ctx->s, xl);
            xr ^= ctx->p[i + 1];
            xl ^= blowfish_f(ctx->s, xr);
        }
        xl ^= ctx->p[16];
        xr ^= ctx->p[17];
        blowfish_write((uint8_t *)dst + n + 0, xr);
        blowfish_write((uint8_t *)dst + n + 4, xl);
    }
}

void
blowfish_decrypt(struct blowfish *ctx, void *dst, const void *src, size_t len)
{
    for (size_t n = 0; n < len; n += 8) {
        uint32_t xl = blowfish_read((uint8_t *)src + n + 0);
        uint32_t xr = blowfish_read((uint8_t *)src + n + 4);
        for (int i = 16; i > 0; i -= 2) {
            xl ^= ctx->p[i + 1];
            xr ^= blowfish_f(ctx->s, xl);
            xr ^= ctx->p[i];
            xl ^= blowfish_f(ctx->s, xr);
        }
        xl ^= ctx->p[1];
        xr ^= ctx->p[0];
        blowfish_write((uint8_t *)dst + n + 0, xr);
        blowfish_write((uint8_t *)dst + n + 4, xl);
    }
}

void
blowfish_init(struct blowfish *ctx, const void *key, int len)
{
    memcpy(ctx->s, blowfish_s, sizeof(blowfish_s));
    memcpy(ctx->p, blowfish_p, sizeof(blowfish_p));

    const uint8_t *k = key;
    for (int i = 0; i < 18; i++) {
        /* big endian */
        ctx->p[i] ^= k[(i * 4 + 0) % len] << 24;
        ctx->p[i] ^= k[(i * 4 + 1) % len] << 16;
        ctx->p[i] ^= k[(i * 4 + 2) % len] <<  8;
        ctx->p[i] ^= k[(i * 4 + 3) % len] <<  0;
    }

    uint8_t buf[8] = {0};
    for (int i = 0; i < 18; i += 2) {
        blowfish_encrypt(ctx, buf, buf, 8);
        ctx->p[i + 0] = blowfish_read(buf + 0);
        ctx->p[i + 1] = blowfish_read(buf + 4);
    }

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 256; j += 2) {
            blowfish_encrypt(ctx, buf, buf, 8);
            ctx->s[i][j + 0] = blowfish_read(buf + 0);
            ctx->s[i][j + 1] = blowfish_read(buf + 4);
        }
    }
}
