/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/


#include "komodo_defs.h"

#include "komodo_cJSON.h"

#define KOMODO_MAINNET_START 178999

const char *Notaries_genesis[][2] =
{
    { "jl777_testA", "03b7621b44118017a16043f19b30cc8a4cfe068ac4e42417bae16ba460c80f3828" },
    { "jl777_testB", "02ebfc784a4ba768aad88d44d1045d240d47b26e248cafaf1c5169a42d7a61d344" },
    { "pondsea_SH", "02209073bc0943451498de57f802650311b1f12aa6deffcd893da198a544c04f36" },
    { "crackers_EU", "0340c66cf2c41c41efb420af57867baa765e8468c12aa996bfd816e1e07e410728" },
    { "pondsea_EU", "0225aa6f6f19e543180b31153d9e6d55d41bc7ec2ba191fd29f19a2f973544e29d" },
    { "locomb_EU", "025c6d26649b9d397e63323d96db42a9d3caad82e1d6076970efe5056c00c0779b" },
    { "fullmoon_AE", "0204a908350b8142698fdb6fabefc97fe0e04f537adc7522ba7a1e8f3bec003d4a" },
    { "movecrypto_EU", "021ab53bc6cf2c46b8a5456759f9d608966eff87384c2b52c0ac4cc8dd51e9cc42" },
    { "badass_EU", "0209d48554768dd8dada988b98aca23405057ac4b5b46838a9378b95c3e79b9b9e" },
    { "crackers_NA", "029e1c01131974f4cd3f564cc0c00eb87a0f9721043fbc1ca60f9bd0a1f73f64a1" },
    { "proto_EU", "03681ffdf17c8f4f0008cefb7fa0779c5e888339cdf932f0974483787a4d6747c1" }, // 10
    { "jeezy_EU", "023cb3e593fb85c5659688528e9a4f1c4c7f19206edc7e517d20f794ba686fd6d6" },
    { "farl4web_EU", "035caa40684ace968677dca3f09098aa02b70e533da32390a7654c626e0cf908e1" },
    { "nxtswe_EU", "032fb104e5eaa704a38a52c126af8f67e870d70f82977e5b2f093d5c1c21ae5899" },
    { "traderbill_EU", "03196e8de3e2e5d872f31d79d6a859c8704a2198baf0af9c7b21e29656a7eb455f" },
    { "vanbreuk_EU", "024f3cad7601d2399c131fd070e797d9cd8533868685ddbe515daa53c2e26004c3" }, // 15
    { "titomane_EU", "03517fcac101fed480ae4f2caf775560065957930d8c1facc83e30077e45bdd199" },
    { "supernet_AE", "029d93ef78197dc93892d2a30e5a54865f41e0ca3ab7eb8e3dcbc59c8756b6e355" },
    { "supernet_EU", "02061c6278b91fd4ac5cab4401100ffa3b2d5a277e8f71db23401cc071b3665546" },
    { "supernet_NA", "033c073366152b6b01535e15dd966a3a8039169584d06e27d92a69889b720d44e1" },
    { "yassin_EU", "033fb7231bb66484081952890d9a03f91164fb27d392d9152ec41336b71b15fbd0" }, // 20
    { "durerus_EU", "02bcbd287670bdca2c31e5d50130adb5dea1b53198f18abeec7211825f47485d57" },
    { "badass_SH", "026b49dd3923b78a592c1b475f208e23698d3f085c4c3b4906a59faf659fd9530b" },
    { "badass_NA", "02afa1a9f948e1634a29dc718d218e9d150c531cfa852843a1643a02184a63c1a7" },
    { "pondsea_NA", "031bcfdbb62268e2ff8dfffeb9ddff7fe95fca46778c77eebff9c3829dfa1bb411" },
    { "rnr_EU", "0287aa4b73988ba26cf6565d815786caf0d2c4af704d7883d163ee89cd9977edec" },
    { "crackers_SH", "02313d72f9a16055737e14cfc528dcd5d0ef094cfce23d0348fe974b6b1a32e5f0" },
    { "grewal_SH", "03212a73f5d38a675ee3cdc6e82542a96c38c3d1c79d25a1ed2e42fcf6a8be4e68" },
    { "polycryptoblock_NA", "02708dcda7c45fb54b78469673c2587bfdd126e381654819c4c23df0e00b679622" },
    { "titomane_NA", "0387046d9745414fb58a0fa3599078af5073e10347e4657ef7259a99cb4f10ad47" },
    { "titomane_AE", "03cda6ca5c2d02db201488a54a548dbfc10533bdc275d5ea11928e8d6ab33c2185" },
    { "kolo_EU", "03f5c08dadffa0ffcafb8dd7ffc38c22887bd02702a6c9ac3440deddcf2837692b" },
    { "artik_NA", "0224e31f93eff0cc30eaf0b2389fbc591085c0e122c4d11862c1729d090106c842" },
    { "eclips_EU", "0339369c1f5a2028d44be7be6f8ec3b907fdec814f87d2dead97cab4edb71a42e9" },
    { "titomane_SH", "035f49d7a308dd9a209e894321f010d21b7793461b0c89d6d9231a3fe5f68d9960" },
};

const char *Notaries_elected0[][2] =
{
    { "0_jl777_testA", "03b7621b44118017a16043f19b30cc8a4cfe068ac4e42417bae16ba460c80f3828" },
    { "0_jl777_testB", "02ebfc784a4ba768aad88d44d1045d240d47b26e248cafaf1c5169a42d7a61d344" },
    { "0_kolo_testA", "0287aa4b73988ba26cf6565d815786caf0d2c4af704d7883d163ee89cd9977edec" },
    { "artik_AR", "029acf1dcd9f5ff9c455f8bb717d4ae0c703e089d16cf8424619c491dff5994c90" },
    { "artik_EU", "03f54b2c24f82632e3cdebe4568ba0acf487a80f8a89779173cdb78f74514847ce" },
    { "artik_NA", "0224e31f93eff0cc30eaf0b2389fbc591085c0e122c4d11862c1729d090106c842" },
    { "artik_SH", "02bdd8840a34486f38305f311c0e2ae73e84046f6e9c3dd3571e32e58339d20937" },
    { "badass_EU", "0209d48554768dd8dada988b98aca23405057ac4b5b46838a9378b95c3e79b9b9e" },
    { "badass_NA", "02afa1a9f948e1634a29dc718d218e9d150c531cfa852843a1643a02184a63c1a7" },
    { "badass_SH", "026b49dd3923b78a592c1b475f208e23698d3f085c4c3b4906a59faf659fd9530b" },
    { "crackers_EU", "03bc819982d3c6feb801ec3b720425b017d9b6ee9a40746b84422cbbf929dc73c3" }, // 10
    { "crackers_NA", "03205049103113d48c7c7af811b4c8f194dafc43a50d5313e61a22900fc1805b45" },
    { "crackers_SH", "02be28310e6312d1dd44651fd96f6a44ccc269a321f907502aae81d246fabdb03e" },
    { "durerus_EU", "02bcbd287670bdca2c31e5d50130adb5dea1b53198f18abeec7211825f47485d57" },
    { "etszombi_AR", "031c79168d15edabf17d9ec99531ea9baa20039d0cdc14d9525863b83341b210e9" },
    { "etszombi_EU", "0281b1ad28d238a2b217e0af123ce020b79e91b9b10ad65a7917216eda6fe64bf7" }, // 15
    { "etszombi_SH", "025d7a193c0757f7437fad3431f027e7b5ed6c925b77daba52a8755d24bf682dde" },
    { "farl4web_EU", "0300ecf9121cccf14cf9423e2adb5d98ce0c4e251721fa345dec2e03abeffbab3f" },
    { "farl4web_SH", "0396bb5ed3c57aa1221d7775ae0ff751e4c7dc9be220d0917fa8bbdf670586c030" },
    { "fullmoon_AR", "0254b1d64840ce9ff6bec9dd10e33beb92af5f7cee628f999cb6bc0fea833347cc" },
    { "fullmoon_NA", "031fb362323b06e165231c887836a8faadb96eda88a79ca434e28b3520b47d235b" }, // 20
    { "fullmoon_SH", "030e12b42ec33a80e12e570b6c8274ce664565b5c3da106859e96a7208b93afd0d" },
    { "grewal_NA", "03adc0834c203d172bce814df7c7a5e13dc603105e6b0adabc942d0421aefd2132" },
    { "grewal_SH", "03212a73f5d38a675ee3cdc6e82542a96c38c3d1c79d25a1ed2e42fcf6a8be4e68" },
    { "indenodes_AR", "02ec0fa5a40f47fd4a38ea5c89e375ad0b6ddf4807c99733c9c3dc15fb978ee147" },
    { "indenodes_EU", "0221387ff95c44cb52b86552e3ec118a3c311ca65b75bf807c6c07eaeb1be8303c" },
    { "indenodes_NA", "02698c6f1c9e43b66e82dbb163e8df0e5a2f62f3a7a882ca387d82f86e0b3fa988" },
    { "indenodes_SH", "0334e6e1ec8285c4b85bd6dae67e17d67d1f20e7328efad17ce6fd24ae97cdd65e" },
    { "jeezy_EU", "023cb3e593fb85c5659688528e9a4f1c4c7f19206edc7e517d20f794ba686fd6d6" },
    { "jsgalt_NA", "027b3fb6fede798cd17c30dbfb7baf9332b3f8b1c7c513f443070874c410232446" },
    { "karasugoi_NA", "02a348b03b9c1a8eac1b56f85c402b041c9bce918833f2ea16d13452309052a982" }, // 30
    { "kashifali_EU", "033777c52a0190f261c6f66bd0e2bb299d30f012dcb8bfff384103211edb8bb207" },
    { "kolo_AR", "03016d19344c45341e023b72f9fb6e6152fdcfe105f3b4f50b82a4790ff54e9dc6" },
    { "kolo_SH", "02aa24064500756d9b0959b44d5325f2391d8e95c6127e109184937152c384e185" },
    { "metaphilibert_AR", "02adad675fae12b25fdd0f57250b0caf7f795c43f346153a31fe3e72e7db1d6ac6" },
    { "movecrypto_AR", "022783d94518e4dc77cbdf1a97915b29f427d7bc15ea867900a76665d3112be6f3" },
    { "movecrypto_EU", "021ab53bc6cf2c46b8a5456759f9d608966eff87384c2b52c0ac4cc8dd51e9cc42" },
    { "movecrypto_NA", "02efb12f4d78f44b0542d1c60146738e4d5506d27ec98a469142c5c84b29de0a80" },
    { "movecrypto_SH", "031f9739a3ebd6037a967ce1582cde66e79ea9a0551c54731c59c6b80f635bc859" },
    { "muros_AR", "022d77402fd7179335da39479c829be73428b0ef33fb360a4de6890f37c2aa005e" },
    { "noashh_AR", "029d93ef78197dc93892d2a30e5a54865f41e0ca3ab7eb8e3dcbc59c8756b6e355" }, // 40
    { "noashh_EU", "02061c6278b91fd4ac5cab4401100ffa3b2d5a277e8f71db23401cc071b3665546" },
    { "noashh_NA", "033c073366152b6b01535e15dd966a3a8039169584d06e27d92a69889b720d44e1" },
    { "nxtswe_EU", "032fb104e5eaa704a38a52c126af8f67e870d70f82977e5b2f093d5c1c21ae5899" },
    { "polycryptoblog_NA", "02708dcda7c45fb54b78469673c2587bfdd126e381654819c4c23df0e00b679622" },
    { "pondsea_AR", "032e1c213787312099158f2d74a89e8240a991d162d4ce8017d8504d1d7004f735" },
    { "pondsea_EU", "0225aa6f6f19e543180b31153d9e6d55d41bc7ec2ba191fd29f19a2f973544e29d" },
    { "pondsea_NA", "031bcfdbb62268e2ff8dfffeb9ddff7fe95fca46778c77eebff9c3829dfa1bb411" },
    { "pondsea_SH", "02209073bc0943451498de57f802650311b1f12aa6deffcd893da198a544c04f36" },
    { "popcornbag_AR", "02761f106fb34fbfc5ddcc0c0aa831ed98e462a908550b280a1f7bd32c060c6fa3" },
    { "popcornbag_NA", "03c6085c7fdfff70988fda9b197371f1caf8397f1729a844790e421ee07b3a93e8" }, // 50
    { "ptytrader_NA", "0328c61467148b207400b23875234f8a825cce65b9c4c9b664f47410b8b8e3c222" },
    { "ptytrader_SH", "0250c93c492d8d5a6b565b90c22bee07c2d8701d6118c6267e99a4efd3c7748fa4" },
    { "rnr_AR", "029bdb08f931c0e98c2c4ba4ef45c8e33a34168cb2e6bf953cef335c359d77bfcd" },
    { "rnr_EU", "03f5c08dadffa0ffcafb8dd7ffc38c22887bd02702a6c9ac3440deddcf2837692b" },
    { "rnr_NA", "02e17c5f8c3c80f584ed343b8dcfa6d710dfef0889ec1e7728ce45ce559347c58c" },
    { "rnr_SH", "037536fb9bdfed10251f71543fb42679e7c52308bcd12146b2568b9a818d8b8377" },
    { "titomane_AR", "03cda6ca5c2d02db201488a54a548dbfc10533bdc275d5ea11928e8d6ab33c2185" },
    { "titomane_EU", "02e41feded94f0cc59f55f82f3c2c005d41da024e9a805b41105207ef89aa4bfbd" },
    { "titomane_SH", "035f49d7a308dd9a209e894321f010d21b7793461b0c89d6d9231a3fe5f68d9960" },
    { "vanbreuk_EU", "024f3cad7601d2399c131fd070e797d9cd8533868685ddbe515daa53c2e26004c3" }, // 60
    { "xrobesx_NA", "03f0cc6d142d14a40937f12dbd99dbd9021328f45759e26f1877f2a838876709e1" },
    { "xxspot1_XX", "02ef445a392fcaf3ad4176a5da7f43580e8056594e003eba6559a713711a27f955" },
    { "xxspot2_XX", "03d85b221ea72ebcd25373e7961f4983d12add66a92f899deaf07bab1d8b6f5573" }
};

#define KOMODO_NOTARIES_TIMESTAMP1 1525132800 // May 1st 2018 1530921600 // 7/7/2017
#define KOMODO_NOTARIES_HEIGHT1 ((814000 / KOMODO_ELECTION_GAP) * KOMODO_ELECTION_GAP)

const char *Notaries_elected1[][2] =
{
    {"0dev1_jl777", "03b7621b44118017a16043f19b30cc8a4cfe068ac4e42417bae16ba460c80f3828" },
    {"0dev2_kolo", "030f34af4b908fb8eb2099accb56b8d157d49f6cfb691baa80fdd34f385efed961" },
    {"0dev3_kolo", "025af9d2b2a05338478159e9ac84543968fd18c45fd9307866b56f33898653b014" },
    {"0dev4_decker", "028eea44a09674dda00d88ffd199a09c9b75ba9782382cc8f1e97c0fd565fe5707" },
    {"a-team_SH", "03b59ad322b17cb94080dc8e6dc10a0a865de6d47c16fb5b1a0b5f77f9507f3cce" },
    {"artik_AR", "029acf1dcd9f5ff9c455f8bb717d4ae0c703e089d16cf8424619c491dff5994c90" },
    {"artik_EU", "03f54b2c24f82632e3cdebe4568ba0acf487a80f8a89779173cdb78f74514847ce" },
    {"artik_NA", "0224e31f93eff0cc30eaf0b2389fbc591085c0e122c4d11862c1729d090106c842" },
    {"artik_SH", "02bdd8840a34486f38305f311c0e2ae73e84046f6e9c3dd3571e32e58339d20937" },
    {"badass_EU", "0209d48554768dd8dada988b98aca23405057ac4b5b46838a9378b95c3e79b9b9e" },
    {"badass_NA", "02afa1a9f948e1634a29dc718d218e9d150c531cfa852843a1643a02184a63c1a7" }, // 10
    {"batman_AR", "033ecb640ec5852f42be24c3bf33ca123fb32ced134bed6aa2ba249cf31b0f2563" },
    {"batman_SH", "02ca5898931181d0b8aafc75ef56fce9c43656c0b6c9f64306e7c8542f6207018c" },
    {"ca333_EU", "03fc87b8c804f12a6bd18efd43b0ba2828e4e38834f6b44c0bfee19f966a12ba99" },
    {"chainmakers_EU", "02f3b08938a7f8d2609d567aebc4989eeded6e2e880c058fdf092c5da82c3bc5ee" },
    {"chainmakers_NA", "0276c6d1c65abc64c8559710b8aff4b9e33787072d3dda4ec9a47b30da0725f57a" },
    {"chainstrike_SH", "0370bcf10575d8fb0291afad7bf3a76929734f888228bc49e35c5c49b336002153" },
    {"cipi_AR", "02c4f89a5b382750836cb787880d30e23502265054e1c327a5bfce67116d757ce8" },
    {"cipi_NA", "02858904a2a1a0b44df4c937b65ee1f5b66186ab87a751858cf270dee1d5031f18" },
    {"crackers_EU", "03bc819982d3c6feb801ec3b720425b017d9b6ee9a40746b84422cbbf929dc73c3" },
    {"crackers_NA", "03205049103113d48c7c7af811b4c8f194dafc43a50d5313e61a22900fc1805b45" }, // 20
    {"dwy_EU", "0259c646288580221fdf0e92dbeecaee214504fdc8bbdf4a3019d6ec18b7540424" },
    {"emmanux_SH", "033f316114d950497fc1d9348f03770cd420f14f662ab2db6172df44c389a2667a" },
    {"etszombi_EU", "0281b1ad28d238a2b217e0af123ce020b79e91b9b10ad65a7917216eda6fe64bf7" },
    {"fullmoon_AR", "03380314c4f42fa854df8c471618751879f9e8f0ff5dbabda2bd77d0f96cb35676" },
    {"fullmoon_NA", "030216211d8e2a48bae9e5d7eb3a42ca2b7aae8770979a791f883869aea2fa6eef" },
    {"fullmoon_SH", "03f34282fa57ecc7aba8afaf66c30099b5601e98dcbfd0d8a58c86c20d8b692c64" },
    {"goldenman_EU", "02d6f13a8f745921cdb811e32237bb98950af1a5952be7b3d429abd9152f8e388d" },
    {"indenodes_AR", "02ec0fa5a40f47fd4a38ea5c89e375ad0b6ddf4807c99733c9c3dc15fb978ee147" },
    {"indenodes_EU", "0221387ff95c44cb52b86552e3ec118a3c311ca65b75bf807c6c07eaeb1be8303c" },
    {"indenodes_NA", "02698c6f1c9e43b66e82dbb163e8df0e5a2f62f3a7a882ca387d82f86e0b3fa988" }, // 30
    {"indenodes_SH", "0334e6e1ec8285c4b85bd6dae67e17d67d1f20e7328efad17ce6fd24ae97cdd65e" },
    {"jackson_AR", "038ff7cfe34cb13b524e0941d5cf710beca2ffb7e05ddf15ced7d4f14fbb0a6f69" },
    {"jeezy_EU", "023cb3e593fb85c5659688528e9a4f1c4c7f19206edc7e517d20f794ba686fd6d6" },
    {"karasugoi_NA", "02a348b03b9c1a8eac1b56f85c402b041c9bce918833f2ea16d13452309052a982" },
    {"komodoninja_EU", "038e567b99806b200b267b27bbca2abf6a3e8576406df5f872e3b38d30843cd5ba" },
    {"komodoninja_SH", "033178586896915e8456ebf407b1915351a617f46984001790f0cce3d6f3ada5c2" },
    {"komodopioneers_SH", "033ace50aedf8df70035b962a805431363a61cc4e69d99d90726a2d48fb195f68c" },
    {"libscott_SH", "03301a8248d41bc5dc926088a8cf31b65e2daf49eed7eb26af4fb03aae19682b95" },
    {"lukechilds_AR", "031aa66313ee024bbee8c17915cf7d105656d0ace5b4a43a3ab5eae1e14ec02696" },
    {"madmax_AR", "03891555b4a4393d655bf76f0ad0fb74e5159a615b6925907678edc2aac5e06a75" }, // 40
    {"meshbits_AR", "02957fd48ae6cb361b8a28cdb1b8ccf5067ff68eb1f90cba7df5f7934ed8eb4b2c" },
    {"meshbits_SH", "025c6e94877515dfd7b05682b9cc2fe4a49e076efe291e54fcec3add78183c1edb" },
    {"metaphilibert_AR", "02adad675fae12b25fdd0f57250b0caf7f795c43f346153a31fe3e72e7db1d6ac6" },
    {"metaphilibert_SH", "0284af1a5ef01503e6316a2ca4abf8423a794e9fc17ac6846f042b6f4adedc3309" },
    {"patchkez_SH", "0296270f394140640f8fa15684fc11255371abb6b9f253416ea2734e34607799c4" },
    {"pbca26_NA", "0276aca53a058556c485bbb60bdc54b600efe402a8b97f0341a7c04803ce204cb5" },
    {"peer2cloud_AR", "034e5563cb885999ae1530bd66fab728e580016629e8377579493b386bf6cebb15" },
    {"peer2cloud_SH", "03396ac453b3f23e20f30d4793c5b8ab6ded6993242df4f09fd91eb9a4f8aede84" },
    {"polycryptoblog_NA", "02708dcda7c45fb54b78469673c2587bfdd126e381654819c4c23df0e00b679622" },
    {"hyper_AR", "020f2f984d522051bd5247b61b080b4374a7ab389d959408313e8062acad3266b4" }, // 50
    {"hyper_EU", "03d00cf9ceace209c59fb013e112a786ad583d7de5ca45b1e0df3b4023bb14bf51" },
    {"hyper_SH", "0383d0b37f59f4ee5e3e98a47e461c861d49d0d90c80e9e16f7e63686a2dc071f3" },
    {"hyper_NA", "03d91c43230336c0d4b769c9c940145a8c53168bf62e34d1bccd7f6cfc7e5592de" },
    {"popcornbag_AR", "02761f106fb34fbfc5ddcc0c0aa831ed98e462a908550b280a1f7bd32c060c6fa3" },
    {"popcornbag_NA", "03c6085c7fdfff70988fda9b197371f1caf8397f1729a844790e421ee07b3a93e8" },
    {"alien_AR", "0348d9b1fc6acf81290405580f525ee49b4749ed4637b51a28b18caa26543b20f0" },
    {"alien_EU", "020aab8308d4df375a846a9e3b1c7e99597b90497efa021d50bcf1bbba23246527" },
    {"thegaltmines_NA", "031bea28bec98b6380958a493a703ddc3353d7b05eb452109a773eefd15a32e421" },
    {"titomane_AR", "029d19215440d8cb9cc6c6b7a4744ae7fb9fb18d986e371b06aeb34b64845f9325" },
    {"titomane_EU", "0360b4805d885ff596f94312eed3e4e17cb56aa8077c6dd78d905f8de89da9499f" }, // 60
    {"titomane_SH", "03573713c5b20c1e682a2e8c0f8437625b3530f278e705af9b6614de29277a435b" },
    {"webworker01_NA", "03bb7d005e052779b1586f071834c5facbb83470094cff5112f0072b64989f97d7" },
    {"xrobesx_NA", "03f0cc6d142d14a40937f12dbd99dbd9021328f45759e26f1877f2a838876709e1" },
};

#define KOMODO_NOTARIES_TIMESTAMP2 1576434600 // Sunday, December 15, 2019 6:30:00 PM GMT
#define KOMODO_NOTARIES_HEIGHT2 ((800200 / KOMODO_ELECTION_GAP) * KOMODO_ELECTION_GAP)

const char *Notaries_elected2[][2] =
{
    {"madmax_NA", "0237e0d3268cebfa235958808db1efc20cc43b31100813b1f3e15cc5aa647ad2c3" }, // 0
    {"alright_AR", "020566fe2fb3874258b2d3cf1809a5d650e0edc7ba746fa5eec72750c5188c9cc9" },
    {"strob_NA", "0206f7a2e972d9dfef1c424c731503a0a27de1ba7a15a91a362dc7ec0d0fb47685" },
    {"hunter_EU", "0378224b4e9d8a0083ce36f2963ec0a4e231ec06b0c780de108e37f41181a89f6a" },       // updated from Komodo
    {"phm87_SH", "021773a38db1bc3ede7f28142f901a161c7b7737875edbb40082a201c55dcf0add" },
    {"chainmakers_NA", "02285d813c30c0bf7eefdab1ff0a8ad08a07a0d26d8b95b3943ce814ac8e24d885" },
    {"indenodes_EU", "0221387ff95c44cb52b86552e3ec118a3c311ca65b75bf807c6c07eaeb1be8303c" },
    {"blackjok3r_SH", "021eac26dbad256cbb6f74d41b10763183ee07fb609dbd03480dd50634170547cc" },
    {"chainmakers_EU", "03fdf5a3fce8db7dee89724e706059c32e5aa3f233a6b6cc256fea337f05e3dbf7" },
    {"titomane_AR", "023e3aa9834c46971ff3e7cb86a200ec9c8074a9566a3ea85d400d5739662ee989" },
    {"fullmoon_SH", "023b7252968ea8a955cd63b9e57dee45a74f2d7ba23b4e0595572138ad1fb42d21" }, // 10
    {"indenodes_NA", "02698c6f1c9e43b66e82dbb163e8df0e5a2f62f3a7a882ca387d82f86e0b3fa988" },
    {"chmex_EU", "0281304ebbcc39e4f09fda85f4232dd8dacd668e20e5fc11fba6b985186c90086e" },
    {"metaphilibert_SH", "0284af1a5ef01503e6316a2ca4abf8423a794e9fc17ac6846f042b6f4adedc3309" },
    {"ca333_DEV", "02856843af2d9457b5b1c907068bef6077ea0904cc8bd4df1ced013f64bf267958" },
    {"cipi_NA", "02858904a2a1a0b44df4c937b65ee1f5b66186ab87a751858cf270dee1d5031f18" },
    {"pungocloud_SH", "024dfc76fa1f19b892be9d06e985d0c411e60dbbeb36bd100af9892a39555018f6" },
    {"voskcoin_EU", "034190b1c062a04124ad15b0fa56dfdf34aa06c164c7163b6aec0d654e5f118afb" },
    {"decker_DEV", "028eea44a09674dda00d88ffd199a09c9b75ba9782382cc8f1e97c0fd565fe5707" },
    {"cryptoeconomy_EU", "0290ab4937e85246e048552df3e9a66cba2c1602db76e03763e16c671e750145d1" },
    {"etszombi_EU", "0293ea48d8841af7a419a24d9da11c34b39127ef041f847651bae6ab14dcd1f6b4" },  // 20
    {"karasugoi_NA", "02a348b03b9c1a8eac1b56f85c402b041c9bce918833f2ea16d13452309052a982" },
    {"pirate_AR", "03e29c90354815a750db8ea9cb3c1b9550911bb205f83d0355a061ac47c4cf2fde" },
    {"metaphilibert_AR", "02adad675fae12b25fdd0f57250b0caf7f795c43f346153a31fe3e72e7db1d6ac6" },
    {"zatjum_SH", "02d6b0c89cacd58a0af038139a9a90c9e02cd1e33803a1f15fceabea1f7e9c263a" },
    {"madmax_AR", "03c5941fe49d673c094bc8e9bb1a95766b4670c88be76d576e915daf2c30a454d3" },
    {"lukechilds_NA", "03f1051e62c2d280212481c62fe52aab0a5b23c95de5b8e9ad5f80d8af4277a64b" },
    {"cipi_AR", "02c4f89a5b382750836cb787880d30e23502265054e1c327a5bfce67116d757ce8" },
    {"tonyl_AR", "02cc8bc862f2b65ad4f99d5f68d3011c138bf517acdc8d4261166b0be8f64189e1" },
    {"infotech_DEV", "0345ad4ab5254782479f6322c369cec77a7535d2f2162d103d666917d5e4f30c4c" },
    {"fullmoon_NA", "032c716701fe3a6a3f90a97b9d874a9d6eedb066419209eed7060b0cc6b710c60b" },  // 30
    {"etszombi_AR", "02e55e104aa94f70cde68165d7df3e162d4410c76afd4643b161dea044aa6d06ce" },
    {"node-9_EU", "0372e5b51e86e2392bb15039bac0c8f975b852b45028a5e43b324c294e9f12e411" },
    {"phba2061_EU", "03f6bd15dba7e986f0c976ea19d8a9093cb7c989d499f1708a0386c5c5659e6c4e" },
    {"indenodes_AR", "02ec0fa5a40f47fd4a38ea5c89e375ad0b6ddf4807c99733c9c3dc15fb978ee147" },
    {"and1-89_EU", "02736cbf8d7b50835afd50a319f162dd4beffe65f2b1dc6b90e64b32c8e7849ddd" },
    {"komodopioneers_SH", "032a238a5747777da7e819cfa3c859f3677a2daf14e4dce50916fc65d00ad9c52a" },
    {"komodopioneers_EU", "036d02425916444fff8cc7203fcbfc155c956dda5ceb647505836bef59885b6866" },
    {"d0ct0r_NA", "0303725d8525b6f969122faf04152653eb4bf34e10de92182263321769c334bf58" },
    {"kolo_DEV", "02849e12199dcc27ba09c3902686d2ad0adcbfcee9d67520e9abbdda045ba83227" },
    {"peer2cloud_AR", "02acc001fe1fe8fd68685ba26c0bc245924cb592e10cec71e9917df98b0e9d7c37" }, // 40
    {"webworker01_SH", "031e50ba6de3c16f99d414bb89866e578d963a54bde7916c810608966fb5700776" },
    {"webworker01_NA", "032735e9cad1bb00eaababfa6d27864fa4c1db0300c85e01e52176be2ca6a243ce" },
    {"pbca26_NA", "03a97606153d52338bcffd1bf19bb69ef8ce5a7cbdc2dbc3ff4f89d91ea6bbb4dc" },
    {"indenodes_SH", "0334e6e1ec8285c4b85bd6dae67e17d67d1f20e7328efad17ce6fd24ae97cdd65e" },
    {"pirate_NA", "0255e32d8a56671dee8aa7f717debb00efa7f0086ee802de0692f2d67ee3ee06ee" },
    {"lukechilds_AR", "025c6a73ff6d750b9ddf6755b390948cffdd00f344a639472d398dd5c6b4735d23" },
    {"dragonhound_NA", "0224a9d951d3a06d8e941cc7362b788bb1237bb0d56cc313e797eb027f37c2d375" },
    {"fullmoon_AR", "03da64dd7cd0db4c123c2f79d548a96095a5a103e5b9d956e9832865818ffa7872" },
    {"chainzilla_SH", "0360804b8817fd25ded6e9c0b50e3b0782ac666545b5416644198e18bc3903d9f9" },
    {"titomane_EU", "03772ac0aad6b0e9feec5e591bff5de6775d6132e888633e73d3ba896bdd8e0afb" }, // 50
    {"jeezy_EU", "037f182facbad35684a6e960699f5da4ba89e99f0d0d62a87e8400dd086c8e5dd7" },
    {"titomane_SH", "03850fdddf2413b51790daf51dd30823addb37313c8854b508ea6228205047ef9b" },
    {"alien_AR", "03911a60395801082194b6834244fa78a3c30ff3e888667498e157b4aa80b0a65f" },
    {"pirate_EU", "03fff24efd5648870a23badf46e26510e96d9e79ce281b27cfe963993039dd1351" },
    {"thegaltmines_NA", "02db1a16c7043f45d6033ccfbd0a51c2d789b32db428902f98b9e155cf0d7910ed" },
    {"computergenie_NA", "03a78ae070a5e9e935112cf7ea8293f18950f1011694ea0260799e8762c8a6f0a4" },
    {"nutellalicka_SH", "02f7d90d0510c598ce45915e6372a9cd0ba72664cb65ce231f25d526fc3c5479fc" },
    {"chainstrike_SH", "03b806be3bf7a1f2f6290ec5c1ea7d3ea57774dcfcf2129a82b2569e585100e1cb" },
    {"hunter_SH", "02407db70ad30ce4dfaee8b4ae35fae88390cad2b0ba0373fdd6231967537ccfdf" },
    {"alien_EU", "03bb749e337b9074465fa28e757b5aa92cb1f0fea1a39589bca91a602834d443cd" }, // 60
    {"gt_AR", "0348430538a4944d3162bb4749d8c5ed51299c2434f3ee69c11a1f7815b3f46135" },
    {"patchkez_SH", "03f45e9beb5c4cd46525db8195eb05c1db84ae7ef3603566b3d775770eba3b96ee" },
    {"decker_AR", "03ffdf1a116300a78729608d9930742cd349f11a9d64fcc336b8f18592dd9c91bc" }, // 63
};

#define KOMODO_NOTARIES_TIMESTAMP4 1592146800 // Sunday, June 14th, 2020 03:00:00 PM UTC
#define KOMODO_NOTARIES_HEIGHT4 ((1053300 / KOMODO_ELECTION_GAP) * KOMODO_ELECTION_GAP)

const char *Notaries_elected4[][2] =
{
    {"alien_AR", "024f20c096b085308e21893383f44b4faf1cdedea9ad53cc7d7e7fbfa0c30c1e71" },
    {"alien_EU", "022b85908191788f409506ebcf96a892f3274f352864c3ed566c5a16de63953236" },
    {"strob_NA", "02285bf2f9e96068ecac14bc6f770e394927b4da9f5ba833eaa9468b5d47f203a3" },
    {"titomane_SH", "02abf206bafc8048dbdc042b8eb6b1e356ea5dbe149eae3532b4811d4905e5cf01" },
    {"fullmoon_AR", "03639bc56d3fecf856f17759a441c5893668e7c2d460f3d216798a413cd6766bb2" },
    {"phba2061_EU", "03369187ce134bd7793ee34af7756fe1ab27202e09306491cdd5d8ad2c71697937" },
    {"fullmoon_NA", "03e388bcc579ac2675f8fadfa921eec186dcea8d2b43de1eed6caba23d5a962b74" },
    {"fullmoon_SH", "03a5cfda2b097c808834ccdd805828c811b519611feabdfe6b3644312e53f6748f" },
    {"madmax_AR", "027afddbcf690230dd8d435ec16a7bfb0083e6b77030f763437f291dfc40a579d0" },
    {"titomane_EU", "02276090e483db1a01a802456b10831b3b6e0a6ad3ece9b2a01f4aad0e480c8edc" },
    {"cipi_NA", "03f4e69edcb4fa3b2095cb8cb1ca010f4ec4972eac5d8822397e5c8d87aa21a739" },
    {"indenodes_SH", "031d1584cf0eb4a2d314465e49e2677226b1615c3718013b8d6b4854c15676a58c" },
    {"decker_AR", "02a85540db8d41c7e60bf0d33d1364b4151cad883dd032878ea4c037f67b769635" },
    {"indenodes_EU", "03a416533cace0814455a1bb1cd7861ce825a543c6f6284a432c4c8d8875b7ace9" },
    {"madmax_NA", "036d3afebe1eab09f4c38c3ee6a4659ad390f3df92787c11437a58c59a29e408e6" },
    {"chainzilla_SH", "0311dde03c2dd654ce78323b718ed3ad73a464d1bde97820f3395f54788b5420dd" },
    {"peer2cloud_AR", "0243958faf9ae4d43b598b859ddc595c170c4cf50f8e4517d660ae5bc72aeb821b" },
    {"pirate_EU", "0240011b95cde819f298fe0f507b2260c9fecdab784924076d4d1e54c522103cb1" },
    {"webworker01_NA", "02de90c720c007229374772505a43917a84ed129d5fbcfa4949cc2e9b563351124" },
    {"zatjum_SH", "0241c5660ca540780be66603b1791127a1261d56abbcb7562c297eec8e4fc078fb" },
    {"titomane_AR", "03958bd8d13fe6946b8d0d0fbbc3861c72542560d0276e80a4c6b5fe55bc758b81" },
    {"chmex_EU", "030bf7bd7ad0515c33b5d5d9a91e0729baf801b9002f80495ae535ea1cebb352cb" },
    {"indenodes_NA", "02b3908eda4078f0e9b6704451cdc24d418e899c0f515fab338d7494da6f0a647b" },
    {"patchkez_SH", "028c08db6e7242681f50db6c234fe3d6e12fb1a915350311be26373bac0d457d49" },
    {"metaphilibert_AR", "0239e34ad22957bbf4c8df824401f237b2afe8d40f7a645ecd43e8f27dde1ab0da" },
    {"etszombi_EU", "03a5c083c78ba397970f20b544a01c13e7ed36ca8a5ae26d5fe7bd38b92b6a0c94" },
    {"pirate_NA", "02ad7ef25d2dd461e361120cd3efe7cbce5e9512c361e9185aac33dd303d758613" },
    {"metaphilibert_SH", "03b21ff042bf1730b28bde43f44c064578b41996117ac7634b567c3773089e3be3" },
    {"indenodes_AR", "0242778789986d614f75bcf629081651b851a12ab1cc10c73995b27b90febb75a2" },
    {"chainmakers_NA", "028803e07bcc521fde264b7191a944f9b3612e8ee4e24a99bcd903f6976240839a" },
    {"mihailo_EU", "036494e7c9467c8c7ff3bf29e841907fb0fa24241866569944ea422479ec0e6252" },
    {"tonyl_AR", "0229e499e3f2e065ced402ceb8aaf3d5ab8bd3793aa074305e9fa30772ce604908" },
    {"alien_NA", "022f62b56ddfd07c9860921c701285ac39bb3ac8f6f083d1b59c8f4943be3de162" },
    {"pungocloud_SH", "02641c36ae6747b88150a463a1fe65cf7a9d1c00a64387c73f296f0b64e77c7d3f" },
    {"node9_EU", "0392e4c9400e69f28c6b9e89d586da69d5a6af7702f1045eaa6ebc1996f0496e1f" },
    {"smdmitry_AR", "0397b7584cb29717b721c0c587d4462477efc1f36a56921f133c9d17b0cd7f278a" },
    {"nodeone_NA", "0310a249c6c2dcc29f2135715138a9ddb8e01c0eab701cbd0b96d9cec660dbdc58" },
    {"gcharang_SH", "02a654037d12cdd609f4fad48e15ec54538e03f61fdae1acb855f16ebacac6bd73" },
    {"cipi_EU", "026f4f66385daaf8313ef30ffe4988e7db497132682dca185a70763d93e1417d9d" },
    {"etszombi_AR", "03bfcbca83f11e622fa4eed9a1fa25dba377981ea3b22e3d0a4015f9a932af9272" },
    {"pbca26_NA", "03c18431bb6bc95672f640f19998a196becd2851d5dcba4795fe8d85b7d77eab81" },
    {"mylo_SH", "026d5f29d09ff3f33e14db4811606249b2438c6bcf964876714f81d1f2d952acde" },
    {"swisscertifiers_EU", "02e7722ebba9f8b5ebfb4e87d4fa58cc75aef677535b9cfc060c7d9471aacd9c9e" },
    {"marmarachain_AR", "028690ca1e3afdf8a38b421f6a41f5ff407afc96d5a7a6a488330aae26c8b086bb" },
    {"karasugoi_NA", "02f803e6f159824a181cc5d709f3d1e7ff65f19e1899920724aeb4e3d2d869f911" },
    {"phm87_SH", "03889a10f9df2caef57220628515693cf25316fe1b0693b0241419e75d0d0e66ed" },
    {"oszy_EU", "03c53bd421de4a29ce68c8cc83f802e1181e77c08f8f16684490d61452ea8d023a" },
    {"chmex_AR", "030cd487e10fbf142e0e8d582e702ecb775f378569c3cb5acd0ff97b6b12803588" },
    {"dragonhound_NA", "029912212d370ee0fb4d38eefd8bfcd8ab04e2c3b0354020789c29ddf2a35c72d6" },
    {"strob_SH", "0213751a1c59d3489ca85b3d62a3d606dcef7f0428aa021c1978ea16fb38a2fad6" },
    {"madmax_EU", "0397ec3a4ad84b3009566d260c89f1c4404e86e5d044964747c9371277e38f5995" },
    {"dudezmobi_AR", "033c121d3f8d450174674a73f3b7f140b2717a7d51ea19ee597e2e8e8f9d5ed87f" },
    {"daemonfox_NA", "023c7584b1006d4a62a4b4c9c1ede390a3789316547897d5ed49ff9385a3acb411" },
    {"nutellalicka_SH", "0284c4d3cb97dd8a32d10fb32b1855ae18cf845dad542e3b8937ca0e998fb54ecc" },
    {"starfleet_EU", "03c6e047218f34644ccba67e317b9da5d28e68bbbb6b9973aef1281d2bafa46496" },
    {"mrlynch_AR", "03e67440141f53a08684c329ebc852b018e41f905da88e52aa4a6dc5aa4b12447a" },
    {"greer_NA", "0262da6aaa0b295b8e2f120035924758a4a630f899316dc63ee15ef03e9b7b2b23" },
    {"mcrypt_SH", "027a4ca7b11d3456ff558c08bb04483a89c7f383448461fd0b6b3b07424aabe9a4" },
    {"decker_EU", "027777775b89ff548c3be54fb0c9455437d87f38bfce83bdef113899881b219c9e" },
    {"dappvader_SH", "025199bc04bcb8a17976d9fe8bc87763a6150c2727321aa59bf34a2b49f2f3a0ce" },
    {"alright_DEV", "03b6f9493658bdd102503585a08ae642b49d6a68fb69ac3626f9737cd7581abdfa" },
    {"artemii235_DEV", "037a20916d2e9ea575300ac9d729507c23a606b9a200c8e913d7c9832f912a1fa7" },
    {"tonyl_DEV", "0258b77d7dcfc6c2628b0b6b438951a6e74201fb2cd180a795e4c37fcf8e78a678" },
    {"decker_DEV", "02fca8ee50e49f480de275745618db7b0b3680b0bdcce7dcae7d2e0fd5c3345744" }
};

#define KOMODO_NOTARIES_TIMESTAMP5 1623682800 // Monday, June 14th, 2021 (03:00:00 PM UTC)
#define KOMODO_NOTARIES_HEIGHT5 ((1562500 / KOMODO_ELECTION_GAP) * KOMODO_ELECTION_GAP)

const char *Notaries_elected5[][2] =
{
	{"alrighttt_DEV", "02a876c6c35060041f6beadb201f4dfc567e80eedd3a4206ff10d99878087bd440"}, // 0
	{"alien_AR", "024f20c096b085308e21893383f44b4faf1cdedea9ad53cc7d7e7fbfa0c30c1e71"},
	{"artempikulin_AR", "03a45c4ad7f279cbc50acb48d81fc0eb63c4c5f556e3a4393fb3d6414df09c6e4c"},
	{"chmex_AR", "030cd487e10fbf142e0e8d582e702ecb775f378569c3cb5acd0ff97b6b12803588"},
	{"cipi_AR", "02336758998f474659020e6887ece61ac7b8567f9b2d38724ebf77ae800c1fb2b7"},
	{"shadowbit_AR", "03949b06c2773b4573aeb0b52e70ccc2d98dc5794a47e24eeb902c9d28e0e8d28b"},
	{"goldenman_AR", "03d745bc6921104b73734e6d9615671bc70b9e11e26c9b0c9abf0d2f9babd01a4d"},
	{"kolo_AR", "027579d0722b2f75b3d11a73829449e4251b4471716b6cb743c7667379750c8fb0"},
	{"madmax_AR", "02ddb23f18e61ea792ae0f28be5a52859e7963bf7f1d2c4f19eec18ac6497cfa2a"},
	{"mcrypt_AR", "02845d016c68c3e5ce924b164abc271511f3092ae359677a515e8f81a9533472f4"},
	{"mrlynch_AR", "03e67440141f53a08684c329ebc852b018e41f905da88e52aa4a6dc5aa4b12447a"}, // 10
	{"ocean_AR", "02d216e72d37a38449d661413cbc6e1f008b21cffdb06865f7be636e2cbc1e5346"},
	{"smdmitry_AR", "0397b7584cb29717b721c0c587d4462477efc1f36a56921f133c9d17b0cd7f278a"},
	{"tokel_AR", "02e4e07060fcd3640a3fd6d54cc15924f2bf63f8172b96a9f1d538ca7a0e490dc5"},
	{"tonyl_AR", "02e2d9ecdc9f462a4767f7dfe8ed243c98fcccc1511989a60e3f859dc6fda42d16"},
	{"tonyl_DEV", "0399c4f8c5b604cda64c1ccb8fdbd7a89730131519f87491a79b0811e619102d8f"},
	{"artem_DEV", "025ee88d1c12f546c1c8942d7a3e0678f10bc27cc566e27bf4a2d2178e018d18c6"},
	{"alien_EU", "022b85908191788f409506ebcf96a892f3274f352864c3ed566c5a16de63953236"},
	{"alienx_EU", "025de0911bab55616c307f02ea8a5915a2e0c8e479aa97968e7f00d1025cbe6c6d"},
	{"ca333_EU", "03a582cfae3760bb1cb38311d686cfeede8f8c4ce263aa1c082fc836c367859122"},
	{"chmex_EU", "030bf7bd7ad0515c33b5d5d9a91e0729baf801b9002f80495ae535ea1cebb352cb"}, // 20
	{"cipi_EU", "033a812d6cccdc4208378728f3a0e15db5b12074def9ab686ddc3752715ff1a194"},
	{"cipi2_EU", "0302ca28a041ed00544de737651bdec9bafe3b7f1c0bf2c6092f2368d59fec75c2"},
	{"shadowbit_EU", "025f8de3a6181270ceb5c31654e6a6e95d0339bc14b46b5e3050e8a69861c91baa"},
	{"komodopioneers_EU", "02fb31b130babe79ac780a6118702555a8c66875835f35c2232a6cb8b1438fe71d"},
	{"madmax_EU", "02e7e5306f159df252ecfded9bab6297050d12640b908b456ea553f90872f8a160"},
	{"marmarachain_EU", "027029380f49b0c3cc1b814976f1a83f0c25d84020ad0a27454e55ebdb2ccc83d7"},
	{"node-9_EU", "029401e427cffa29bb2bd7664110e160d525fac6f1518ac7b59343b16de301e0ac"},
	{"slyris_EU", "02a0705ec221a94a6a5b3ea2e763ba0350f8213c73e8dad49a708fb1e87acdc5f8"},
	{"smdmitry_EU", "0338f30ca34d0aca0d79b69abde447036aaaa75f482b6c75801fd382e984337d01"},
	{"van_EU", "0370305b9e91d46331da202ae733d6050d01038ef6eceb2036ada394a48fae84b9"}, // 30
	{"shadowbit_DEV", "03e2de3418c88be0cfe2fa0dcfdaea001b5a36ad86e6833ad284d79021ae7e2b94"},
	{"gcharang_DEV", "0321868e0eb39271330fa2c3a9f4e542275d9719f8b87773c5432448ab10d6943d"},
	{"alien_NA", "022f62b56ddfd07c9860921c701285ac39bb3ac8f6f083d1b59c8f4943be3de162"},
	{"alienx_NA", "025d5e11725233ab161f4f63d697c5f9f0c6b9d3aa2b9c68299638f8cc63faa9c2"},
	{"cipi_NA", "0335352862da521bd90b99d394db1ee3ecde379db9cf7ba2f28b16fa76153e289f"},
	{"computergenie_NA", "02f945d87b7cd6e9f2173a110399d36b369edb1f10bdf5a4ba6fd4923e2986e137"},
	{"dragonhound_NA", "0366a87a476a09e05560c5aae0e44d2ab9ba56e69701cee24307871ddd37c86258"},
	{"hyper_NA", "0303503ea8f5ec8bcab474962dfadd3561b44732b6ad308acd8d04276dd2f1baf3"},
	{"madmax_NA", "0378e47061572e4a406bbad1522c03c3331d0a6c820fde1248ccf2cbc72fec47c2"},
	{"node-9_NA", "03fac1468a949244dd4c563062459d46e966479fe23748382fc2e3e8d05218023e"}, // 40
	{"nodeone_NA", "0310a249c6c2dcc29f2135715138a9ddb8e01c0eab701cbd0b96d9cec660dbdc58"},
	{"pbca26_NA", "03e8485883eba6d4f2902338ab6aac87654a4b98d3bc01f89638aaf9c37db66ccf"},
	{"ptyx_NA", "028267c92db3c48a99dfb8d88e9cdab60d8a1525913ab3978b1b629667b12b1ee2"},
	{"strob_NA", "02285bf2f9e96068ecac14bc6f770e394927b4da9f5ba833eaa9468b5d47f203a3"},
	{"karasugoi_NA", "02f803e6f159824a181cc5d709f3d1e7ff65f19e1899920724aeb4e3d2d869f911"},
	{"webworker01_NA", "03d6c76aabe24fde7ce7cc37cff0899d50a20d4147ac0b2db812e2a1edcf0d5232"},
	{"yurii_DEV", "0243977da0533c7c1a37f0f6e30175225c9012d9f3f426180ff6e5710f5a50e32b"},
	{"ca333_DEV", "035f3413d71856ac0859f564ced42fe1ce5c5058df888f4592b8a11d34a5ba3a45"},
	{"chmex_SH", "03e09c8ee6ae20cde64857d116c4bb5d50db6de2887ac39ea3ccf6434b1abf8698"},
	{"collider_SH", "033a1b62de10c3802f359da7767b033eac3837b58530722f3ddd2f359a2cd0a8f9"}, // 50
	{"dappvader_SH", "02684e2e7425ffa36d331f7a2f9c4542b61e88370dc6b4313a5025643f82ee17fa"},
	{"drkush_SH", "0210320b03f00f10f16313eb6e8929b5be7e66a034a4e9b7d11f2d87aa92708c6c"},
	{"majora31_SH", "03bc75c112ac7c6a99d6eb3fe5582feef4fd1b43f11c08ad887e21c4c3bc4e9104"},
	{"mcrypt_SH", "027a4ca7b11d3456ff558c08bb04483a89c7f383448461fd0b6b3b07424aabe9a4"},
	{"metaphilibert_SH", "03b21ff042bf1730b28bde43f44c064578b41996117ac7634b567c3773089e3be3"},
	{"mylo_SH", "026a52dba25ca4deb225a5ef7fca117d59e20ef2319b00e1bb6750a5d61e5ed601"},
	{"nutellaLicka_SH", "03ca46ea9a32de632823419948188088069f5820023920d810da6076624adb9901"},
	{"pbca26_SH", "021b39173b2b966ab277799a1f148a1d9e6cf26020f5f7eb9708f020ee0461e9c0"},
	{"phit_SH", "021b893b7978284e3d73701a623f23104fcce27e70fb49427c215f9a7481f652da"},
	{"sheeba_SH", "030dd2c3c02cbc5b3c25e3c54ed02c1541951a6f5ecf8adbd353e8d9052d08b8fc"}, // 60
	{"strob_SH", "0213751a1c59d3489ca85b3d62a3d606dcef7f0428aa021c1978ea16fb38a2fad6"},
	{"strobnidan_SH", "033e33ef18effb979437cd202bb87dc32385e16ebd52d6f762d8a3b308d6f89c52"},
	{"dragonhound_DEV", "02b3c168ed4acd96594288cee3114c77de51b6afe1ab6a866887a13a96ee80f33c"}
};

#define KOMODO_NOTARIES_TIMESTAMP6 1656077853 // Friday, June 24, 2022 (13:37:33 UTC)
#define KOMODO_NOTARIES_HEIGHT6 ((2084866 / KOMODO_ELECTION_GAP) * KOMODO_ELECTION_GAP)

const char *Notaries_elected6[][2] =
(
	{"blackice_DEV": "03e2de3418c88be0cfe2fa0dcfdaea001b5a36ad86e6833ad284d79021ae7e2b94"}, // 0
	{"blackice_AR": "03949b06c2773b4573aeb0b52e70ccc2d98dc5794a47e24eeb902c9d28e0e8d28b"},
	{"alien_EU": "022b85908191788f409506ebcf96a892f3274f352864c3ed566c5a16de63953236"},
	{"alien_NA": "022f62b56ddfd07c9860921c701285ac39bb3ac8f6f083d1b59c8f4943be3de162"},
	{"alien_SH": "024f20c096b085308e21893383f44b4faf1cdedea9ad53cc7d7e7fbfa0c30c1e71"},
	{"alienx_EU": "025de0911bab55616c307f02ea8a5915a2e0c8e479aa97968e7f00d1025cbe6c6d"},
	{"alienx_NA": "025d5e11725233ab161f4f63d697c5f9f0c6b9d3aa2b9c68299638f8cc63faa9c2"},
	{"artem.pikulin_AR": "03a45c4ad7f279cbc50acb48d81fc0eb63c4c5f556e3a4393fb3d6414df09c6e4c"},
	{"artem.pikulin_DEV": "025ee88d1c12f546c1c8942d7a3e0678f10bc27cc566e27bf4a2d2178e018d18c6"},
	{"blackice_EU": "025f8de3a6181270ceb5c31654e6a6e95d0339bc14b46b5e3050e8a69861c91baa"},
	{"chmex_AR": "030cd487e10fbf142e0e8d582e702ecb775f378569c3cb5acd0ff97b6b12803588"}, // 10
	{"chmex_EU": "030bf7bd7ad0515c33b5d5d9a91e0729baf801b9002f80495ae535ea1cebb352cb"},
	{"chmex_NA": "024e88a36d729352a391e07d1821dbfda1fca6409320cf9c2869b6fb99f05fbddd"},
	{"chmex_SH": "03e09c8ee6ae20cde64857d116c4bb5d50db6de2887ac39ea3ccf6434b1abf8698"},
	{"chmex1_SH": "02d59db293de6c7da6673beeb373ebce62fd6d3522f715ea1356b5a2624fbd11a2"},
	{"cipi_1_EU": "033a812d6cccdc4208378728f3a0e15db5b12074def9ab686ddc3752715ff1a194"},
	{"cipi_2_EU": "0302ca28a041ed00544de737651bdec9bafe3b7f1c0bf2c6092f2368d59fec75c2"},
	{"cipi_AR": "02336758998f474659020e6887ece61ac7b8567f9b2d38724ebf77ae800c1fb2b7"},
	{"cipi_NA": "0335352862da521bd90b99d394db1ee3ecde379db9cf7ba2f28b16fa76153e289f"},
	{"computergenie_EU": "033a2474a762700b452b96a49730280040a9872070bc51461e3727f6f118ff5358"},
	{"computergenie_NA": "02f945d87b7cd6e9f2173a110399d36b369edb1f10bdf5a4ba6fd4923e2986e137"}, // 20
	{"dimxy_AR": "0337e443df52f278f313f90628aaaa7a8db777f17bc7ce519069eb72717c1c2755"},
	{"dimxy_DEV": "03a7edd6d0ba188960e39eced4d6b4ca6946bd98323ab40cbc13d6e52696de7dc4"},
	{"dragonhound_NA": "0366a87a476a09e05560c5aae0e44d2ab9ba56e69701cee24307871ddd37c86258"},
	{"fediakash_AR": "035be6a54242a53e3ca55bd63430ac9b960fbfaad336d8c1464b5802f03ab184be"},
	{"gcharang_DEV": "03a3878af1152f648e6084fd3fbe697a26b1c2e92d407dd96c375f45f7d3ca13bf"},
	{"gcharang_SH": "0321868e0eb39271330fa2c3a9f4e542275d9719f8b87773c5432448ab10d6943d"},
	{"goldenman_AR": "03e027927dd1e379c2f45624ed9b057b187fe094595fee55c53f36ed665ed566ab"},
	{"kolo_AR": "032c2a6aeaf8176f9630abe2e1bbea5e481da23ab1f9a5b10f220a9b2bc9607bd6"},
	{"kolo_EU": "03b21717e84c0a6cf22b557b198daba4f78980048211b9139b4517fa08f9f17359"},
	{"kolox_AR": "038010e24e6d53f26871d31287f446f407fa87596d946bcd1f7b7b8458e34ad73f"}, // 30
	{"komodopioneers_EU": "02fb31b130babe79ac780a6118702555a8c66875835f35c2232a6cb8b1438fe71d"},
	{"madmax_DEV": "02d1ace4a25794de5a5287edeb9df9619dc97020114801c5cb287b1efdd49ddbb3"},
	{"marmarachain_EU": "02ca3e0618bc7c75afa6359ae476ee639682adfaa6fc463bbe7016c4f00da23ccf"},
	{"mcrypt_AR": "02845d016c68c3e5ce924b164abc271511f3092ae359677a515e8f81a9533472f4"},
	{"mcrypt_SH": "027a4ca7b11d3456ff558c08bb04483a89c7f383448461fd0b6b3b07424aabe9a4"},
	{"metaphilibert_SH": "03b21ff042bf1730b28bde43f44c064578b41996117ac7634b567c3773089e3be3"},
	{"mylo_NA": "02493412e6014d2bb985b1026e31204e7634a211a16454fc696f4dc4dfe409e998"},
	{"mylo_SH": "026a52dba25ca4deb225a5ef7fca117d59e20ef2319b00e1bb6750a5d61e5ed601"},
	{"nodeone_NA": "0310a249c6c2dcc29f2135715138a9ddb8e01c0eab701cbd0b96d9cec660dbdc58"},
	{"nutellalicka_AR": "03a5502c61839a34edc8443aee5c16c67d4a958874e13d9b6b69d29075354739ad"}, // 40
	{"nutellalicka_SH": "03c7822f0c3434037fa17bfa4d3b7f9d3e0eb9abe49e8cc1188d92c6b3c360a675"},
	{"ocean_AR": "02d216e72d37a38449d661413cbc6e1f008b21cffdb06865f7be636e2cbc1e5346"},
	{"pbca26_NA": "030b6515e80aaa489215875e2aa6f2a15fa36cb3342580e885275f8c636252cbc8"},
	{"pbca26_SH": "02d17840724692a9d5e72d61d001c31eb5ddc4d2f0f104b760e6854bf144e63fb8"},
	{"phit_SH": "021b893b7978284e3d73701a623f23104fcce27e70fb49427c215f9a7481f652da"},
	{"ptyx_NA": "025d72ef0f1c5103de306d536360bcf3c5b6129c2046334b21cec8202e9bfc4baf"},
	{"ptyx2_NA": "02913b3af6f67453eaff2318f3eed0fa0ea60eb2b37c8da64c575fec972f178d9b"},
	{"sheeba_SH": "030dd2c3c02cbc5b3c25e3c54ed02c1541951a6f5ecf8adbd353e8d9052d08b8fc"},
	{"smdmitry_AR": "0397b7584cb29717b721c0c587d4462477efc1f36a56921f133c9d17b0cd7f278a"},
	{"smdmitry_EU": "0338f30ca34d0aca0d79b69abde447036aaaa75f482b6c75801fd382e984337d01"}, // 50
	{"smdmitry_SH": "03f7d5ac650baaccedab959adf7c4f416584f4c05a37bf079f710227560c456978"},
	{"strob_SH": "0213751a1c59d3489ca85b3d62a3d606dcef7f0428aa021c1978ea16fb38a2fad6"},
	{"strobnidan_SH": "033e33ef18effb979437cd202bb87dc32385e16ebd52d6f762d8a3b308d6f89c52"},
	{"tokel_NA": "0315d866c09e15709e2036a05faec6aaf28e0ecf67329b2adb922b746f22e694bc"},
	{"tonyl_AR": "02e2d9ecdc9f462a4767f7dfe8ed243c98fcccc1511989a60e3f859dc6fda42d16"},
	{"tonyl_DEV": "0399c4f8c5b604cda64c1ccb8fdbd7a89730131519f87491a79b0811e619102d8f"},
	{"van_EU": "0370305b9e91d46331da202ae733d6050d01038ef6eceb2036ada394a48fae84b9"},
	{"webworker01_EU": "0390ba250f20b5849b9d37ad2bcb58d3d9a3a0385937e652c26511ba9f445f5db1"},
	{"webworker01_NA": "03bde0df98de0ff9697b7d5ecea225fd7267f55c061caa2c43a47b313e35c9b6c6"},
	{"who-biz_NA": "0268d30efafc6ac84b1c8210e99fd4936e178794581d348b87f64fcbbfa8d5e73b"}, // 60
	{"yurii-khi_DEV": "0243977da0533c7c1a37f0f6e30175225c9012d9f3f426180ff6e5710f5a50e32b"},
	{"ca333_EU": "03c34a62c8c89889e4529962578e0b75a010a6e1d9bcbe8f4bb9cc680d82c7261e"},
	{"dragonhound_DEV": "02b3c168ed4acd96594288cee3114c77de51b6afe1ab6a866887a13a96ee80f33c"}
};

int32_t komodo_notaries(uint8_t pubkeys[64][33],int32_t height,uint32_t timestamp)
{
    static uint8_t elected_pubkeys0[64][33],
                   elected_pubkeys1[64][33],
                   elected_pubkeys2[64][33],
                   elected_pubkeys4[64][33],
                   elected_pubkeys5[64][33],
                   elected_pubkeys6[64][33],
                   did0,
                   did1,
                   did2,
                   did4,
                   did5;
                   did6;
    static int32_t n0, n1, n2, n4, n5, n6;
    int32_t i, htind, n;
    uint64_t mask = 0;
    struct knotary_entry *kp, *tmp;
    if ( timestamp == 0 && ASSETCHAINS_SYMBOL[0] != 0 )
        timestamp = komodo_heightstamp(height);
    else if ( ASSETCHAINS_SYMBOL[0] == 0 )
        timestamp = 0;
    if ( height >= KOMODO_NOTARIES_HARDCODED || ASSETCHAINS_SYMBOL[0] != 0 )
    {
        if ( (timestamp != 0 && timestamp <= KOMODO_NOTARIES_TIMESTAMP1) || (ASSETCHAINS_SYMBOL[0] == 0 && height <= KOMODO_NOTARIES_HEIGHT1) )
        {
            if ( did0 == 0 )
            {
                n0 = (int32_t)(sizeof(Notaries_elected0)/sizeof(*Notaries_elected0));
                for (i=0; i<n0; i++)
                    decode_hex(elected_pubkeys0[i],33,(char *)Notaries_elected0[i][1]);
                did0 = 1;
            }
            memcpy(pubkeys, elected_pubkeys0, n0 * 33);
            //if ( ASSETCHAINS_SYMBOL[0] != 0 )
            //fprintf(stderr,"%s height.%d t.%u elected.%d notaries\n",ASSETCHAINS_SYMBOL,height,timestamp,n0);
            return(n0);
        }
        else if ( (timestamp != 0 && timestamp <= KOMODO_NOTARIES_TIMESTAMP2) || height <= KOMODO_NOTARIES_HEIGHT2 )
        {
            if ( did1 == 0 )
            {
                n1 = (int32_t)(sizeof(Notaries_elected1)/sizeof(*Notaries_elected1));
                for (i=0; i<n1; i++)
                    decode_hex(elected_pubkeys1[i],33,(char *)Notaries_elected1[i][1]);
                if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
                    fprintf(stderr,"%s height.%d t.%u elected.%d notaries2\n",ASSETCHAINS_SYMBOL,height,timestamp,n1);
                did1 = 1;
            }
            memcpy(pubkeys, elected_pubkeys1, n1 * 33);
            return(n1);
        }
        else if ( (timestamp != 0 && timestamp <= KOMODO_NOTARIES_TIMESTAMP4) || height <= KOMODO_NOTARIES_HEIGHT4 )
        {
            if ( did2 == 0 )
            {
                n2 = (int32_t)(sizeof(Notaries_elected2)/sizeof(*Notaries_elected2));
                for (i=0; i<n2; i++)
                    decode_hex(elected_pubkeys2[i],33,(char *)Notaries_elected2[i][1]);
                if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
                    fprintf(stderr,"%s height.%d t.%u elected.%d notaries2\n",ASSETCHAINS_SYMBOL,height,timestamp,n2);
                did2 = 1;
            }
            memcpy(pubkeys, elected_pubkeys2, n2 * 33);
            return(n2);
        }
        else if ( (timestamp != 0 && timestamp <= KOMODO_NOTARIES_TIMESTAMP5) || height <= KOMODO_NOTARIES_HEIGHT5 )
        {
            if ( did4 == 0 )
            {
                n4 = (int32_t)(sizeof(Notaries_elected4)/sizeof(*Notaries_elected4));
                for (i=0; i<n4; i++)
                    decode_hex(elected_pubkeys4[i],33,(char *)Notaries_elected4[i][1]);
                if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
                    fprintf(stderr,"%s height.%d t.%u elected.%d notaries4\n",ASSETCHAINS_SYMBOL,height,timestamp,n4);
                did4 = 1;
            }
            memcpy(pubkeys, elected_pubkeys4, n4 * 33);
            return(n4);
        }
        else if ( (timestamp != 0 && timestamp <= KOMODO_NOTARIES_TIMESTAMP6) || height <= KOMODO_NOTARIES_HEIGHT6 )
        {
            if ( did5 == 0 )
            {
                n5 = (int32_t)(sizeof(Notaries_elected5)/sizeof(*Notaries_elected5));
                for (i=0; i<n5; i++)
                    decode_hex(elected_pubkeys5[i],33,(char *)Notaries_elected5[i][1]);
                if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
                    fprintf(stderr,"%s height.%d t.%u elected.%d notaries5\n",ASSETCHAINS_SYMBOL,height,timestamp,n5);
                did5 = 1;
            }
            memcpy(pubkeys, elected_pubkeys5, n5 * 33);
            return(n5);
        }
        else
        {
            if ( did6 == 0 )
            {
                n6 = (int32_t)(sizeof(Notaries_elected6)/sizeof(*Notaries_elected6));
                for (i=0; i<n6; i++)
                    decode_hex(elected_pubkeys6[i],33,(char *)Notaries_elected6[i][1]);
                if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
                    fprintf(stderr,"%s height.%d t.%u elected.%d notaries6\n",ASSETCHAINS_SYMBOL,height,timestamp,n6);
                did6 = 1;
            }
            memcpy(pubkeys, elected_pubkeys6, n6 * 33);
            return(n6);
        }
    }
    htind = height / KOMODO_ELECTION_GAP;
    if ( htind >= KOMODO_MAXBLOCKS / KOMODO_ELECTION_GAP )
        htind = (KOMODO_MAXBLOCKS / KOMODO_ELECTION_GAP) - 1;
    if ( Pubkeys == 0 )
    {
        komodo_init(height);
        //printf("Pubkeys.%p htind.%d vs max.%d\n",Pubkeys,htind,KOMODO_MAXBLOCKS / KOMODO_ELECTION_GAP);
    }
    pthread_mutex_lock(&komodo_mutex);
    n = Pubkeys[htind].numnotaries;
    if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
        fprintf(stderr,"%s height.%d t.%u genesis.%d\n",ASSETCHAINS_SYMBOL,height,timestamp,n);
    HASH_ITER(hh,Pubkeys[htind].Notaries,kp,tmp)
    {
        if ( kp->notaryid < n )
        {
            mask |= (1LL << kp->notaryid);
            memcpy(pubkeys[kp->notaryid],kp->pubkey,33);
        } else printf("illegal notaryid.%d vs n.%d\n",kp->notaryid,n);
    }
    pthread_mutex_unlock(&komodo_mutex);
    if ( (n < 64 && mask == ((1LL << n)-1)) || (n == 64 && mask == 0xffffffffffffffffLL) )
        return(n);
    printf("error retrieving notaries ht.%d got mask.%llx for n.%d\n",height,(long long)mask,n);
    return(-1);
}

int32_t komodo_electednotary(int32_t *numnotariesp,uint8_t *pubkey33,int32_t height,uint32_t timestamp)
{
    int32_t i,n; uint8_t pubkeys[64][33];
    n = komodo_notaries(pubkeys,height,timestamp);
    *numnotariesp = n;
    for (i=0; i<n; i++)
    {
        if ( memcmp(pubkey33,pubkeys[i],33) == 0 )
            return(i);
    }
    return(-1);
}

int32_t komodo_ratify_threshold(int32_t height,uint64_t signedmask)
{
    int32_t htind,numnotaries,i,wt = 0;
    htind = height / KOMODO_ELECTION_GAP;
    if ( htind >= KOMODO_MAXBLOCKS / KOMODO_ELECTION_GAP )
        htind = (KOMODO_MAXBLOCKS / KOMODO_ELECTION_GAP) - 1;
    numnotaries = Pubkeys[htind].numnotaries;
    for (i=0; i<numnotaries; i++)
        if ( ((1LL << i) & signedmask) != 0 )
            wt++;
    if ( wt > (numnotaries >> 1) || (wt > 7 && (signedmask & 1) != 0) )
        return(1);
    else return(0);
}

void komodo_notarysinit(int32_t origheight,uint8_t pubkeys[64][33],int32_t num)
{
    static int32_t hwmheight;
    int32_t k,i,htind,height; struct knotary_entry *kp; struct knotaries_entry N;
    if ( Pubkeys == 0 )
        Pubkeys = (struct knotaries_entry *)calloc(1 + (KOMODO_MAXBLOCKS / KOMODO_ELECTION_GAP),sizeof(*Pubkeys));
    memset(&N,0,sizeof(N));
    if ( origheight > 0 )
    {
        height = (origheight + KOMODO_ELECTION_GAP/2);
        height /= KOMODO_ELECTION_GAP;
        height = ((height + 1) * KOMODO_ELECTION_GAP);
        htind = (height / KOMODO_ELECTION_GAP);
        if ( htind >= KOMODO_MAXBLOCKS / KOMODO_ELECTION_GAP )
            htind = (KOMODO_MAXBLOCKS / KOMODO_ELECTION_GAP) - 1;
        //printf("htind.%d activation %d from %d vs %d | hwmheight.%d %s\n",htind,height,origheight,(((origheight+KOMODO_ELECTION_GAP/2)/KOMODO_ELECTION_GAP)+1)*KOMODO_ELECTION_GAP,hwmheight,ASSETCHAINS_SYMBOL);
    } else htind = 0;
    pthread_mutex_lock(&komodo_mutex);
    for (k=0; k<num; k++)
    {
        kp = (struct knotary_entry *)calloc(1,sizeof(*kp));
        memcpy(kp->pubkey,pubkeys[k],33);
        kp->notaryid = k;
        HASH_ADD_KEYPTR(hh,N.Notaries,kp->pubkey,33,kp);
        if ( 0 && height > 10000 )
        {
            for (i=0; i<33; i++)
                printf("%02x",pubkeys[k][i]);
            printf(" notarypubs.[%d] ht.%d active at %d\n",k,origheight,htind*KOMODO_ELECTION_GAP);
        }
    }
    N.numnotaries = num;
    for (i=htind; i<KOMODO_MAXBLOCKS / KOMODO_ELECTION_GAP; i++)
    {
        if ( Pubkeys[i].height != 0 && origheight < hwmheight )
        {
            printf("Pubkeys[%d].height %d < %d hwmheight, origheight.%d\n",i,Pubkeys[i].height,hwmheight,origheight);
            break;
        }
        Pubkeys[i] = N;
        Pubkeys[i].height = i * KOMODO_ELECTION_GAP;
    }
    pthread_mutex_unlock(&komodo_mutex);
    if ( origheight > hwmheight )
        hwmheight = origheight;
}

int32_t komodo_chosennotary(int32_t *notaryidp,int32_t height,uint8_t *pubkey33,uint32_t timestamp)
{
    // -1 if not notary, 0 if notary, 1 if special notary
    struct knotary_entry *kp; int32_t numnotaries=0,htind,modval = -1;
    *notaryidp = -1;
    if ( height < 0 )//|| height >= KOMODO_MAXBLOCKS )
    {
        printf("komodo_chosennotary ht.%d illegal\n",height);
        return(-1);
    }
    if ( height >= KOMODO_NOTARIES_HARDCODED || ASSETCHAINS_SYMBOL[0] != 0 )
    {
        if ( (*notaryidp= komodo_electednotary(&numnotaries,pubkey33,height,timestamp)) >= 0 && numnotaries != 0 )
        {
            modval = ((height % numnotaries) == *notaryidp);
            return(modval);
        }
    }
    if ( height >= 250000 )
        return(-1);
    if ( Pubkeys == 0 )
        komodo_init(0);
    htind = height / KOMODO_ELECTION_GAP;
    if ( htind >= KOMODO_MAXBLOCKS / KOMODO_ELECTION_GAP )
        htind = (KOMODO_MAXBLOCKS / KOMODO_ELECTION_GAP) - 1;
    pthread_mutex_lock(&komodo_mutex);
    HASH_FIND(hh,Pubkeys[htind].Notaries,pubkey33,33,kp);
    pthread_mutex_unlock(&komodo_mutex);
    if ( kp != 0 )
    {
        if ( (numnotaries= Pubkeys[htind].numnotaries) > 0 )
        {
            *notaryidp = kp->notaryid;
            modval = ((height % numnotaries) == kp->notaryid);
            //printf("found notary.%d ht.%d modval.%d\n",kp->notaryid,height,modval);
        } else printf("unexpected zero notaries at height.%d\n",height);
    } //else printf("cant find kp at htind.%d ht.%d\n",htind,height);
    //int32_t i; for (i=0; i<33; i++)
    //    printf("%02x",pubkey33[i]);
    //printf(" ht.%d notary.%d special.%d htind.%d num.%d\n",height,*notaryidp,modval,htind,numnotaries);
    return(modval);
}

//struct komodo_state *komodo_stateptr(char *symbol,char *dest);

struct notarized_checkpoint *komodo_npptr_for_height(int32_t height, int *idx)
{
    char symbol[KOMODO_ASSETCHAIN_MAXLEN],dest[KOMODO_ASSETCHAIN_MAXLEN]; int32_t i; struct komodo_state *sp; struct notarized_checkpoint *np = 0;
    if ( (sp= komodo_stateptr(symbol,dest)) != 0 )
    {
        for (i=sp->NUM_NPOINTS-1; i>=0; i--)
        {
            *idx = i;
            np = &sp->NPOINTS[i];
            if ( np->MoMdepth != 0 && height > np->notarized_height-(np->MoMdepth&0xffff) && height <= np->notarized_height )
                return(np);
        }
    }
    *idx = -1;
    return(0);
}

struct notarized_checkpoint *komodo_npptr(int32_t height)
{
    int idx;
    return komodo_npptr_for_height(height, &idx);
}

struct notarized_checkpoint *komodo_npptr_at(int idx)
{
    char symbol[KOMODO_ASSETCHAIN_MAXLEN],dest[KOMODO_ASSETCHAIN_MAXLEN]; struct komodo_state *sp;
    if ( (sp= komodo_stateptr(symbol,dest)) != 0 )
        if (idx < sp->NUM_NPOINTS)
            return &sp->NPOINTS[idx];
    return(0);
}

int32_t komodo_prevMoMheight()
{
    static uint256 zero;
    char symbol[KOMODO_ASSETCHAIN_MAXLEN],dest[KOMODO_ASSETCHAIN_MAXLEN]; int32_t i; struct komodo_state *sp; struct notarized_checkpoint *np = 0;
    if ( (sp= komodo_stateptr(symbol,dest)) != 0 )
    {
        for (i=sp->NUM_NPOINTS-1; i>=0; i--)
        {
            np = &sp->NPOINTS[i];
            if ( np->MoM != zero )
                return(np->notarized_height);
        }
    }
    return(0);
}

int32_t komodo_notarized_height(int32_t *prevMoMheightp,uint256 *hashp,uint256 *txidp)
{
    char symbol[KOMODO_ASSETCHAIN_MAXLEN],dest[KOMODO_ASSETCHAIN_MAXLEN]; struct komodo_state *sp;
    if ( (sp= komodo_stateptr(symbol,dest)) != 0 )
    {
        *hashp = sp->NOTARIZED_HASH;
        *txidp = sp->NOTARIZED_DESTTXID;
        *prevMoMheightp = komodo_prevMoMheight();
        return(sp->NOTARIZED_HEIGHT);
    }
    else
    {
        *prevMoMheightp = 0;
        memset(hashp,0,sizeof(*hashp));
        memset(txidp,0,sizeof(*txidp));
        return(0);
    }
}

int32_t komodo_MoMdata(int32_t *notarized_htp,uint256 *MoMp,uint256 *kmdtxidp,int32_t height,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *kmdstartip,int32_t *kmdendip)
{
    struct notarized_checkpoint *np = 0;
    if ( (np= komodo_npptr(height)) != 0 )
    {
        *notarized_htp = np->notarized_height;
        *MoMp = np->MoM;
        *kmdtxidp = np->notarized_desttxid;
        *MoMoMp = np->MoMoM;
        *MoMoMoffsetp = np->MoMoMoffset;
        *MoMoMdepthp = np->MoMoMdepth;
        *kmdstartip = np->kmdstarti;
        *kmdendip = np->kmdendi;
        return(np->MoMdepth & 0xffff);
    }
    *notarized_htp = *MoMoMoffsetp = *MoMoMdepthp = *kmdstartip = *kmdendip = 0;
    memset(MoMp,0,sizeof(*MoMp));
    memset(MoMoMp,0,sizeof(*MoMoMp));
    memset(kmdtxidp,0,sizeof(*kmdtxidp));
    return(0);
}

int32_t komodo_notarizeddata(int32_t nHeight,uint256 *notarized_hashp,uint256 *notarized_desttxidp)
{
    struct notarized_checkpoint *np = 0; int32_t i=0,flag = 0; char symbol[KOMODO_ASSETCHAIN_MAXLEN],dest[KOMODO_ASSETCHAIN_MAXLEN]; struct komodo_state *sp;
    if ( (sp= komodo_stateptr(symbol,dest)) != 0 )
    {
        if ( sp->NUM_NPOINTS > 0 )
        {
            flag = 0;
            if ( sp->last_NPOINTSi < sp->NUM_NPOINTS && sp->last_NPOINTSi > 0 )
            {
                np = &sp->NPOINTS[sp->last_NPOINTSi-1];
                if ( np->nHeight < nHeight )
                {
                    for (i=sp->last_NPOINTSi; i<sp->NUM_NPOINTS; i++)
                    {
                        if ( sp->NPOINTS[i].nHeight >= nHeight )
                        {
                            //printf("flag.1 i.%d np->ht %d [%d].ht %d >= nHeight.%d, last.%d num.%d\n",i,np->nHeight,i,sp->NPOINTS[i].nHeight,nHeight,sp->last_NPOINTSi,sp->NUM_NPOINTS);
                            flag = 1;
                            break;
                        }
                        np = &sp->NPOINTS[i];
                        sp->last_NPOINTSi = i;
                    }
                }
            }
            if ( flag == 0 )
            {
                np = 0;
                for (i=0; i<sp->NUM_NPOINTS; i++)
                {
                    if ( sp->NPOINTS[i].nHeight >= nHeight )
                    {
                        //printf("i.%d np->ht %d [%d].ht %d >= nHeight.%d\n",i,np->nHeight,i,sp->NPOINTS[i].nHeight,nHeight);
                        break;
                    }
                    np = &sp->NPOINTS[i];
                    sp->last_NPOINTSi = i;
                }
            }
        }
        if ( np != 0 )
        {
            //char str[65],str2[65]; printf("[%s] notarized_ht.%d\n",ASSETCHAINS_SYMBOL,np->notarized_height);
            if ( np->nHeight >= nHeight || (i < sp->NUM_NPOINTS && np[1].nHeight < nHeight) )
                printf("warning: flag.%d i.%d np->ht %d [1].ht %d >= nHeight.%d\n",flag,i,np->nHeight,np[1].nHeight,nHeight);
            *notarized_hashp = np->notarized_hash;
            *notarized_desttxidp = np->notarized_desttxid;
            return(np->notarized_height);
        }
    }
    memset(notarized_hashp,0,sizeof(*notarized_hashp));
    memset(notarized_desttxidp,0,sizeof(*notarized_desttxidp));
    return(0);
}

void komodo_notarized_update(struct komodo_state *sp,int32_t nHeight,int32_t notarized_height,uint256 notarized_hash,uint256 notarized_desttxid,uint256 MoM,int32_t MoMdepth)
{
    struct notarized_checkpoint *np;
    if ( notarized_height >= nHeight )
    {
        fprintf(stderr,"komodo_notarized_update REJECT notarized_height %d > %d nHeight\n",notarized_height,nHeight);
        return;
    }
    if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
        fprintf(stderr,"[%s] komodo_notarized_update nHeight.%d notarized_height.%d\n",ASSETCHAINS_SYMBOL,nHeight,notarized_height);
    portable_mutex_lock(&komodo_mutex);
    sp->NPOINTS = (struct notarized_checkpoint *)realloc(sp->NPOINTS,(sp->NUM_NPOINTS+1) * sizeof(*sp->NPOINTS));
    np = &sp->NPOINTS[sp->NUM_NPOINTS++];
    memset(np,0,sizeof(*np));
    np->nHeight = nHeight;
    sp->NOTARIZED_HEIGHT = np->notarized_height = notarized_height;
    sp->NOTARIZED_HASH = np->notarized_hash = notarized_hash;
    sp->NOTARIZED_DESTTXID = np->notarized_desttxid = notarized_desttxid;
    sp->MoM = np->MoM = MoM;
    sp->MoMdepth = np->MoMdepth = MoMdepth;
    portable_mutex_unlock(&komodo_mutex);
}

void komodo_init(int32_t height)
{
    static int didinit; uint256 zero; int32_t k,n; uint8_t pubkeys[64][33];
    if ( 0 && height != 0 )
        printf("komodo_init ht.%d didinit.%d\n",height,didinit);
    memset(&zero,0,sizeof(zero));
    if ( didinit == 0 )
    {
        pthread_mutex_init(&komodo_mutex,NULL);
        decode_hex(NOTARY_PUBKEY33,33,(char *)NOTARY_PUBKEY.c_str());
        if ( height >= 0 )
        {
            n = (int32_t)(sizeof(Notaries_genesis)/sizeof(*Notaries_genesis));
            for (k=0; k<n; k++)
            {
                if ( Notaries_genesis[k][0] == 0 || Notaries_genesis[k][1] == 0 || Notaries_genesis[k][0][0] == 0 || Notaries_genesis[k][1][0] == 0 )
                    break;
                decode_hex(pubkeys[k],33,(char *)Notaries_genesis[k][1]);
            }
            komodo_notarysinit(0,pubkeys,k);
        }
        //for (i=0; i<sizeof(Minerids); i++)
        //    Minerids[i] = -2;
        didinit = 1;
        komodo_stateupdate(0,0,0,0,zero,0,0,0,0,0,0,0,0,0,0,zero,0);
    }
}
