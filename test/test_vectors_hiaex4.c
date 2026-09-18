// HiAEx4 test vectors. The specification doesn't cover the parallel variants, so these come from a separate reference model that also reproduces the HiAE and HiAEx2 test vectors.

#include "HiAEx4.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_LEN 4096

typedef struct {
    const char *name;
    const char *key;
    const char *nonce;
    const char *ad;
    const char *plaintext;
    const char *ciphertext;
    const char *tag;
} TestVector;

typedef struct {
    const char *name;
    const char *key;
    const char *nonce;
    const char *data;
    const char *tag;
} MacTestVector;

// Plaintext of the multi-chunk AEAD vector, and data of the multi-chunk MAC vector
#define HIAEX4_LARGE_MSG                                               \
    "51c8cea7420b1faa72ab337cdfdac830dc9b8bf4e1bdfad2e8658be98ea44392" \
    "7d8473a16415c56cfe7d18594b104ae5e1dc7477fbdaee9ab447ab82e5568bc0" \
    "1ba7f34bfb7b869c54e3495c039d7b67c96b682c6d8fceff7f28fdfb0e2c6837" \
    "f0d6920e45f2d6b0b4569b01e76721e307671037c4a6990add6743ec670aa196" \
    "2f829463a776afd06052b081d171d32fedd85de8710b4e12743b28908654724f" \
    "3dd7e75025bb97bae8129df3c4e64bdbc32595da4265e3f80939bfdab744e82a" \
    "4fb5423e35ff79e3a4561e7c743466ed7a583f3729d0eaff93491d574a7148d4" \
    "84078c9599193fe37dc85e0de5396a418de509de4c7a823cbd4013d1918b75e7" \
    "3f9a8e8cbab1856356d53b01259c2ee97fe38e5d63209bd7f2092e6f19b97883" \
    "560039cdf3942bf356b54e9c0ab1ce102b4dac346b96eca427fac3ac934736cd" \
    "1b52e626adb362ae260ff1541b37e6955a366ecf3924252db5a1a0a8a7eae874" \
    "9b3f9253b25f42ef3f549675e92f1018c5e50a4189346724596f16815dbeece3" \
    "1bdf695ca6623e0acffb7a66a168f988a24dcbfa772be3a4b2bd6014e97bd5fc" \
    "210fad6a0a5d5ca604a2a80c62c46b3ad51fe60ed197cf930263b38be404ed47" \
    "9de9bb42f27a584b4ba007670a36b42097a768ba48194b7b10b9187146a00d82" \
    "36c3905ad24f8b359f429c48620a8c26a2cbafa93a1c044ce9592834f7988dc6" \
    "63eedd9c3364ecd799ada7f8a0bfbb54ca17bd968b6c6482c8af73e2888a662f" \
    "8612d7d6ab73e3d1fb97568a142f2a780b2863766a70ba3c8518c0a93c5409a7" \
    "57babfcff12e05b6d75af629a36533cabaae4a40b797a9d500c93e652dc7220d" \
    "f8f0872b1e84a0a10fc5431d00a58466d4809f6b182529ea105645ffbd8b3b6e" \
    "112fe693c767c16d53992aef87654f2c4f033422737bb4cc76639f88c011dded" \
    "f60682757e4c989de04717997cd1f0f1c5ee8499067cd4a6d981e8f1107eb993" \
    "b90fbce910f1627f59c7c9d0726f1f3ed932627855f7a2ab41bed8c0dcafefbd" \
    "c245dae7f54198325822d846d19d92cea39bc3adb6af7c62c3adb92c77ce790b" \
    "c703440fcff056fbc09ced1b72e4a7a701146df4b4098ee818f966e5a4f3d257" \
    "ace7bf6a02d36013376266ebb9a42774f669fbb12bdb63a8b842ce50b5ecab25" \
    "e3c824e463d5642b7e5e5bde037e506da13c01ee8291b9f1f5152b50d352e783" \
    "3c78c44202804a7a6ffe85bfbe82852e7577c80114dd5bc3498f1de365876175" \
    "a537ba58cf82ca689f20c71a756299d8759f2df62f9687f8c1c3218e86a7a7ca" \
    "67cddf2aff9a10b665fcc12e73fb56d449f7708f016602ddba92b66430beb9a2" \
    "7664b45a68324f97234eb6a85da381f5dc70d834d2b4fe3f08a549cfe7d4ae25" \
    "675990f436b0ea5b7110f639596c3e8abeaa26e91ba66a6ac7e6bef6bda41874" \
    "ccd3c838984941d99dea89809b39a81c5d69316a70ec560c2b70d655f8f05ed6" \
    "8345da54da43fce1b659c1dcc588af1fb13ec305f4fcfa8e5f9cc3ed86274b12" \
    "ebf23de1c5ecc62ebd6734fb62ac0eee18210141944b9b700c8fce6a2f432797" \
    "3f1d06c7d8d1a3ee672895e95f7c00e2a0cbb4fe2d18dd2410b92d76a8c92e33" \
    "a648fd8ff136d5c14ea5334a8dd58ad8316f65be2c45cca15981020b9daf4f3f" \
    "1d4d374889e1b02b12278168709fa60ac7bdaed89bf6822e18a0735a8fb335de" \
    "e6bb6484d11d56e98b332424dc95db454935ee8dfd86fe10e0107272d3e3dacb" \
    "c77f2cde1307ab9f6bdd2c720b720d8d3186cf8ea4884ab5e4cf5203ade9eba9" \
    "811775b637f95504547e46e534a1c4d86aee797f4f16aaf56541143ed85caaf6" \
    "5d4877d3d0fc6c1961628779796468b8050a20890cee15c48f3a3e4787ac62d5" \
    "cb2cd79e1d2b38a41a254c9a95517ce7b552c49a487634d9b4c96d0b5c4d005b" \
    "3ba2c70e3fb7a864af3de1b76a4614dbbb33b36592aef010cee7efee3da97264" \
    "e4543eab929734a064c31f345ab617a8a194a01780c439224b0f12048564e118" \
    "7deaaa276b4291f4e94081dc7053f4f9612abd7be7851e9389956762e4921a1c" \
    "808f29cd469d5d23cf43d148d9be698386c7f2fdaa3b0380cf8879db853df597" \
    "f9e6066f82f487ef691a074626d3df2a11bb44c6f929884f73a17c95eeefdf3e" \
    "4b458070f69b4854875f2d00b2e0f70c7a03526ac7501ca0b414c5eb7a5eeb40" \
    "6b0de97775a2314eb86d767dd330cd3dd563e9db304fb27695bb6a5752e2fe55" \
    "470f1ae105adb8415acfcdf9007b98afe0fd11bc46a471ff51794343c649d6dc" \
    "d367b293601f49097d2c3774cad128fe254aa7174320c27d4296f8537d6c61fc" \
    "95ea280c01ea1f01a952ce5c100ac3895ec70a7f3a5ff7cc1a0d55f550a9468d" \
    "349e166556eff136ba93c750078d337810d8babf310af2291f80a1b0c91c2531" \
    "35facbd0eab80ff79b4db0c7f21efabfacebf164ed16aea640d4f6e698012d65" \
    "2c6a4a0bbe8a478e8bd8bbf29df7bd0a4988bddbd3420d56869066d55fbe39f2" \
    "f19c7e3acfa098dc66c4a1d78c9752ffe7c09654a892e74331059e7a4cf490ef" \
    "eb34ab7dfb85b0c0d69ae1eb027c1d1d575a4ceda09696d76faa6f32fb01b918" \
    "cf49cf17282dac6940eee4e95b7f02d2830897ef74002b7d83fff6f37204e3d7" \
    "76b8148aaa2ad14d7213a1e69a1111e1fb396dcd96a8e19822bcf88754319b6d" \
    "f00c0f78c98df404f987905f4f01af9cd4d6fb426981ea6ae9886e22c37f4d98" \
    "bc04eda20dae4a64788a09d6015b79b008c3df380b4f838cb2540ba51779ce3e" \
    "385f2b00086935e6ed2b2e971cdadf707e819ae3756a98bd9cf449bd5a8236fa" \
    "6077ce684996a77f5d51502dc35d7ff442b4ee80b83467a48486ded1e3e7a378" \
    "252be6dd814cae3107c6f110f3dff58b30cb8f4121bf4ea092a803d41acea141" \
    "ff85a4c322b2b6673f6f605d452b509253d95c4b"

static const TestVector test_vectors[] = {
    { .name       = "Empty plaintext, no AD",
      .key        = "4b7a9c3ef8d2165a0b3e5f8c9d4a7b1e2c5f8a9d3b6e4c7f0a1d2e5b8c9f4a7d",
      .nonce      = "a5b8c2d9e3f4a7b1c8d5e9f2a3b6c7d8",
      .ad         = "",
      .plaintext  = "",
      .ciphertext = "",
      .tag        = "fea28c7f4633a83174705b980432e456" },
    { .name       = "Partial block plaintext, no AD",
      .key        = "2f8e4d7c3b9a5e1f8d2c6b4a9f3e7d5c1b8a6f4e3d2c9b5a8f7e6d4c3b2a1f9e",
      .nonce      = "7c3e9f5a1d8b4c6f2e9a5d7b3f8c1e4a",
      .ad         = "",
      .plaintext  = "55f00fcc339669aa55f00fcc339669aa",
      .ciphertext = "20926b54cb95a38ebb7572672ded2ec1",
      .tag        = "bc12c1edf6f5eddebb3962c8818a5b37" },
    { .name       = "Empty plaintext with AD",
      .key        = "9f3e7d5c4b8a2f1e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e",
      .nonce      = "3d8c7f2a5b9e4c1f8a6d3b7e5c2f9a4d",
      .ad         = "394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2f30415263748",
      .plaintext  = "",
      .ciphertext = "",
      .tag        = "0589de2321d5051a01d9c0cb57bd6e07" },
    { .name       = "64-byte aligned plaintext",
      .key        = "6c8f2d5a9e3b7f4c1d8a5e9f3c7b2d6a4f8e1c9b5d3a7e2f4c8b6d9a1e5f3c7d",
      .nonce      = "9a5c7e3f1b8d4a6c2e9f5b7d3a8c1e6f",
      .ad         = "",
      .plaintext  = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      .ciphertext = "7e1b0efffd27ccbf6b4fdec61dab8227f0bb033819df8ba657bd4462cda9134d"
                    "9800dbfbdb8153945a5a465de34964170f3251327425d912ff1699f17b82920b",
      .tag        = "2ab15f27c1ae33df473d19101ad74ba2" },
    { .name       = "Single byte plaintext",
      .key        = "7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a",
      .nonce      = "2e7c9f5d3b8a4c6f1e9b5d7a3f8c2e4a",
      .ad         = "",
      .plaintext  = "ff",
      .ciphertext = "ea",
      .tag        = "536f86e61f2865e2fb67b7737b5c7fe8" },
    { .name       = "Unaligned AD and plaintext",
      .key        = "d810cee46b9251d96a2c86fa67dcca07483f8da2233cc8d51b33733d00840f70",
      .nonce      = "da88904c725d17d12fa81d7905971580",
      .ad         = "fd2e9ee751e796c63e4cefeb01c7d4e411c22824801a9670ca5213b67222e221"
                    "9ad7653c48fd9e922cc93b4e5c6aac33c51c23c825c4d0fc4b9697aaf92279a4"
                    "c835f02d52719d46da482f6e9c36cf480ab0a74d0857c0750f2719a906648f2b"
                    "1694e236",
      .plaintext  = "d20370a1080b3acee7de56245f881f32e71f8d59e135c4940ae3af21c353f199"
                    "e598e5922ad5f2f162a5af5df8c94c0839a52d9bd2c890173f713f88a4e68472"
                    "afdccdd37910471fe944fc7f470c2f360443931f107b9fbd12eef8dd0ab04fd9"
                    "4c0b6499ff8772ee122c00e242bc995df664a35b498a44eeb6c73ce5b73d625d"
                    "d780",
      .ciphertext = "996a07463343cb43dd13403e5e77e3d31a784ffb30a73cfef902d2e3f01cd43e"
                    "38cf7f98202bb2826459b8564e47083fe44dc758ff27f565bf3d25b51196499b"
                    "ca7e1a82060d7d960a42f25660ffde83dc286b91023ed854cde359cd18fcfbff"
                    "48439a404d68710e53f8629c7cf361a9ecb729f30681223b2130affa784fe969"
                    "1fd3",
      .tag        = "3b1451e2df72d96957952c585971301f" },
    { .name       = "Multi-chunk AD and plaintext",
      .key        = "95810241cd874a83f88143d42222c6e0e84e2e163943c95fbfc6d98c64f39f1e",
      .nonce      = "a6b5d5887ce3b50a1436548487b32894",
      .ad         = "03d3bf74cc337c30324991380a67f8e76d62bb55c6c43c98e5dc595ad3a85ab0"
                    "3b2d9da3db33f05f98a3dbc983adc82210df3c4b3a3126301c8652b167b8e089"
                    "b7cce0034b7bdd5fc4c38844af19ba7b18144df8bd77c75c83dbec773c0c37b5"
                    "c3ea41dd1a0cb5a0d72b08863fccc08c1cf1d2f4af841ec0cce05b9405f84a1d"
                    "827f4045361751682f4c708da2d5bd4b48955d66c36b81688f8ee59edf4b65ce"
                    "3ec7cf2887e46d890974e9bc9bb58754f5d8a200ccb380ab0fc789ca0309a3f7"
                    "3f6415837081d9d040faa7ad1d15db866b3216e50bb622dd22e281d8d391a37a"
                    "e661dddd0f018fa43b33b7a4f1fcb52f495f17e12ee4d2a0670d743818c82b17"
                    "77f5827352580fb13aba19ec42ba2706c4ab6c6a261f443ddb3a0ad8ea8ade67"
                    "ff691773cdec2222d6c98594f3ec5c1242251042e9e20641796b8428d7ebc7d1"
                    "ada9d4c4f253106f0a80275bed69ce3a06fea0515c27a622e5a61b0fc2388801"
                    "e5de00bf59c76239f202a244b2518aec7f1a156aac0cf195fe95b01228d505bf"
                    "16dfa3ff54a45c99c920590019f6eaa030a78e86d1c691715bb3bc8481a3f7ff"
                    "5a17ccc48ca325bd31cba2a8d82ff5e0ec4820c8dbaf7ccd34e0cd49cdf80bfa"
                    "3401265837006e8c38ec7a3120d00706dbb459075ea38b6418f209b22cec4dcb"
                    "3866c479a5f7b2ae576de30967a7210de2e5991a69de7f3071576260a5bf727d"
                    "cbf8cc3b7c79481d907e2734b3ed8762a319b3cb69ac0bb7deb35106359bbdd6"
                    "e19a2014c804dd7b896b62e5beaaf5080b43a3b8f55964cd88129f56d13d1b7a"
                    "92a698aeeaa79b7bc23d19ff451b34721dcbc2d9889a76248547feb44491e238"
                    "af35c6db24c4932798f1fa379bfd8190dfddb36938f69a3e58ba201d9c75218f"
                    "24bffd73857e2a6cd895742001e9b56b38bc8e19d7676ac4e7d32a8d7cdaaa90"
                    "7c996383eded17843953aa77eb1438ebf3b0dc548daf7921788dccb75ea939d3"
                    "2c60d449e20ea30e96335f20b35f110e5a1dd9b6fe54390efbae71feb03fe5f3"
                    "7f56365506a282061610e4370e88bd2aacbe836d0101f622920681d8e102bf16"
                    "b854dacdbf50acf245be3c15a4c4ef599a00940bd08c28f8308f30c1072478eb"
                    "85a98ec017fda19d58fb31d34017f94f46866cb270ba3f1e05ffc577f01b99d2"
                    "6072bc5bc2a343037292bb15614b9f800908a68ae99a274dc1e981cbf9313534"
                    "4d17247e52015b4f61880ef1dc69108807649effec11cce1f69e5244d3416868"
                    "149126da51772fc25cd087caa616deda3f69324ccda9dfe58545b7cb972c15d7"
                    "ec056968ef8b52a04cabcc679795f23a32454bd39c49a8c5ab09c4b9cb3a9a4e"
                    "ce021bb621beaa6cfa9d28d79e0f9e8d6241dcdca9dbae7a03a20685e234476d"
                    "6c1af825a0dca8fe9a0f45f900714c53da4e00b659d8a406d1462e918eaff72e"
                    "40a1d23bf707420a78afa8285afb117f",
      .plaintext  = HIAEX4_LARGE_MSG,
      .ciphertext = "0d97468a0b8c4c1f333b88cd937a1f64d4d37defbbbcc622d5ac26a6e706fae8"
                    "a95cdcc90b003eb5bccd1d9da7fc5adde520854e7e35a63e513df23f74313a50"
                    "f5c4903ef24ce226003f3d24df9187af8e098bf560ec092c20f7f6cb2ca33753"
                    "969f8d3d3491deaa5316b5fe1e445b7d77f2a1b8eec5c71a7c7a62c6233bdf7b"
                    "584ff988b65968b619d6f13e5373cbc6bfaacc10629d3ef9b2314110ec31cf39"
                    "8bb04f5df9bd7fc6180e25cf645571f4837c574b0890a76e8cdbed41d709b029"
                    "afb8602285cdfc02b2f3e062d281e9a75a73a3d689c516cdfbed15b2c43ca597"
                    "5593b47d26b2e04397d303ecf7782fabf4b47f34af8de48159c3440499a0e680"
                    "db0e6d09ee919a7f8c9d4e878e3465166ea7b81fe34bd34bd55a59ff40df3d1d"
                    "dcd6225ef2db471d91d341faa58cb827b14fd73209363c83e403ec74e8f0aa78"
                    "87e6d15e4a32251a0889e5abf677a8fc53f45af2b86e7bb75f90e89d856da7f2"
                    "8f9b8f7bc65aa9376f4b45969e2ed65743246ca036010cab01ca09b39f669454"
                    "1053f4717db0e9351a2b5a84936e619ce9aa66af20a7e7f5074ff59c25ffca67"
                    "263d922da164071c5bcce7ddf7b8173435c1c62b981f2c22e7a9766468734109"
                    "d6adf3a6f8ada2dbae21d34200218064020a421bad23f025fa933d8d84a456b3"
                    "b7b31e8dbfd589e82e135289e47bd0439cb0dfa53c6b02b5d35817d45bf3e088"
                    "02f06735681780f1ec69b311b585aa7e454c44f195b58a8ac9cdfb8f3a5f030a"
                    "7d442a16d36b2740ef4deefe7766ed0782ae59283427ef633fa7dc6c55ebf367"
                    "d74e0918d8f09c94914eec0b3a9d864a9400f781023adb51edde99a463c53534"
                    "18eafb099731fc6ac1a7aefc920298a26bedf120aeb002f3ef57a8ad528d3715"
                    "3ebe4b9b98b99060823db8c82cc8a2678bb411a40d8dead2a355c7315c9547a3"
                    "0bc22cb4a52b18300f9b8c55bf927b03443bcd4de217c4cb7b4f6e2d2633b8f1"
                    "17ed5283027eb5cec6d46c2645b87f290dc75dc7059a39f986d9e301595fc314"
                    "78b02650eb8d34b9d5bfaaf61a1eb4effb93aab64dc191339f8ff9491eca82b5"
                    "d1d8ac891e315de66c894aa4b1a624d9c884b07717d0fb05197d5aa52dc153ec"
                    "5ead70ad3dd00b8fc46396b654ed952b6b0bd7c976c3a79d670399b7fcb7490f"
                    "1a3ea15611c338d0ce7bad59050c46ef2af5781b264304d4f2afb22d36e58a1a"
                    "5a488802ee406ab54784fbe3d436140fbc6a3e9d13179a254ac470293bc71d67"
                    "1144dca91dc8921b702d637b01d37012e6ebbbec673f6f2cfcf3261eaee7ec2d"
                    "f6da068604067721f7eeb1b2d0314c15bfd1f56c08d04b6170c5ab45f0f3e70b"
                    "609a080da16f2fcf057974bb6321ce89d60a43fda193c231e17b36920f521ec8"
                    "84081e4b0070ebf94ecee5d38281bb91a172bf90683787ad6198c3186080f6b6"
                    "fcd66841314fa59238e4a7e883cbc9b2073e0cb99530e56fdf700372d88eddc0"
                    "7d6c0bf51286813ef4d9e56bb050c9a604ca5870a78da68f099b8d1ce8b007c1"
                    "92eb7439210526853f137df4afa851fe3e094d09e312c5ffe18b4ea13c4115d7"
                    "01cf7761c57cea336b4e484d70ca05a04b9a9bbab933fdf29a7586d148771d82"
                    "5909a86b455c0a3feb6a2bbb66fcee41d63b521bfad025af3670b5c16919ecb3"
                    "214d5ecf60071113dd86ad1e2d3d4ef1ca2408afbcc7aec1be6e03252051c2f2"
                    "039a39ae602e4bd441cbac9563b45a547fef83eece810631ce0510bfc6c048bb"
                    "4368135cb3b5230728dd892b730d468e9a723fd7f9a554eada51c2bb6a73db32"
                    "3c8d7537f95fd19ebd9a2fe8e254f56c63b30580ee3dff524787bd0c53e0f625"
                    "1843c0e4e3a3369fa94cf06b4156bc755e825c4d7a32b364d4df61704f7ce073"
                    "6de7369a1ead7dff655d7e24cfa71fc959219830568a92cd0dcc39d4ac9e9012"
                    "407bebef0a35444d34d6ca79c61c9f7519140aa6f7c595f09bf825962abce8b4"
                    "c54b6035ece09cb78cb41209dc35c359d39e05fd3970868c95699e2bfbf8d46c"
                    "476d78186ed91101bb946cdd7326dd57adfe6580cb064486d6973f3bde1d475f"
                    "60d0dbef4351b8be9e84ce719870144dad5bfa26f8b0e6b588ffc7a3863f55ae"
                    "9be4654741541601cbd14ab41e6882868ef5632824ea82935b120e532c7137e7"
                    "7f642177b86012b31b558d7b72ca3e2bdb04ac99b9efcecde00c81ffd0be6767"
                    "e4d1246112ba2a1264f7a7f9fb59a994ac447681640ebce03df8d96f6cf9a563"
                    "3bf71e7c7d9367f32b78c38a48bf3b3cc3a3c00a6e7ef3161970b50f4888fad1"
                    "36cbb44d9f48e83ca1fccb82ce6beef8482a818ad5ca08a0427b32450afbbaf6"
                    "0645efe35430c253b53c59597c159d657837542b2aefb68c72f9bad5e7c3b021"
                    "0863e250b89e67762ec7e8bf9f79b6473ed92aba22281220a495f9611fcde7d0"
                    "8774f6c759d6c445866b9b6faeb155fd1fa6a9321282f77613d520a7ccb1b5da"
                    "03d54fff51cfbdd0f725d297efccd4232a9aed5a949688c3b6a0436d08158623"
                    "09d8121ebf5ab6d6912a54ce9d8b035a58dacd035d5f4131e378ee7409cd0a49"
                    "a114bec3db1d2db8c99df701c88ae3d7f8d1acfaea35364e4374aaa3d8be8443"
                    "643510b7e544a4c5e00c82d9cf74222bc54120f903f5e3325044a9a7e0f34f4a"
                    "c12fadb50747f1c59182504077ab73f8a58ee9fad6945b31305fb4bfe2ccc56a"
                    "fe6d9d2c990eacb9a4be25e04eda786f126b888d5175bb055d2785664a1b9b45"
                    "58388628d1b3ecce9914372aeeb7ddef3aa78a490ee4ebd6cc5730563a167f40"
                    "0d039c85c95fc48451103260f582deecfe32f2457f49d15b395b2e0ed6c27fc7"
                    "74583ef2556792addb9b9572507f72c8aa97e75310e167484999ce482dcfb90d"
                    "d62a6a90063f61c9002c3e9741bc74d12443234f64426faa4aeecb1aa065e812"
                    "8a64f64b0b4c9c749b51ba16547ae7bd92d5bdb1",
      .tag        = "d941c0e1fa9dfb5f53f29aa704b3a2d6" },
};

static const MacTestVector mac_test_vectors[] = {
    { .name  = "Empty data",
      .key   = "c833d7986c24087c5086d376a6a9a2619dea2b46d94a5c5fb5ad0a7a5cff1ccc",
      .nonce = "e401e08cb9a0da550659cdc79f7f0fa3",
      .data  = "",
      .tag   = "6f62f380b41270bb00297b58c0f04bee" },
    { .name  = "Unaligned data",
      .key   = "7e441249d18a5ee2d617af4065986474c8ed21c705630d0ed61a3366245eb990",
      .nonce = "0221e4502c7d9b59e6dfd57550225121",
      .data  = "a3a9ae3518847bb4f27ac0c155db9604fd2c4e00bc40d06a12d7a81556fde1b8"
               "d7ef3e4d91cb11c74da62e922ea10ad5f8e708dc0c54dc1432b5a3d647d98d3a"
               "2f",
      .tag   = "ac228af88fa27af3cf0b74f27357bcb8" },
    { .name  = "Multi-chunk data",
      .key   = "c0e4617ee06b6c420f64792ef7f0ef68ec1c4cdcf08c32c28d003a5d1bbeab4f",
      .nonce = "534d475386940bcd42ac34867e864ae9",
      .data  = HIAEX4_LARGE_MSG,
      .tag   = "635833511ab7363ee5ac6c0099938dd2" },
};

static size_t
unhex(uint8_t *out, const char *hex)
{
    const size_t len = strlen(hex) / 2;
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (uint8_t) b;
    }
    return len;
}

static uint8_t key[HIAEX4_KEYBYTES], nonce[HIAEX4_NONCEBYTES], tag[HIAEX4_MACBYTES];
static uint8_t out_tag[HIAEX4_MACBYTES], ad[MAX_LEN], pt[MAX_LEN], ct[MAX_LEN], out[MAX_LEN];

static int
check_aead(const TestVector *tv)
{
    unhex(key, tv->key);
    unhex(nonce, tv->nonce);
    unhex(tag, tv->tag);
    unhex(ct, tv->ciphertext);
    const size_t ad_len = unhex(ad, tv->ad);
    const size_t len    = unhex(pt, tv->plaintext);

    HiAEx4_encrypt(key, nonce, pt, out, len, ad, ad_len, out_tag);
    if (memcmp(out, ct, len) != 0 || memcmp(out_tag, tag, sizeof tag) != 0) {
        return 0;
    }
    return HiAEx4_decrypt(key, nonce, out, ct, len, ad, ad_len, tag) == 0 &&
           memcmp(out, pt, len) == 0;
}

static int
check_mac(const MacTestVector *tv)
{
    unhex(key, tv->key);
    unhex(nonce, tv->nonce);
    unhex(tag, tv->tag);
    const size_t len = unhex(pt, tv->data);

    HiAEx4_mac(key, nonce, pt, len, out_tag);
    return memcmp(out_tag, tag, sizeof tag) == 0;
}

int
main(void)
{
    // The implementation picked for this CPU, then the software one if it's a different one
    static const char *const impls[] = { NULL, "Software" };
    const char              *tested  = NULL;
    int                      passed = 0, failed = 0;

    for (size_t i = 0; i < sizeof impls / sizeof impls[0]; i++) {
        if (HiAEx4_force_implementation(impls[i]) != 0) {
            continue;
        }
        const char *name = HiAEx4_get_implementation_name();
        if (tested != NULL && strcmp(tested, name) == 0) {
            continue;
        }
        tested = name;
        for (size_t j = 0; j < sizeof test_vectors / sizeof test_vectors[0]; j++) {
            const int ok = check_aead(&test_vectors[j]);
            passed += ok;
            failed += !ok;
            if (!ok) {
                printf("FAILED [%s]: %s\n", name, test_vectors[j].name);
            }
        }
        for (size_t j = 0; j < sizeof mac_test_vectors / sizeof mac_test_vectors[0]; j++) {
            const int ok = check_mac(&mac_test_vectors[j]);
            passed += ok;
            failed += !ok;
            if (!ok) {
                printf("FAILED [%s]: %s\n", name, mac_test_vectors[j].name);
            }
        }
    }
    HiAEx4_force_implementation(NULL);
    printf("HiAEx4 test vectors: %d passed, %d failed\n", passed, failed);

    return failed != 0;
}
