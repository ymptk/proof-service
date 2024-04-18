using System.IdentityModel.Tokens.Jwt;
using System.Text;
using AElf;
using AElf.Client;
using AElf.Client.Dto;
using AElf.Contracts.MultiToken;
using AElf.Types;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Groth16.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Portkey.Contracts.CA;
using ProofService.interfaces;
using RestSharp;
using ZkVerifier;

namespace ProofService.controllers;

[Route("proof")]
[ApiController]
public class ProofController : ControllerBase
{
    private readonly ILogger<ProofController> _logger;
    private readonly Prover _prover;
    private readonly ContractClient _contractClient;
    
    public ProofController(ILogger<ProofController> logger, Prover prover, ContractClient contractClient)
    {
        _logger = logger;
        _prover = prover;
        _contractClient = contractClient;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(ProofGenerationSchema.ProofLoginInRequest request)
    {
        try
        {
            var proof = request.Proof;
            var identifierHash = request.IdentifierHash;
            var publicKeyHex = request.PublicKey;
            var managerAddress = request.ManagerAddress;
            var salt = request.Salt;
            var walletAddress = _contractClient.WalletAddress;
            var caContractAddress = _contractClient.CaContractAddress;
            var pk = _contractClient.PK;
            var client = new AElfClient("http://" + _contractClient.IP + ":8000");

            // get holder info to check whether needs to create new holder
            GetHolderInfoOutput holderInfo = null;
            try
            {
                holderInfo = await GetCaHolder(client, caContractAddress, pk, identifierHash, walletAddress);
            }
            catch (Exception e)
            {
                if (e.Message.Contains("Not found ca_hash"))
                {
                    _logger.LogWarning("Not found ca_hash");
                }
                else
                {
                    throw;
                }
            }

            // if holder is not null, just needs to add manager address
            if (holderInfo != null)
            {
                await AddCaManager(client, caContractAddress, pk, holderInfo.CaHash, managerAddress);
                var response = new ProofGenerationSchema.ProofLoginInResponse
                {
                    CaCash = holderInfo.CaHash.ToHex(),
                    CaAddress = holderInfo.CaAddress.ToBase58(),
                };
                return StatusCode(200, response);
            }
            // if holder is null, just needs to create holder and add manager address
            else
            {
                // add new public key to zkIssuer
                await AddZkIssuerPublicKey(client, caContractAddress, pk, identifierHash, walletAddress, salt, publicKeyHex, proof);
                // await InitializeAsync(ip, endpoint, caContractAddress, walletAddress, pk, publicKeyHex, zkVk);
                var result = await CreateCaHolder(client, caContractAddress, pk, identifierHash, walletAddress, salt, publicKeyHex, proof);
                
                var newHolderInfo = await GetCaHolder(client, caContractAddress, pk, identifierHash, walletAddress);
                await AddCaManager(client, caContractAddress, pk, newHolderInfo.CaHash, managerAddress);

                var response = new ProofGenerationSchema.ProofLoginInResponse
                {
                    CaCash = newHolderInfo.CaHash.ToHex(),
                    CaAddress = newHolderInfo.CaAddress.ToBase58(),
                };

                return StatusCode(200, response);
            }
        }
        catch (Exception e)
        {
            _logger.LogError("login exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }

    [HttpPost("generate")]
    public async Task<IActionResult> GenerateProof(ProofGenerationSchema.ProofGenerationRequest request)
    {
        try
        {
            var jwtHeader = request.Jwt.Split(".")[0];
            var jwtPayload = request.Jwt.Split(".")[1];
            var jwtSignature = request.Jwt.Split(".")[2];

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(request.Jwt);

            // get google public key from jwt
            var publicKey = await GetGooglePublicKeyFromJwt(jwt);
            // google public key to hex
            var publicKeyHex = BitConverter
                .ToString(WebEncoders.Base64UrlDecode(publicKey)).Replace("-", "")
                .ToLower();
            // google public key hex to chunked bytes
            var pubkey = Helpers.HexToChunkedBytes(publicKeyHex, 121, 17)
                .Select(s => s.HexToBigInt()).ToList();
            // jwt signature to hex
            var signatureHex = BitConverter
                .ToString(WebEncoders.Base64UrlDecode(jwtSignature)).Replace("-", "")
                .ToLower();
            // jwt signature hex to chunked bytes
            var signature = Helpers.HexToChunkedBytes(signatureHex, 121, 17)
                .Select(s => s.HexToBigInt()).ToList();
            // salt hex to chunked bytes
            var salt = HexStringToByteArray(request.Salt).Select(b => b.ToString()).ToList();

            var payloadStartIndex = request.Jwt.IndexOf(".") + 1;
            var subClaim = PadString("\"sub\":" + "\"" + jwt.Payload.Sub + "\"" + ",", 41);
            var subClaimLength = jwt.Payload.Sub.Length + 9;
            var jsonString = ParseJwtPayload(jwtPayload);
            // the start index of field sub
            var startIndex = jsonString.IndexOf("\"sub\"");
            // the start index of field sub value
            var valueStartIndex = jsonString.IndexOf('"', startIndex + 5) + 1;
            // the end index of field sub value
            var valueEndIndex = jsonString.IndexOf('"', valueStartIndex);
            var subIndexB64 = payloadStartIndex + startIndex * 4 / 3;
            var subLengthB64 = (valueEndIndex + 2 - (startIndex - 1)) * 4 / 3;
            var subNameLength = 5;
            var subColonIndex = 5;
            var subValueIndex = 6;
            var subValueLength = 23;

            // build parameters of ProveBn254
            IDictionary<string, IList<string>> provingInput = new Dictionary<string, IList<string>>();
            provingInput["jwt"] = PadString(jwtHeader + "." + jwtPayload, 2048);
            provingInput["signature"] = signature;
            provingInput["pubkey"] = pubkey;
            provingInput["salt"] = salt;
            provingInput["payload_start_index"] = new List<string> {payloadStartIndex.ToString()};
            provingInput["sub_claim"] = subClaim;
            provingInput["sub_claim_length"] = new List<string> {subClaimLength.ToString()};
            provingInput["sub_index_b64"] = new List<string> {subIndexB64.ToString()};
            provingInput["sub_length_b64"] = new List<string> {subLengthB64.ToString()};
            provingInput["sub_name_length"] = new List<string> {subNameLength.ToString()};
            provingInput["sub_colon_index"] = new List<string> {subColonIndex.ToString()};
            provingInput["sub_value_index"] = new List<string> {subValueIndex.ToString()};
            provingInput["sub_value_length"] = new List<string> {subValueLength.ToString()};

            // exec ProveBn254
            var provingOutputString = _prover.ProveBn254(provingInput);
            var provingOutput = ParseProvingOutput(provingOutputString);
            // verify output
            var verified = Verifier.VerifyBn254(_prover.ExportVerifyingKeyBn254(), provingOutput.PublicInputs,
                provingOutput.Proof);
            return verified
                ? StatusCode(200, new ProofGenerationSchema.ProofGenerationResponse
                {
                    Proof = provingOutput.Proof,
                    IdentifierHash =
                        GetGuardianIdentifierHashFromJwtPublicInputs(new List<string>(provingOutput.PublicInputs)),
                    PublicKey = publicKeyHex
                })
                : StatusCode(500, "proof generate fail");
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }

    #region testing method
    [HttpPost("generate-v1")]
    public async Task<IActionResult> GenerateProofV1(ProofGenerationSchema.ProofGenerationRequest request)
    {
        try
        {
            var jwtHeader = request.Jwt.Split(".")[0];
            var jwtPayload = request.Jwt.Split(".")[1];
            var jwtSignature = request.Jwt.Split(".")[2];

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(request.Jwt);

            // get google public key from jwt
            var publicKey = await GetGooglePublicKeyFromJwt(jwt);
            // google public key to hex
            var publicKeyHex = BitConverter
                .ToString(WebEncoders.Base64UrlDecode(publicKey)).Replace("-", "")
                .ToLower();
            // google public key hex to chunked bytes
            var pubkey = Helpers.HexToChunkedBytes(publicKeyHex, 121, 17)
                .Select(s => s.HexToBigInt()).ToList();
            // jwt signature to hex
            var signatureHex = BitConverter
                .ToString(WebEncoders.Base64UrlDecode(jwtSignature)).Replace("-", "")
                .ToLower();
            // jwt signature hex to chunked bytes
            var signature = Helpers.HexToChunkedBytes(signatureHex, 121, 17)
                .Select(s => s.HexToBigInt()).ToList();
            // salt hex to chunked bytes
            var salt = HexStringToByteArray(request.Salt).Select(b => b.ToString()).ToList();

            // build parameters of ProveBn254
            IDictionary<string, IList<string>> provingInput = new Dictionary<string, IList<string>>();
            provingInput["jwt"] = PadString(jwtHeader + "." + jwtPayload, 2048);
            provingInput["signature"] = signature;
            provingInput["pubkey"] = pubkey;
            provingInput["salt"] = salt;

            // exec ProveBn254
            var provingOutputString = _prover.ProveBn254(provingInput);
            var provingOutput = ParseProvingOutput(provingOutputString);
            // verify output
            var verified = Verifier.VerifyBn254(_prover.ExportVerifyingKeyBn254(), provingOutput.PublicInputs,
                provingOutput.Proof);
            return verified
                ? StatusCode(200, new ProofGenerationSchema.ProofGenerationResponse
                {
                    Proof = provingOutput.Proof,
                    IdentifierHash =
                        GetGuardianIdentifierHashFromJwtPublicInputs(new List<string>(provingOutput.PublicInputs)),
                    PublicKey = publicKeyHex
                })
                : StatusCode(500, "proof generate fail");
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }

    [HttpPost("info")]
    public async Task<IActionResult> Info(ProofGenerationSchema.ProofGenerationRequest request)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(request.Jwt);

            // get google public key from jwt
            var publicKey = await GetGooglePublicKeyFromJwt(jwt);
            // google public key to hex
            var publicKeyHex = BitConverter
                .ToString(WebEncoders.Base64UrlDecode(publicKey)).Replace("-", "")
                .ToLower();
            var zkVk = _prover.ExportVerifyingKeyBn254();
            return StatusCode(200, new Dictionary<string, string>
            {
                {"publicKey", publicKeyHex},
                {"zkVk", zkVk}
            });
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }

    [HttpPost("initialize")]
    public async Task<IActionResult> Initialize(ProofGenerationSchema.InitializeRequest request)
    {
        try
        {
            var endpoint = "http://" + request.Ip + ":8000";
            var zkVk = _prover.ExportVerifyingKeyBn254();
            var res = await InitializeAsync(request.Ip, endpoint, _contractClient.CaContractAddress, _contractClient.WalletAddress,
                _contractClient.PK, request.PublicKey, zkVk);
            return res
                ? StatusCode(200, "initialize succeed")
                : StatusCode(500, "initialize fail");
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }

    [HttpPost("generate-test")]
    public IActionResult GenerateProofTest(ProofGenerationSchema.ProofGenerationTestRequest request)
    {
        try
        {
            IDictionary<string, IList<string>> provingInput = new Dictionary<string, IList<string>>();
            provingInput["jwt"] = request.Jwt;
            provingInput["signature"] = request.Signature;
            provingInput["pubkey"] = request.Pubkey;
            provingInput["salt"] = request.Salt;

            var provingOutputString = _prover.ProveBn254(provingInput);
            var provingOutput = ParseProvingOutput(provingOutputString);
            var verified = Verifier.VerifyBn254(_prover.ExportVerifyingKeyBn254(), provingOutput.PublicInputs,
                provingOutput.Proof);
            return verified
                ? StatusCode(200, new ProofGenerationSchema.ProofGenerationResponse {Proof = provingOutput.Proof})
                : StatusCode(500, "proof generate fail");
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }

    [HttpPost("call-test")]
    public async Task<IActionResult> CallTest(ProofGenerationSchema.CallTestRequest request)
    {
        try
        {
            AElfClient client = new AElfClient(request.Endpoint);
            var isConnected = await client.IsConnectedAsync();
            if (!isConnected) return StatusCode(500, "call fail");
            var transferInput = new TransferInput
            {
                To = Address.FromBase58(request.ToAddress),
                Symbol = "ELF",
                Amount = request.Amount,
                Memo = "test"
            };
            _logger.LogDebug("args: " + transferInput.ToByteString());
            var managerForwardCallInput = new ManagerForwardCallInput
            {
                CaHash = Hash.LoadFromHex(request.CaHash),
                ContractAddress = Address.FromBase58(request.TokenContractAddress),
                MethodName = "Transfer",
                Args = transferInput.ToByteString()
            };
            SendTransaction(client, request.CaContractAddress, "ManagerForwardCall", request.Pk,
                managerForwardCallInput);
            return StatusCode(200, "call succeed");
        }
        catch (Exception e)
        {
            _logger.LogError("call exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }

    [HttpPost("generate-mock")]
    public IActionResult GenerateProofMock(ProofGenerationSchema.ProofGenerationRequest request)
    {
        string ProofStr =
        "335aa015b0b048b769fc391874638384b1c39b98ac6ed85f072610d904058a922b210e4510ecfeb775ccb0ebd53a5e4158a4d0853beafeb913982e445e2c680a8123d822fe8e1c5b7ef7ba1df386d30e4c7e3820a3d5207f3d6478e69bd719a4a8b556dcc7d746f51cc11c33b2d25fa15bacba108ea329cd41e4f393b95eed02";
        string IdentifierHash =
        "4eb4642eebf554104267dbf6b7908a4eced912c5656b3cffe83012c2f6cbc5c6";
        string PublicKey =
            "dcd5f001235fffbfbd84e5832b2677f6a833fb297f9e9b88b018319e136813b5b241097e9ae6a33ec411745a8cf875ac0006d2fd6b4bae67f66914a68d7066f305c721e26372b66259e5274b27d92c3af5de3c5784dd2b0ef762644b0095a2ae87e8828300bfa577744ed5a969896fe45160bae4a2b4a4ce88347acf77926547745cdc6bf0f3820d0ed5946ff81f2ce1b0eee73b0822bcef8fcde90311b7282c8f7753cbb32995d81d24716168684a9e3b3db33d0f959bbb05ea6e65d1a7d4e3889532e86a84389e0ad8536fa9efa0e82dc19e93d5b8764d6957fc4063fcd3aad6ad63dd2748ab181860f846ac0beb1d152ac7de4c4cc4115f56cba3ebd53eed";

        try
        {
            return StatusCode(200, new ProofGenerationSchema.ProofGenerationResponse
            {
                Proof = ProofStr,
                IdentifierHash = IdentifierHash,
                PublicKey = PublicKey
            });
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }
    #endregion

    #region private method

    private string ParseJwtPayload(string payload)
    {
        string padded = payload.Length % 4 == 0 ? payload : payload + "====".Substring(payload.Length % 4);
        string base64 = padded.Replace("_", "/").Replace("-", "+");
        byte[] outputb = Convert.FromBase64String(base64);
        string outStr = Encoding.Default.GetString(outputb);
        return outStr;
    }

    private byte[] HexStringToByteArray(string hex)
    {
        var length = hex.Length;
        var byteArray = new byte[length / 2];

        for (var i = 0; i < length; i += 2)
        {
            byteArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }

        return byteArray;
    }

    private string GetGuardianIdentifierHashFromJwtPublicInputs(List<string> publicInputs)
    {
        var idHash = publicInputs.GetRange(0, 32);
        var identifierHash = idHash.Select(s => byte.Parse(s)).ToArray();
        var guardianIdentifierHash = identifierHash.ToHex();
        return guardianIdentifierHash;
    }

    private async Task<string> GetGooglePublicKeyFromJwt(JwtSecurityToken jwt)
    {
        var options = new RestClientOptions("https://www.googleapis.com/oauth2/v3/certs");
        var client = new RestClient(options);
        var request = new RestRequest();
        var response = await client.GetAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            return "";
        }

        var res = (JObject) JsonConvert.DeserializeObject(response.Content);
        var keys = res["keys"];
        foreach (var key in keys)
        {
            var kid = key["kid"].ToString();
            if (jwt.Header.Kid == kid)
            {
                return key["n"].ToString();
            }
        }

        return "";
    }

    private ProvingOutput ParseProvingOutput(string provingOutput)
    {
        return JsonConvert.DeserializeObject<ProvingOutput>(provingOutput);
    }

    private List<string> PadString(string str, int paddedBytesSize)
    {
        var paddedBytes = str.Select(c => ((int) c).ToString()).ToList();

        var paddingLength = paddedBytesSize - paddedBytes.Count;
        if (paddingLength > 0)
        {
            paddedBytes.AddRange(Enumerable.Repeat("0", paddingLength));
        }

        return paddedBytes;
    }

    private async Task<bool> InitializeAsync(string ip, string endpoint, string contractAddress, string walletAddress,
        string pk, string publicKey, string vk)
    {
        AElfClient client = new AElfClient(endpoint);
        var isConnected = await client.IsConnectedAsync();
        if (!isConnected) return false;
        // var contractAddress = "";
        // var pk = "";

        var initializeInput = new InitializeInput
        {
            ContractAdmin = Address.FromBase58(walletAddress)
        };
        await SendTransaction(client, contractAddress, "Initialize", pk, initializeInput);

        var setCreateHolderEnabledInput = new SetCreateHolderEnabledInput
        {
            CreateHolderEnabled = true
        };
        await SendTransaction(client, contractAddress, "SetCreateHolderEnabled", pk, setCreateHolderEnabledInput);

        var issuerPublicKeyEntry = new IssuerPublicKeyEntry
        {
            IssuerName = "Google",
            IssuerPubkey = publicKey
        };
        await SendTransaction(client, contractAddress, "AddZkIssuer", pk, issuerPublicKeyEntry);

        var publicKeysBytes = await CallTransaction(client, walletAddress, contractAddress, "GetZkIssuerPublicKeyList", pk,
            new StringValue {Value = ""});
        var publicKeyList = PublicKeyList.Parser.ParseFrom(publicKeysBytes).PublicKeys;
        if (!publicKeyList.Contains(publicKey))
        {
            await SendTransaction(client, contractAddress, "AddZkIssuerPublicKey", pk, issuerPublicKeyEntry);
        }

        var addVerifierServerEndPointsInput = new AddVerifierServerEndPointsInput
        {
            Name = "Portkey",
            ImageUrl = "https://portkey-did.s3.ap-northeast-1.amazonaws.com/img/Portkey.png",
            EndPoints = {ip},
            VerifierAddressList = {Address.FromBase58(walletAddress)}
        };
        await SendTransaction(client, contractAddress, "AddVerifierServerEndPoints", pk,
            addVerifierServerEndPointsInput);

        var stringValue = new StringValue
        {
            Value = vk
        };
        await SendTransaction(client, contractAddress, "SetZkVerifiyingKey", pk, stringValue);
        return true;
    }

    private async Task<TransactionResultDto> AddCaManager(AElfClient client, string caContractAddress, string pk, Hash caHash, string managerAddress)
    {
        var addManagerInfoInput = new AddManagerInfoInput
        {
            CaHash = caHash,
            ManagerInfo = new ManagerInfo
            {
                Address = Address.FromBase58(managerAddress),
                ExtraData = "manager"
            }
        };
        return await SendTransaction(client, caContractAddress, "AddManagerInfo", pk, addManagerInfoInput);
    }
    
    private async Task<TransactionResultDto> RemoveCaManager(AElfClient client, string caContractAddress, string pk, Hash caHash, string managerAddress)
    {
        var removeManagerInfoInput = new RemoveManagerInfoInput()
        {
            CaHash = caHash
        };
        return await SendTransaction(client, caContractAddress, "RemoveManagerInfo", pk, removeManagerInfoInput);
    }

    private async Task<GetHolderInfoOutput> GetCaHolder(AElfClient client, string caContractAddress, string pk, string identifierHash, string walletAddress)
    {
        var holderInfoInput = new GetHolderInfoInput
        {
            LoginGuardianIdentifierHash = Hash.LoadFromHex(identifierHash)
        };
        return GetHolderInfoOutput.Parser.ParseFrom(await CallTransaction(client, walletAddress,
            caContractAddress, "GetHolderInfo", pk, holderInfoInput));
    }

    private async Task<TransactionResultDto> CreateCaHolder(AElfClient client, string caContractAddress, string pk,
        string identifierHash, string walletAddress, string salt, string publicKeyHex, string proof)
    {
        var createCAHolderInput = new CreateCAHolderInput()
        {
            GuardianApproved = new GuardianInfo
            {
                IdentifierHash = Hash.LoadFromHex(identifierHash),
                ZkGuardianInfo = new ZkGuardianInfo
                {
                    IdentifierHash = Hash.LoadFromHex(identifierHash),
                    Salt = salt,
                    IssuerName = "Google",
                    IssuerPubkey = publicKeyHex,
                    Proof = proof
                }
            },
            ManagerInfo = new ManagerInfo
            {
                Address = Address.FromBase58(walletAddress),
                ExtraData = "manager"
            }
        };
        return await SendTransaction(client, caContractAddress, "CreateCAHolder", pk, createCAHolderInput);
    }
    
    private async Task AddZkIssuerPublicKey(AElfClient client, string contractAddress, string pk,
        string identifierHash, string walletAddress, string salt, string publicKey, string proof)
    {
        var issuerPublicKeyEntry = new IssuerPublicKeyEntry
        {
            IssuerName = "Google",
            IssuerPubkey = publicKey
        };
        var publicKeysBytes = await CallTransaction(client, walletAddress, contractAddress, "GetZkIssuerPublicKeyList", pk,
            new StringValue {Value = ""});
        var publicKeyList = PublicKeyList.Parser.ParseFrom(publicKeysBytes).PublicKeys;
        if (!publicKeyList.Contains(publicKey))
        {
            await SendTransaction(client, contractAddress, "AddZkIssuerPublicKey", pk, issuerPublicKeyEntry);
        }
    }

    private async Task<TransactionResultDto> SendTransaction(AElfClient client, string contractAddress,
        string methodName, string pk,
        IMessage param)
    {
        // var tokenContractAddress = await client.GetContractAddressByNameAsync(HashHelper.ComputeFrom("AElf.ContractNames.Token"));
        // var methodName = "Transfer";
        // var param = new TransferInput
        // {
        //     To = new Address {Value = Address.FromBase58("7s4XoUHfPuqoZAwnTV7pHWZAaivMiL8aZrDSnY9brE1woa8vz").Value},
        //     Symbol = "ELF",
        //     Amount = 1000000000,
        //     Memo = "transfer in demo"
        // };
        var ownerAddress = client.GetAddressFromPrivateKey(pk);

        // Generate a transfer transaction.
        var transaction = await client.GenerateTransactionAsync(ownerAddress, contractAddress, methodName, param);
        var txWithSign = client.SignTransaction(pk, transaction);

        // Send the transfer transaction to AElf chain node.
        var result = await client.SendTransactionAsync(new SendTransactionInput
        {
            RawTransaction = txWithSign.ToByteArray().ToHex()
        });

        _logger.LogInformation(result.TransactionId);

        await Task.Delay(5000);
        // After the transaction is mined, query the execution results.
        var transactionResult = await client.GetTransactionResultAsync(result.TransactionId);
        _logger.LogInformation(transactionResult.Status != "MINED"
            ? methodName + ": " + result.TransactionId + ": " + transactionResult.Status + ": " +
              transactionResult.Error
            : methodName + ": " + result.TransactionId + ": " + transactionResult.Status);
        return transactionResult;
    }

    private async Task<byte[]> CallTransaction(AElfClient client, string walletAddress, string contractAddress,
        string methodName, string pk,
        IMessage param)
    {
        var transaction = await client.GenerateTransactionAsync(walletAddress, contractAddress, methodName, param);
        var txWithSign = client.SignTransaction(pk, transaction);
        var transactionResult = await client.ExecuteTransactionAsync(new ExecuteTransactionDto
        {
            RawTransaction = txWithSign.ToByteArray().ToHex()
        });
        return ByteArrayHelper.HexStringToByteArray(transactionResult);
    }

    #endregion
}

public class ProvingOutput
{
    public ProvingOutput(IList<string> publicInputs, string proof)
    {
        PublicInputs = publicInputs;
        Proof = proof;
    }

    [JsonProperty("public_inputs")] public IList<string> PublicInputs { get; set; }

    [JsonProperty("proof")] public string Proof { get; set; }

    public static ProvingOutput FromJsonString(string jsonString)
    {
        return JsonConvert.DeserializeObject<ProvingOutput>(jsonString);
    }
}