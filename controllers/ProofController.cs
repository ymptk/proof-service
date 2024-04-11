using System.IdentityModel.Tokens.Jwt;
using AElf;
using AElf.Client;
using AElf.Client.Dto;
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

    private string ProofStr =
        "dd035f99330d5786b42537194346d69f1b4c2ce359b3191981d92451e5d90600736a41a5b2e104c7598f185deb60b4ae150050a3ddb11122a81bdcc10754211c9a8e0e56ebcc6547823aef5d407995601e5d480d0be7440bff95d31fe43b34045d70e8b844d1399e0cc86a09d8fece16e86714d903635ad6d4cebeea986f0b82";

    private string IdentifierHash =
        "217f047dbbf7b6233d427a811ac87ce13587ed66b9d8d1df10304f747e71ef65";

    private string PublicKey =
        "dcd5f001235fffbfbd84e5832b2677f6a833fb297f9e9b88b018319e136813b5b241097e9ae6a33ec411745a8cf875ac0006d2fd6b4bae67f66914a68d7066f305c721e26372b66259e5274b27d92c3af5de3c5784dd2b0ef762644b0095a2ae87e8828300bfa577744ed5a969896fe45160bae4a2b4a4ce88347acf77926547745cdc6bf0f3820d0ed5946ff81f2ce1b0eee73b0822bcef8fcde90311b7282c8f7753cbb32995d81d24716168684a9e3b3db33d0f959bbb05ea6e65d1a7d4e3889532e86a84389e0ad8536fa9efa0e82dc19e93d5b8764d6957fc4063fcd3aad6ad63dd2748ab181860f846ac0beb1d152ac7de4c4cc4115f56cba3ebd53eed";

    public ProofController(ILogger<ProofController> logger, Prover prover)
    {
        _logger = logger;
        _prover = prover;
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
            var res = await InitializeAsync(request.Endpoint, request.ContractAddress, request.WalletAddress,
                request.Pk, request.PublicKey, request.Vk);
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
    
    [HttpPost("create-test")]
    public async Task<IActionResult> CreateTest(ProofGenerationSchema.InitializeRequest request)
    {
        try
        {
            var res = await InitializeAsync(request.Endpoint, request.ContractAddress, request.WalletAddress,
                request.Pk, request.PublicKey, request.Vk);
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

    [HttpPost("generate-mock")]
    public IActionResult GenerateProofMock(ProofGenerationSchema.ProofGenerationRequest request)
    {
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

    #region private method

    private static byte[] HexStringToByteArray(string hex)
    {
        var length = hex.Length;
        var byteArray = new byte[length / 2];

        for (var i = 0; i < length; i += 2)
        {
            byteArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }

        return byteArray;
    }

    private static string GetGuardianIdentifierHashFromJwtPublicInputs(List<string> publicInputs)
    {
        var idHash = publicInputs.GetRange(0, 32);
        var identifierHash = idHash.Select(s => byte.Parse(s)).ToArray();
        var guardianIdentifierHash = identifierHash.ToHex();
        return guardianIdentifierHash;
    }

    private static async Task<string> GetGooglePublicKeyFromJwt(JwtSecurityToken jwt)
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

    private static ProvingOutput ParseProvingOutput(string provingOutput)
    {
        return JsonConvert.DeserializeObject<ProvingOutput>(provingOutput);
    }

    private static List<string> PadString(string str, int paddedBytesSize)
    {
        var paddedBytes = str.Select(c => ((int) c).ToString()).ToList();

        var paddingLength = paddedBytesSize - paddedBytes.Count;
        if (paddingLength > 0)
        {
            paddedBytes.AddRange(Enumerable.Repeat("0", paddingLength));
        }

        return paddedBytes;
    }

    private static async Task<bool> InitializeAsync(string endpoint, string contractAddress, string walletAddress,
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
        SendTransaction(client, contractAddress, "Initialize", pk, initializeInput);

        var setCreateHolderEnabledInput = new SetCreateHolderEnabledInput
        {
            CreateHolderEnabled = true
        };
        SendTransaction(client, contractAddress, "SetCreateHolderEnabled", pk, setCreateHolderEnabledInput);

        var issuerPublicKeyEntry = new IssuerPublicKeyEntry
        {
            IssuerName = "Google",
            IssuerPubkey = publicKey
        };
        SendTransaction(client, contractAddress, "AddZkIssuer", pk, issuerPublicKeyEntry);

        var addVerifierServerEndPointsInput = new AddVerifierServerEndPointsInput
        {
            Name = "Portkey",
            ImageUrl = "https://portkey-did.s3.ap-northeast-1.amazonaws.com/img/Portkey.png",
            EndPoints = {endpoint},
            VerifierAddressList = {Address.FromBase58(walletAddress)}
        };
        SendTransaction(client, contractAddress, "AddVerifierServerEndPoints", pk, addVerifierServerEndPointsInput);

        var stringValue = new StringValue
        {
            Value = vk
        };
        SendTransaction(client, contractAddress, "SetZkVerifiyingKey", pk, stringValue);
        return true;
    }

    private static async void SendTransaction(AElfClient client, string contractAddress, string methodName, string pk,
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

        await Task.Delay(2000);
        // After the transaction is mined, query the execution results.
        var transactionResult = await client.GetTransactionResultAsync(result.TransactionId);
        Console.WriteLine(transactionResult.Status);
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